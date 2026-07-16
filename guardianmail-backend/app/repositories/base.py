"""Generic async repository base class.

Design goals
------------
* One class exposes the entire *database* surface: reads, writes, soft
  delete/restore, pagination, aggregation, bulk ops, and transactions.
* Repositories are *pure* — no business logic, no cross-collection calls,
  no external I/O beyond MongoDB.
* Every query is projection-friendly and index-aware; slow queries are
  logged with structured context so ops can trace them.
* Soft delete is the default: `find_*` methods exclude tombstoned rows
  unless `include_deleted=True` is passed explicitly.

Subclasses only need to set `collection_name` and `model`; domain-specific
queries (e.g. "find emails scanned but not yet reported") live on the
subclass and reuse these primitives.
"""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Generic, Iterable, Mapping, Sequence, TypeVar

from motor.motor_asyncio import (
    AsyncIOMotorClientSession,
    AsyncIOMotorCollection,
    AsyncIOMotorDatabase,
)
from pymongo import ASCENDING, DESCENDING, InsertOne, ReturnDocument, UpdateOne
from pymongo.errors import DuplicateKeyError, PyMongoError
from pydantic import BaseModel

from app.core.clock import now_utc
from app.core.exceptions import (
    ConflictError,
    ExternalServiceError,
    NotFoundError,
)
from app.core.logging import get_logger
from app.schemas.base import Page

T = TypeVar("T", bound=BaseModel)

_log = get_logger(__name__)
SLOW_QUERY_MS = 250


class BaseRepository(Generic[T]):
    collection_name: str = ""
    model: type[T]
    #: whether the collection uses soft-delete semantics
    soft_delete: bool = True

    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        if not self.collection_name:
            raise RuntimeError(f"{type(self).__name__} missing collection_name")
        self.db = db
        self.col: AsyncIOMotorCollection = db[self.collection_name]

    # ------------------------------------------------------------------ utils
    def _wrap(self, doc: Mapping[str, Any] | None) -> T | None:
        return self.model.model_validate(doc) if doc else None

    def _live_filter(self, filter_: Mapping[str, Any], include_deleted: bool) -> dict:
        f = dict(filter_)
        if self.soft_delete and not include_deleted and "deleted_at" not in f:
            f["deleted_at"] = None
        return f

    def _dump(self, doc: T | Mapping[str, Any]) -> dict:
        if isinstance(doc, BaseModel):
            return doc.model_dump(by_alias=True)
        return dict(doc)

    @asynccontextmanager
    async def _timed(self, op: str, filter_: Any = None) -> AsyncIterator[None]:
        t0 = time.perf_counter()
        try:
            yield
        finally:
            dur_ms = (time.perf_counter() - t0) * 1000
            if dur_ms >= SLOW_QUERY_MS:
                _log.warning(
                    "slow_query",
                    collection=self.collection_name,
                    op=op,
                    duration_ms=round(dur_ms, 1),
                    filter=str(filter_)[:256] if filter_ is not None else None,
                )

    # ------------------------------------------------------------------ reads
    async def find_by_id(
        self,
        _id: Any,
        *,
        include_deleted: bool = False,
        projection: Mapping[str, Any] | None = None,
    ) -> T | None:
        f = self._live_filter({"_id": _id}, include_deleted)
        async with self._timed("find_by_id", f):
            doc = await self.col.find_one(f, projection=projection)
        return self._wrap(doc)

    async def get_by_id(self, _id: Any) -> T:
        doc = await self.find_by_id(_id)
        if not doc:
            raise NotFoundError(f"{self.collection_name}:{_id} not found")
        return doc

    async def find_one(
        self,
        filter_: Mapping[str, Any],
        *,
        include_deleted: bool = False,
        projection: Mapping[str, Any] | None = None,
        sort: Sequence[tuple[str, int]] | None = None,
    ) -> T | None:
        f = self._live_filter(filter_, include_deleted)
        async with self._timed("find_one", f):
            doc = await self.col.find_one(f, projection=projection, sort=list(sort) if sort else None)
        return self._wrap(doc)

    async def find_many(
        self,
        filter_: Mapping[str, Any],
        *,
        skip: int = 0,
        limit: int = 50,
        sort: Sequence[tuple[str, int]] | None = None,
        projection: Mapping[str, Any] | None = None,
        include_deleted: bool = False,
    ) -> list[T]:
        f = self._live_filter(filter_, include_deleted)
        async with self._timed("find_many", f):
            cur = self.col.find(f, projection=projection).skip(skip).limit(limit)
            if sort:
                cur = cur.sort(list(sort))
            return [self.model.model_validate(d) async for d in cur]

    async def paginate(
        self,
        filter_: Mapping[str, Any],
        *,
        page: int = 1,
        page_size: int = 25,
        sort: Sequence[tuple[str, int]] | None = (("created_at", DESCENDING),),
        projection: Mapping[str, Any] | None = None,
        include_deleted: bool = False,
    ) -> Page[T]:
        page = max(1, page)
        page_size = max(1, min(page_size, 200))
        skip = (page - 1) * page_size
        f = self._live_filter(filter_, include_deleted)
        async with self._timed("paginate", f):
            total = await self.col.count_documents(f)
            cur = self.col.find(f, projection=projection).skip(skip).limit(page_size)
            if sort:
                cur = cur.sort(list(sort))
            items = [self.model.model_validate(d) async for d in cur]
        return Page[T](items=items, total=total, page=page, page_size=page_size)

    async def count(
        self, filter_: Mapping[str, Any], *, include_deleted: bool = False
    ) -> int:
        f = self._live_filter(filter_, include_deleted)
        return await self.col.count_documents(f)

    async def exists(self, filter_: Mapping[str, Any]) -> bool:
        return await self.count(filter_) > 0

    async def distinct(
        self, field: str, filter_: Mapping[str, Any] | None = None
    ) -> list[Any]:
        f = self._live_filter(filter_ or {}, include_deleted=False)
        return await self.col.distinct(field, f)

    async def aggregate(
        self,
        pipeline: Sequence[Mapping[str, Any]],
        *,
        allow_disk_use: bool = False,
    ) -> list[dict]:
        async with self._timed("aggregate", pipeline[0] if pipeline else None):
            cur = self.col.aggregate(list(pipeline), allowDiskUse=allow_disk_use)
            return [d async for d in cur]

    # ----------------------------------------------------------------- writes
    async def insert(
        self,
        doc: T | Mapping[str, Any],
        *,
        session: AsyncIOMotorClientSession | None = None,
    ) -> Any:
        payload = self._dump(doc)
        try:
            async with self._timed("insert"):
                res = await self.col.insert_one(payload, session=session)
            return res.inserted_id
        except DuplicateKeyError as e:
            raise ConflictError(
                f"duplicate key in {self.collection_name}", details={"error": str(e)}
            ) from e
        except PyMongoError as e:  # pragma: no cover - infra failure path
            raise ExternalServiceError("mongodb write failed") from e

    async def insert_many(
        self,
        docs: Iterable[T | Mapping[str, Any]],
        *,
        ordered: bool = False,
        session: AsyncIOMotorClientSession | None = None,
    ) -> list[Any]:
        payload = [self._dump(d) for d in docs]
        if not payload:
            return []
        async with self._timed("insert_many"):
            res = await self.col.insert_many(payload, ordered=ordered, session=session)
        return list(res.inserted_ids)

    async def update(
        self,
        filter_: Mapping[str, Any],
        update: Mapping[str, Any],
        *,
        upsert: bool = False,
        touch: bool = True,
        session: AsyncIOMotorClientSession | None = None,
    ) -> int:
        payload = dict(update)
        if touch:
            payload.setdefault("$set", {})
            payload["$set"]["updated_at"] = now_utc()
            payload.setdefault("$inc", {})
            payload["$inc"]["version"] = 1
        async with self._timed("update", filter_):
            res = await self.col.update_one(filter_, payload, upsert=upsert, session=session)
        return res.modified_count

    async def update_many(
        self,
        filter_: Mapping[str, Any],
        update: Mapping[str, Any],
        *,
        touch: bool = True,
    ) -> int:
        payload = dict(update)
        if touch:
            payload.setdefault("$set", {})
            payload["$set"]["updated_at"] = now_utc()
            payload.setdefault("$inc", {})
            payload["$inc"]["version"] = 1
        async with self._timed("update_many", filter_):
            res = await self.col.update_many(filter_, payload)
        return res.modified_count

    async def find_one_and_update(
        self,
        filter_: Mapping[str, Any],
        update: Mapping[str, Any],
        *,
        return_new: bool = True,
        upsert: bool = False,
        touch: bool = True,
    ) -> T | None:
        payload = dict(update)
        if touch:
            payload.setdefault("$set", {})
            payload["$set"]["updated_at"] = now_utc()
            payload.setdefault("$inc", {})
            payload["$inc"]["version"] = 1
        doc = await self.col.find_one_and_update(
            filter_,
            payload,
            upsert=upsert,
            return_document=ReturnDocument.AFTER if return_new else ReturnDocument.BEFORE,
        )
        return self._wrap(doc)

    async def replace(
        self,
        filter_: Mapping[str, Any],
        doc: T | Mapping[str, Any],
        *,
        upsert: bool = False,
    ) -> int:
        payload = self._dump(doc)
        payload["updated_at"] = now_utc()
        payload["version"] = payload.get("version", 0) + 1
        res = await self.col.replace_one(filter_, payload, upsert=upsert)
        return res.modified_count

    # ---- soft delete / restore ------------------------------------------
    async def soft_delete_by_id(self, _id: Any) -> bool:
        if not self.soft_delete:
            return await self.delete_by_id(_id)
        res = await self.col.update_one(
            {"_id": _id, "deleted_at": None},
            {"$set": {"deleted_at": now_utc(), "updated_at": now_utc()}, "$inc": {"version": 1}},
        )
        return res.modified_count == 1

    async def restore_by_id(self, _id: Any) -> bool:
        if not self.soft_delete:
            return False
        res = await self.col.update_one(
            {"_id": _id, "deleted_at": {"$ne": None}},
            {"$set": {"deleted_at": None, "updated_at": now_utc()}, "$inc": {"version": 1}},
        )
        return res.modified_count == 1

    async def delete_by_id(self, _id: Any) -> bool:
        """Hard delete — for GDPR erasure only. Prefer `soft_delete_by_id`."""
        res = await self.col.delete_one({"_id": _id})
        return res.deleted_count == 1

    async def delete_many(self, filter_: Mapping[str, Any]) -> int:
        res = await self.col.delete_many(dict(filter_))
        return res.deleted_count

    # ------------------------------------------------------------- bulk ops
    async def bulk_write(
        self, ops: Sequence[UpdateOne | InsertOne], *, ordered: bool = False
    ) -> Any:
        if not ops:
            return None
        async with self._timed("bulk_write"):
            return await self.col.bulk_write(list(ops), ordered=ordered)

    # ---------------------------------------------------------- transactions
    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[AsyncIOMotorClientSession]:
        """Multi-document transaction (requires replica set / Atlas)."""
        client = self.db.client
        async with await client.start_session() as session:
            async with session.start_transaction():
                yield session
