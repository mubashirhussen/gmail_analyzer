"""Generic async repository base class.

Every collection-specific repository extends this class. It provides the
minimum CRUD surface every service needs; domain-specific queries live
on the subclass.
"""
from __future__ import annotations

from typing import Any, Generic, TypeVar

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class BaseRepository(Generic[T]):
    collection_name: str = ""
    model: type[T]

    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        if not self.collection_name:
            raise RuntimeError(f"{type(self).__name__} missing collection_name")
        self.db = db
        self.col: AsyncIOMotorCollection = db[self.collection_name]

    # ---- reads -----------------------------------------------------------
    async def find_by_id(self, _id: Any) -> T | None:
        doc = await self.col.find_one({"_id": _id})
        return self.model.model_validate(doc) if doc else None

    async def find_one(self, filter_: dict) -> T | None:
        doc = await self.col.find_one(filter_)
        return self.model.model_validate(doc) if doc else None

    async def find_many(
        self,
        filter_: dict,
        *,
        skip: int = 0,
        limit: int = 50,
        sort: list[tuple[str, int]] | None = None,
    ) -> list[T]:
        cur = self.col.find(filter_).skip(skip).limit(limit)
        if sort:
            cur = cur.sort(sort)
        return [self.model.model_validate(d) async for d in cur]

    async def count(self, filter_: dict) -> int:
        return await self.col.count_documents(filter_)

    # ---- writes ----------------------------------------------------------
    async def insert(self, doc: T | dict) -> Any:
        payload = doc.model_dump() if isinstance(doc, BaseModel) else dict(doc)
        res = await self.col.insert_one(payload)
        return res.inserted_id

    async def update(self, filter_: dict, update: dict, *, upsert: bool = False) -> int:
        res = await self.col.update_one(filter_, update, upsert=upsert)
        return res.modified_count

    async def delete(self, filter_: dict) -> int:
        res = await self.col.delete_one(filter_)
        return res.deleted_count
