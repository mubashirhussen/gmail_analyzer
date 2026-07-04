from fastapi import APIRouter, Depends
from app.core.security import require_user
from app.database.mongodb import get_db

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("")
async def analytics(user=Depends(require_user), db=Depends(get_db)):
    pipeline = [
        {"$match": {"user_id": user["sub"]}},
        {"$group": {"_id": {"$dateTrunc": {"date": "$created_at", "unit": "day"}},
                    "safe": {"$sum": {"$cond": [{"$eq": ["$verdict", "safe"]}, 1, 0]}},
                    "susp": {"$sum": {"$cond": [{"$eq": ["$verdict", "suspicious"]}, 1, 0]}},
                    "phish": {"$sum": {"$cond": [{"$eq": ["$verdict", "phishing"]}, 1, 0]}},
                    "fraud": {"$sum": {"$cond": [{"$eq": ["$verdict", "fraud"]}, 1, 0]}}}},
        {"$sort": {"_id": 1}},
    ]
    return {"trend": [d async for d in db.threats.aggregate(pipeline)]}
