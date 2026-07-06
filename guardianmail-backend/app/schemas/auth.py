from pydantic import BaseModel, EmailStr


class GoogleExchangeIn(BaseModel):
    code: str
    redirect_uri: str | None = None


class RefreshIn(BaseModel):
    refresh_token: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: str
    email: EmailStr
    name: str | None = None
    picture: str | None = None
