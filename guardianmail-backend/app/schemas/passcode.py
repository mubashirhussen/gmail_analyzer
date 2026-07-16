"""Passcode DTOs."""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class PasscodeIn(BaseModel):
    passcode: str = Field(..., min_length=6, max_length=6)

    @field_validator("passcode")
    @classmethod
    def _digits(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("passcode must be exactly 6 digits")
        return v


class PasscodeChangeIn(BaseModel):
    current: str = Field(..., min_length=6, max_length=6)
    new: str = Field(..., min_length=6, max_length=6)

    @field_validator("current", "new")
    @classmethod
    def _digits(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("passcode must be exactly 6 digits")
        return v


class PasscodeStatus(BaseModel):
    enabled: bool
    locked: bool
    remaining_attempts: int
