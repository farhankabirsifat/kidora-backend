from pydantic import BaseModel, Field
from typing import Optional


class AddressBase(BaseModel):
    street: str
    city: str
    state: str
    zipCode: str
    country: str
    isDefault: bool = Field(default=False)


class AddressCreate(AddressBase):
    pass


class AddressUpdate(AddressBase):
    pass


class AddressOut(AddressBase):
    id: int
