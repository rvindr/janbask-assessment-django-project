from pydantic import BaseModel, Field
from typing import Optional, List
from bson import ObjectId


class PermissionModel(BaseModel):
    """
    Pydantic model for permission with ID, name, and optional description.
    """

    id: Optional[str] = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    name: str
    description: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True
        populate_by_name = True


class RoleModel(BaseModel):
    """
    Pydantic model for role with ID, name, and a list of permission IDs.
    """

    id: Optional[str] = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    name: str
    permissions: List[str]  # List of permission IDs

    class Config:
        arbitrary_types_allowed = True
        populate_by_name = True
