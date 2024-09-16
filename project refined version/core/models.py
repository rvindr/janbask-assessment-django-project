from pydantic import BaseModel, Field
from typing import Optional, List
from bson import ObjectId
from datetime import datetime, timedelta


class UserModel(BaseModel):
    """
    Pydantic model for user with account management and role-based access.
    """

    id: Optional[str] = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    email: str
    first_name: str
    last_name: str
    password: str
    is_active: bool = True
    is_admin: bool = False
    role_id: Optional[str] = None

    @property
    def is_authenticated(self):
        """Indicates the user is authenticated."""
        return True

    class Config:
        arbitrary_types_allowed = True
        populate_by_name = True



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


class UserActivity(BaseModel):

    email:str
    action:str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    details: dict 

    class Config:
        arbitrary_types_allowed = True
        populate_by_name = True
