"""
Database Schemas for LernifyRoad

Each Pydantic model represents a collection in MongoDB (collection name = lowercase class name).
"""
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, EmailStr, constr

# -----------------------------
# Core Schemas
# -----------------------------

AllowedQualification = Literal[
    "B.Tech CSE",
    "B.Tech IT",
    "BSc CS",
    "BSc IT",
    "BCA",
    "MCA",
    "MSc CS",
    "Diploma IT",
]

class Session(BaseModel):
    token: str
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    user_agent: Optional[str] = None

class User(BaseModel):
    first_name: constr(pattern=r"^[A-Za-z]{2,50}$") = Field(..., description="Only letters, 2-50 chars")
    last_name: constr(pattern=r"^[A-Za-z]{2,50}$") = Field(..., description="Only letters, 2-50 chars")
    qualification: AllowedQualification
    email: EmailStr
    phone: constr(pattern=r"^[0-9]{10}$")
    password_hash: str
    domains: List[str] = Field(default_factory=list)
    sessions: List[Session] = Field(default_factory=list)

class VideoSuggestion(BaseModel):
    domain: str
    step_id: str
    title: str
    url: constr(pattern=r"^(https?:\/\/)?(www\.)?(youtube\.com|youtu\.be)\/.*$")
    suggested_by: str  # user_id

class AssessmentResult(BaseModel):
    domain: str
    step_id: str
    score: int = Field(..., ge=0, le=20)
    passed: bool

class RoadmapProgress(BaseModel):
    user_id: str
    domain: str
    current_step_index: int = 0
    steps_status: List[Literal["locked", "unlocked", "passed"]] = Field(default_factory=list)
    results: List[AssessmentResult] = Field(default_factory=list)

class Resume(BaseModel):
    user_id: str
    summary: constr(min_length=30, max_length=1000)
    skills: List[constr(min_length=2, max_length=40)]
    education: List[dict]  # {degree, institution, start, end}
    experience: List[dict]  # {role, company, start, end, description}
    projects: List[dict]  # {name, description, tech, link}

# Utility schema for step
class RoadmapStep(BaseModel):
    id: str
    title: str
    description: str
    assessment_marks: int = 20

# Roadmap static catalog (can be expanded later)
class Roadmap(BaseModel):
    domain: str
    steps: List[RoadmapStep]
