import os
import hashlib
import uuid
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Header, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr, constr
from database import db, create_document, get_documents
from bson import ObjectId

app = FastAPI(title="LernifyRoad API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Utility helpers
# -----------------------------

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def make_token() -> str:
    return uuid.uuid4().hex

def get_user_from_token(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization format")
    token = parts[1]
    user = db.user.find_one({"sessions.token": token})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user

# -----------------------------
# Static domain roadmaps (seed)
# -----------------------------

DEFAULT_ROADMAPS: Dict[str, List[Dict[str, Any]]] = {
    "Frontend Development": [
        {"id": "html-css", "title": "HTML & CSS Basics", "description": "Learn HTML tags and CSS fundamentals", "assessment_marks": 20},
        {"id": "js-fund", "title": "JavaScript Fundamentals", "description": "Variables, loops, functions", "assessment_marks": 20},
        {"id": "react-basics", "title": "React Basics", "description": "Components, state, props", "assessment_marks": 20},
    ],
    "Backend Development": [
        {"id": "python-basics", "title": "Python Basics", "description": "Syntax, data structures", "assessment_marks": 20},
        {"id": "api-design", "title": "API Design", "description": "REST principles & auth", "assessment_marks": 20},
        {"id": "database", "title": "Databases", "description": "MongoDB CRUD & indexing", "assessment_marks": 20},
    ],
    "AI & ML": [
        {"id": "py-numpy", "title": "Python + NumPy", "description": "Data handling with NumPy", "assessment_marks": 20},
        {"id": "pandas-ml", "title": "Pandas & ML Intro", "description": "Pandas, scikit-learn basics", "assessment_marks": 20},
        {"id": "models", "title": "Models & Evaluation", "description": "Train/test split, metrics", "assessment_marks": 20},
    ],
}

ALLOWED_DOMAINS = list(DEFAULT_ROADMAPS.keys())
PASS_MARKS = 12  # out of 20

# -----------------------------
# Request/Response Models
# -----------------------------

class RegisterPayload(BaseModel):
    first_name: constr(pattern=r"^[A-Za-z]{2,50}$")
    last_name: constr(pattern=r"^[A-Za-z]{2,50}$")
    qualification: str
    phone: constr(pattern=r"^[0-9]{10}$")
    email: EmailStr
    password: constr(min_length=6)

class LoginPayload(BaseModel):
    email: EmailStr
    password: constr(min_length=6)

class ProfileUpdatePayload(BaseModel):
    phone: Optional[constr(pattern=r"^[0-9]{10}$")] = None
    current_password: Optional[constr(min_length=6)] = None
    new_password: Optional[constr(min_length=6)] = None

class SuggestVideoPayload(BaseModel):
    domain: str
    step_id: str
    title: constr(min_length=3, max_length=120)
    url: constr(pattern=r"^(https?:\/\/)?(www\.)?(youtube\.com|youtu\.be)\/.*$")

class AssessmentPayload(BaseModel):
    domain: str
    step_id: str
    score: int = Field(..., ge=0, le=20)

class ResumeItem(BaseModel):
    degree: Optional[str] = None
    institution: Optional[str] = None
    start: Optional[str] = None
    end: Optional[str] = None
    role: Optional[str] = None
    company: Optional[str] = None
    description: Optional[str] = None
    name: Optional[str] = None
    tech: Optional[str] = None
    link: Optional[str] = None

class ResumePayload(BaseModel):
    summary: constr(min_length=30, max_length=1000)
    skills: List[constr(min_length=2, max_length=40)]
    education: List[ResumeItem]
    experience: List[ResumeItem]
    projects: List[ResumeItem]

# -----------------------------
# Basic routes
# -----------------------------

@app.get("/")
def root():
    return {"app": "LernifyRoad API", "domains": ALLOWED_DOMAINS}

@app.get("/test")
def test_database():
    try:
        collections = db.list_collection_names()
        return {"backend": "running", "database": "connected", "collections": collections}
    except Exception as e:
        return {"backend": "running", "database": f"error: {str(e)}"}

# -----------------------------
# Auth
# -----------------------------

@app.post("/auth/register")
def register(payload: RegisterPayload):
    if payload.qualification not in ALLOWED_DOMAINS + [
        "B.Tech CSE","B.Tech IT","BSc CS","BSc IT","BCA","MCA","MSc CS","Diploma IT"
    ]:
        # Allow any string but keep a simple length check if not in ALLOWED list
        if len(payload.qualification) < 2:
            raise HTTPException(status_code=400, detail="Invalid qualification")

    existing = db.user.find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_doc = {
        "first_name": payload.first_name,
        "last_name": payload.last_name,
        "qualification": payload.qualification,
        "email": str(payload.email).lower(),
        "phone": payload.phone,
        "password_hash": hash_password(payload.password),
        "domains": [],
        "sessions": [],
    }
    inserted_id = db.user.insert_one(user_doc).inserted_id
    return {"status": "ok", "user_id": str(inserted_id)}

@app.post("/auth/login")
def login(payload: LoginPayload):
    user = db.user.find_one({"email": str(payload.email).lower()})
    if not user or user.get("password_hash") != hash_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = make_token()
    db.user.update_one({"_id": user["_id"]}, {"$push": {"sessions": {"token": token}}})
    return {"token": token, "first_name": user["first_name"], "last_name": user["last_name"]}

@app.get("/me")
def me(user=Depends(get_user_from_token)):
    user["_id"] = str(user["_id"])  # type: ignore
    # hide sensitive
    user.pop("password_hash", None)
    return user

@app.put("/me")
def update_profile(payload: ProfileUpdatePayload, user=Depends(get_user_from_token)):
    update: Dict[str, Any] = {}
    if payload.phone:
        update["phone"] = payload.phone
    if payload.new_password:
        if not payload.current_password:
            raise HTTPException(status_code=400, detail="Current password required")
        if hash_password(payload.current_password) != user.get("password_hash"):
            raise HTTPException(status_code=400, detail="Current password incorrect")
        update["password_hash"] = hash_password(payload.new_password)
    if update:
        db.user.update_one({"_id": user["_id"]}, {"$set": update})
    return {"status": "updated"}

# -----------------------------
# Domains & Roadmaps
# -----------------------------

@app.get("/domains")
def get_domains():
    return {"domains": ALLOWED_DOMAINS}

@app.post("/select-domain")
def select_domain(domain: str, user=Depends(get_user_from_token)):
    if domain not in ALLOWED_DOMAINS:
        raise HTTPException(status_code=400, detail="Unknown domain")
    db.user.update_one({"_id": user["_id"]}, {"$addToSet": {"domains": domain}})
    # initialize progress if not exists
    prog = db.roadmapprogress.find_one({"user_id": str(user["_id"]), "domain": domain})
    if not prog:
        steps = DEFAULT_ROADMAPS[domain]
        db.roadmapprogress.insert_one({
            "user_id": str(user["_id"]),
            "domain": domain,
            "current_step_index": 0,
            "steps_status": ["unlocked"] + ["locked"] * (len(steps) - 1),
            "results": [],
        })
    return {"status": "ok"}

@app.get("/roadmap/{domain}")
def get_roadmap(domain: str):
    if domain not in ALLOWED_DOMAINS:
        raise HTTPException(status_code=404, detail="Domain not found")
    return {"domain": domain, "steps": DEFAULT_ROADMAPS[domain]}

@app.get("/progress/{domain}")
def get_progress(domain: str, user=Depends(get_user_from_token)):
    prog = db.roadmapprogress.find_one({"user_id": str(user["_id"]), "domain": domain})
    if not prog:
        raise HTTPException(status_code=404, detail="No progress yet for this domain")
    prog["_id"] = str(prog["_id"])  # type: ignore
    return prog

# -----------------------------
# Video Suggestions
# -----------------------------

@app.post("/suggest-video")
def suggest_video(payload: SuggestVideoPayload, user=Depends(get_user_from_token)):
    if payload.domain not in ALLOWED_DOMAINS:
        raise HTTPException(status_code=400, detail="Unknown domain")
    steps = [s["id"] for s in DEFAULT_ROADMAPS[payload.domain]]
    if payload.step_id not in steps:
        raise HTTPException(status_code=400, detail="Unknown step")
    suggestion = {
        "domain": payload.domain,
        "step_id": payload.step_id,
        "title": payload.title,
        "url": payload.url,
        "suggested_by": str(user["_id"])  # type: ignore
    }
    create_document("videosuggestion", suggestion)
    return {"status": "saved"}

@app.get("/suggest-video/{domain}/{step_id}")
def list_suggestions(domain: str, step_id: str):
    items = get_documents("videosuggestion", {"domain": domain, "step_id": step_id})
    for it in items:
        it["_id"] = str(it["_id"])  # type: ignore
    return {"items": items}

# -----------------------------
# Assessments
# -----------------------------

@app.post("/assessment/submit")
def submit_assessment(payload: AssessmentPayload, user=Depends(get_user_from_token)):
    if payload.domain not in ALLOWED_DOMAINS:
        raise HTTPException(status_code=400, detail="Unknown domain")
    steps = DEFAULT_ROADMAPS[payload.domain]
    ids = [s["id"] for s in steps]
    if payload.step_id not in ids:
        raise HTTPException(status_code=400, detail="Unknown step")
    passed = payload.score >= PASS_MARKS
    prog = db.roadmapprogress.find_one({"user_id": str(user["_id"]), "domain": payload.domain})
    if not prog:
        raise HTTPException(status_code=400, detail="Progress not initialized. Select domain first.")

    # Update results
    result = {"domain": payload.domain, "step_id": payload.step_id, "score": payload.score, "passed": passed}
    db.roadmapprogress.update_one(
        {"_id": prog["_id"]},
        {"$push": {"results": result}}
    )

    # Update steps_status and current step
    step_index = ids.index(payload.step_id)
    steps_status = prog.get("steps_status", ["locked"] * len(steps))
    if step_index < len(steps_status):
        steps_status[step_index] = "passed" if passed else "unlocked"
        # unlock next if passed
        if passed and step_index + 1 < len(steps_status):
            steps_status[step_index + 1] = "unlocked"
    current_step_index = prog.get("current_step_index", 0)
    if passed and step_index >= current_step_index:
        current_step_index = step_index + 1

    db.roadmapprogress.update_one(
        {"_id": prog["_id"]},
        {"$set": {"steps_status": steps_status, "current_step_index": current_step_index}}
    )

    return {"passed": passed, "score": payload.score}

@app.get("/dashboard/progress")
def dashboard_progress(user=Depends(get_user_from_token)):
    progs = list(db.roadmapprogress.find({"user_id": str(user["_id"]) }))
    items = []
    for p in progs:
        steps = DEFAULT_ROADMAPS[p["domain"]]
        total = len(steps)
        passed = sum(1 for s in p.get("steps_status", []) if s == "passed")
        items.append({"domain": p["domain"], "completed": passed, "total": total, "percent": int(passed*100/total)})
    return {"items": items}

# -----------------------------
# Final comprehensive assessment per domain
# -----------------------------

@app.post("/assessment/final/{domain}")
def final_assessment(domain: str, score: int = Query(..., ge=0, le=100), user=Depends(get_user_from_token)):
    if domain not in ALLOWED_DOMAINS:
        raise HTTPException(status_code=400, detail="Unknown domain")
    prog = db.roadmapprogress.find_one({"user_id": str(user["_id"]), "domain": domain})
    if not prog:
        raise HTTPException(status_code=400, detail="No progress for domain")
    # only allow if all steps passed
    steps = DEFAULT_ROADMAPS[domain]
    if not all(s == "passed" for s in prog.get("steps_status", [])):
        raise HTTPException(status_code=400, detail="Complete all steps before final assessment")
    passed = score >= 60
    db.roadmapprogress.update_one({"_id": prog["_id"]}, {"$set": {"final_score": score, "final_passed": passed}})
    return {"passed": passed, "score": score}

# -----------------------------
# Resume Builder
# -----------------------------

@app.post("/resume")
def upsert_resume(payload: ResumePayload, user=Depends(get_user_from_token)):
    existing = db.resume.find_one({"user_id": str(user["_id"])})
    doc = {"user_id": str(user["_id"]), **payload.model_dump()}
    if existing:
        db.resume.update_one({"_id": existing["_id"]}, {"$set": doc})
    else:
        create_document("resume", doc)
    return {"status": "saved"}

@app.get("/resume")
def get_resume(user=Depends(get_user_from_token)):
    res = db.resume.find_one({"user_id": str(user["_id"])})
    if not res:
        return {"summary": "", "skills": [], "education": [], "experience": [], "projects": []}
    res["_id"] = str(res["_id"])  # type: ignore
    return res

@app.get("/resume/download")
def download_resume(user=Depends(get_user_from_token)):
    res = db.resume.find_one({"user_id": str(user["_id"])})
    user_doc = db.user.find_one({"_id": user["_id"]})
    if not res:
        raise HTTPException(status_code=404, detail="No resume found")
    name = f"{user_doc.get('first_name', '')} {user_doc.get('last_name', '')}".strip()
    html = f"""
    <html>
    <head><meta charset='utf-8'><title>Resume - {name}</title></head>
    <body style='font-family: Arial, sans-serif; padding: 24px;'>
      <h1 style='margin:0'>{name}</h1>
      <p style='color:#555'>{user_doc.get('email','')} | {user_doc.get('phone','')}</p>
      <h2>Summary</h2>
      <p>{res.get('summary','')}</p>
      <h2>Skills</h2>
      <ul>{''.join([f'<li>{s}</li>' for s in res.get('skills', [])])}</ul>
      <h2>Education</h2>
      <ul>{''.join([f"<li><strong>{e.get('degree','')}</strong> - {e.get('institution','')} ({e.get('start','')} - {e.get('end','')})</li>" for e in res.get('education',[])])}</ul>
      <h2>Experience</h2>
      <ul>{''.join([f"<li><strong>{x.get('role','')}</strong> - {x.get('company','')} ({x.get('start','')} - {x.get('end','')})<br/>{x.get('description','')}</li>" for x in res.get('experience',[])])}</ul>
      <h2>Projects</h2>
      <ul>{''.join([f"<li><strong>{p.get('name','')}</strong> - {p.get('description','')}<br/>Tech: {p.get('tech','')} | <a href='{p.get('link','')}'>{p.get('link','')}</a></li>" for p in res.get('projects',[])])}</ul>
    </body>
    </html>
    """
    from fastapi.responses import Response
    return Response(content=html, media_type="text/html", headers={"Content-Disposition": "attachment; filename=resume.html"})
