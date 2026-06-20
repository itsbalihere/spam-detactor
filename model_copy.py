from pathlib import Path
import os
import secrets
import sqlite3

import bcrypt
import pandas as pd
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split


BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "spam.csv"
TEMPLATE_PATH = BASE_DIR / "templates" / "index.html"
DB_PATH = Path(os.getenv("SPAM_DETECTOR_DB", BASE_DIR / "spam_detector.sqlite3"))


def get_db_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db_connection()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                age INTEGER NOT NULL,
                phone_number TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                api_key TEXT NOT NULL UNIQUE,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_api_keys_user_active
                ON api_keys (user_id, is_active);

            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_user_sessions_token
                ON user_sessions (session_token);
            """
        )
        conn.commit()
    finally:
        conn.close()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def row_to_user(row):
    if not row:
        return None
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "password_hash": row["password_hash"],
        "age": row["age"],
        "phone_number": row["phone_number"],
    }


def get_user_by_email(email: str):
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, name, email, password_hash, age, phone_number FROM users WHERE email = ?",
            (email.lower().strip(),),
        ).fetchone()
        return row_to_user(row)
    finally:
        conn.close()


def create_user(name: str, email: str, password: str, age: int, phone_number: str):
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO users (name, email, password_hash, age, phone_number)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                name.strip(),
                email.lower().strip(),
                hash_password(password),
                age,
                phone_number.strip(),
            ),
        )
        user_id = cursor.lastrowid
        api_key = create_api_key(conn, user_id)
        conn.commit()
        return user_id, api_key
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already exists")
    finally:
        conn.close()


def create_api_key(conn, user_id: int) -> str:
    while True:
        api_key = "sk-" + secrets.token_urlsafe(32)
        exists = conn.execute("SELECT id FROM api_keys WHERE api_key = ?", (api_key,)).fetchone()
        if not exists:
            conn.execute(
                "INSERT INTO api_keys (user_id, api_key, is_active) VALUES (?, ?, 1)",
                (user_id, api_key),
            )
            return api_key


def create_session(user_id: int) -> str:
    conn = get_db_connection()
    try:
        while True:
            session_token = "sess-" + secrets.token_urlsafe(32)
            exists = conn.execute(
                "SELECT id FROM user_sessions WHERE session_token = ?",
                (session_token,),
            ).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO user_sessions (user_id, session_token) VALUES (?, ?)",
                    (user_id, session_token),
                )
                conn.commit()
                return session_token
    finally:
        conn.close()


def get_user_id_from_session(session_token: str) -> int:
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT user_id FROM user_sessions WHERE session_token = ?",
            (session_token,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid session. Please log in again.")
        return row["user_id"]
    finally:
        conn.close()


def get_user_id_from_api_key(api_key: str) -> int:
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT user_id FROM api_keys WHERE api_key = ? AND is_active = 1",
            (api_key,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid or inactive API key")
        return row["user_id"]
    finally:
        conn.close()


def get_active_api_key(user_id: int):
    conn = get_db_connection()
    try:
        row = conn.execute(
            """
            SELECT api_key FROM api_keys
            WHERE user_id = ? AND is_active = 1
            ORDER BY id DESC
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        return row["api_key"] if row else None
    finally:
        conn.close()


def revoke_all_keys(user_id: int):
    conn = get_db_connection()
    try:
        conn.execute("UPDATE api_keys SET is_active = 0 WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def generate_new_api_key(user_id: int) -> str:
    conn = get_db_connection()
    try:
        conn.execute("UPDATE api_keys SET is_active = 0 WHERE user_id = ?", (user_id,))
        new_key = create_api_key(conn, user_id)
        conn.commit()
        return new_key
    finally:
        conn.close()


init_db()

data = pd.read_csv(DATA_PATH, encoding="latin-1")[["v1", "v2"]]
data.columns = ["Label", "Message"]
data["Label"] = data["Label"].map({"spam": 1, "ham": 0})

vectorizer = TfidfVectorizer(lowercase=True, stop_words="english", ngram_range=(1, 2))
X = vectorizer.fit_transform(data["Message"])
y = data["Label"]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = LogisticRegression(class_weight="balanced", max_iter=2000)
model.fit(X_train, y_train)


app = FastAPI(
    title="Spam Detector API",
    description="Create an account, generate an API key, and classify spam messages.",
    version="1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SignupRequest(BaseModel):
    name: str = Field(..., min_length=2)
    email: str = Field(..., min_length=5)
    password: str = Field(..., min_length=6)
    age: int = Field(..., ge=1, le=120)
    phone_number: str = Field(..., min_length=5)


class LoginRequest(BaseModel):
    email: str
    password: str


class MessageRequest(BaseModel):
    message: str


class PredictionResponse(BaseModel):
    prediction: str
    confidence: float


async def get_current_user(api_key: str = Header(..., alias="X-API-Key")):
    return get_user_id_from_api_key(api_key)


async def get_dashboard_user(session_token: str = Header(..., alias="X-Session-Token")):
    return get_user_id_from_session(session_token)


@app.get("/", response_class=HTMLResponse)
async def get_index():
    return HTMLResponse(content=TEMPLATE_PATH.read_text(encoding="utf-8"), status_code=200)


@app.get("/health")
async def health():
    return {"status": "ok", "database": "sqlite"}


@app.post("/signup")
async def signup(request: SignupRequest):
    if "@" not in request.email:
        raise HTTPException(status_code=400, detail="Valid email is required")
    user_id, api_key = create_user(
        request.name,
        request.email,
        request.password,
        request.age,
        request.phone_number,
    )
    session_token = create_session(user_id)
    return {
        "message": "User created",
        "api_key": api_key,
        "session_token": session_token,
        "user": {
            "id": user_id,
            "name": request.name,
            "email": request.email.lower(),
            "age": request.age,
            "phone_number": request.phone_number,
        },
    }


@app.post("/login")
async def login(request: LoginRequest):
    user = get_user_by_email(request.email)
    if not user or not verify_password(request.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    api_key = get_active_api_key(user["id"]) or generate_new_api_key(user["id"])
    session_token = create_session(user["id"])
    return {
        "message": "Login successful",
        "api_key": api_key,
        "session_token": session_token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "age": user["age"],
            "phone_number": user["phone_number"],
        },
    }


@app.get("/api-keys")
async def get_current_key(user_id: int = Depends(get_dashboard_user)):
    return {"api_key": get_active_api_key(user_id)}


@app.post("/api-keys/generate")
async def generate_key(user_id: int = Depends(get_dashboard_user)):
    return {"api_key": generate_new_api_key(user_id)}


@app.post("/api-keys/revoke")
async def revoke_key(user_id: int = Depends(get_dashboard_user)):
    revoke_all_keys(user_id)
    return {"message": "All keys revoked"}


@app.post("/predict", response_model=PredictionResponse)
async def predict(request: MessageRequest, user_id: int = Depends(get_current_user)):
    if not request.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    msg_vec = vectorizer.transform([request.message])
    proba = model.predict_proba(msg_vec)[0]
    pred_class = model.predict(msg_vec)[0]

    if pred_class == 1:
        return PredictionResponse(prediction="spam", confidence=round(float(proba[1]), 4))
    return PredictionResponse(prediction="ham", confidence=round(float(proba[0]), 4))


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
