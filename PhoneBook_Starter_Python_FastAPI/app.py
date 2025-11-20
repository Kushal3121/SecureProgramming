from datetime import datetime
import logging
import re
import secrets

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# FastAPI app

app = FastAPI(title="Secure PhoneBook API")

# Database setup (SQLite)

engine = create_engine("sqlite:///phonebook.db", echo=True, connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class PhoneBook(Base):
    __tablename__ = "phonebook"

    id = Column(Integer, primary_key=True, index=True)
    # Use field names that line up conceptually with the OpenAPI schema
    name = Column(String, nullable=False)
    phone_number = Column(String, nullable=False)


Base.metadata.create_all(engine)

# Audit logging setup

logger = logging.getLogger("phonebook_audit")
logger.setLevel(logging.INFO)
handler = logging.FileHandler("audit.log")
formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
handler.setFormatter(formatter)
logger.addHandler(handler)


def log_action(action: str, user: str | None, detail: str = "") -> None:
    """
    Write a line to the audit log.

    action: LIST / ADD / DELETE_BY_NAME / DELETE_BY_NUMBER / AUTH_FAIL etc.
    user:   authenticated username, or "anonymous" / None
    detail: extra information (eg. name or phone number)
    """
    username = user or "anonymous"
    logger.info(f"action={action} user={username} detail={detail}")


# Authentication & Authorization

security = HTTPBasic()

# Super simple in-memory user store for the assignment
USERS = {
    "reader": {"password": "readerpass", "role": "read"},
    "admin": {"password": "adminpass", "role": "readwrite"},
}


class AuthUser(BaseModel):
    username: str
    role: str


def get_current_user(credentials: HTTPBasicCredentials = Depends(security)) -> AuthUser:
    """
    HTTP Basic authentication.
    - reader / readerpass -> role=read
    - admin / adminpass   -> role=readwrite
    """
    user_record = USERS.get(credentials.username)
    if not user_record:
        log_action("AUTH_FAIL", None, f"unknown_user={credentials.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    # Use constant-time comparison for passwords
    correct_password = user_record["password"]
    if not secrets.compare_digest(credentials.password, correct_password):
        log_action("AUTH_FAIL", credentials.username, "bad_password")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    return AuthUser(username=credentials.username, role=user_record["role"])


def require_role(required: str):
    """
    Dependency factory that checks the user has the required role.
    - "read": allows read + readwrite
    - "readwrite": only allows readwrite
    """

    def role_checker(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if required == "read":
            # Any authenticated user is okay
            return user
        if required == "readwrite" and user.role != "readwrite":
            log_action("AUTHZ_FAIL", user.username, f"required={required}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return role_checker


# Regex Validation

# Person name validation:
# - allow:
#   * "Bruce Schneier"
#   * "Schneier, Bruce"
#   * "Schneier, Bruce Wayne"
#   * "O’Malley, John F."
#   * "John O’Malley-Smith"
#   * "Cher"
# - reject multi-apostrophe, multi-hyphen last-names, digits, angle brackets, etc.

NAME_BASIC_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z'’.-]*(?:[ ]+[A-Za-z][A-Za-z'’.-]*)*(?:,[ ]*[A-Za-z][A-Za-z'’.-]*(?:[ ]+[A-Za-z][A-Za-z'’.-]*\.?)?)?$"
)


def is_valid_name(value: str) -> bool:
    # No obvious script tags or angle brackets
    if "<" in value or ">" in value:
        return False
    # No digits
    if re.search(r"\d", value):
        return False
    # Basic pattern match
    if not NAME_BASIC_PATTERN.fullmatch(value.strip()):
        return False

    # Split on comma to separate "Last, First MI" forms
    parts = [p.strip() for p in value.split(",")]
    if len(parts) > 2:
        return False

    # Limit number of words before/after comma
    if len(parts) == 1:
        # No comma: allow 1 to 3 words max ("Cher", "Bruce Schneier", "Bruce Wayne Schneier")
        words = parts[0].split()
        if not (1 <= len(words) <= 3):
            return False
    else:
        # "Last, First" or "Last, First MI"
        last, rest = parts
        if len(last.split()) > 1:
            # Last name should be a single token (may include apostrophe/hyphen)
            return False
        rest_words = rest.split()
        if not (1 <= len(rest_words) <= 2):
            return False

    # Disallow double apostrophes
    if "''" in value or "’’" in value:
        return False

    # Limit total hyphens in the name (reject triple-barrelled last name)
    if value.count("-") > 1:
        return False

    return True


# Phone number validation using several patterns
PHONE_PATTERNS = [
    # 5-digit extension / short internal
    re.compile(r"^\d{5}$"),
    # Subscriber number only: 123-1234
    re.compile(r"^\d{3}-\d{4}$"),
    # (703)111-2121
    re.compile(r"^\(\d{3}\)\d{3}-\d{4}$"),
    # 670-123-4567
    re.compile(r"^\d{3}-\d{3}-\d{4}$"),
    # 1-670-123-4567
    re.compile(r"^1-\d{3}-\d{3}-\d{4}$"),
    # 1(703)123-1234
    re.compile(r"^1\(\d{3}\)\d{3}-\d{4}$"),
    # 670 123 4567 or 1 670 123 4567
    re.compile(r"^1? ?\d{3} \d{3} \d{4}$"),
    # 670.123.4567 or 1.670.123.4567
    re.compile(r"^1?\.\d{3}\.\d{3}\.\d{4}$"),
    # +1(703)111-2121
    re.compile(r"^\+1\(\d{3}\)\d{3}-\d{4}$"),
    # +CC (AA) BBB-CCCC  (e.g. +32 (21) 212-2324)
    re.compile(r"^\+\d{1,3} \(\d{2,3}\) \d{3}-\d{4}$"),
    # 011 international formats (e.g. 011 701 111 1234, 011 1 703 111 1234)
    re.compile(r"^011( \d{1,4}){2,5}$"),
    # 12345.12345 (two groups of five)
    re.compile(r"^\d{5}\.\d{5}$"),
    # Danish formats: 12 34 56 78, 1234 5678, and with optional +45 / 45 prefix
    re.compile(r"^(\+?45[ .]?)?((\d{2}[ .]){3}\d{2}|\d{4}[ .]\d{4})$"),
]


def is_valid_phone(number: str) -> bool:
    # Block obvious bad stuff: letters, angle brackets, '/', 'ext'
    if re.search(r"[A-Za-z/]", number):
        return False
    if "<" in number or ">" in number:
        return False
    if "ext" in number.lower():
        return False

    # Must match at least one allowed pattern
    if not any(p.fullmatch(number.strip()) for p in PHONE_PATTERNS):
        return False

    # Additional semantic checks:
    # - Reject +0X and +01 country codes
    if number.strip().startswith("+0"):
        return False
    if number.strip().startswith("+01"):
        return False

    # For North American patterns, reject area codes starting with 0
    # Extract things inside parentheses if present
    m = re.search(r"\((\d{3})\)", number)
    if m:
        area = m.group(1)
        if area.startswith("0"):
            return False

    # Also reject pure 10-digit "7031111234" style by construction (no pattern matches it),
    # so no extra code needed here.

    return True


# Pydantic models (align with OpenAPI schema)

class PhoneBookEntry(BaseModel):
    name: str
    phoneNumber: str = Field(..., alias="phone_number")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not is_valid_name(v):
            raise HTTPException(
                status_code=400,
                detail="Invalid name format"
            )
        return v

    @field_validator("phoneNumber")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        if not is_valid_phone(v):
            raise HTTPException(
                status_code=400,
                detail="Invalid phone number format"
            )
        return v

    model_config = {
        "from_attributes": True,
        "populate_by_name": True
    }



# Dependency: DB session

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# API Endpoints

@app.get("/PhoneBook/list", response_model=list[PhoneBookEntry])
def list_phonebook(
    current_user: AuthUser = Depends(require_role("read")),
    db=Depends(get_db),
):
    entries = db.query(PhoneBook).all()
    log_action("LIST", current_user.username, f"count={len(entries)}")
    # FastAPI will convert ORM -> Pydantic via orm_mode
    return [PhoneBookEntry.from_orm(e) for e in entries]


@app.post("/PhoneBook/add", response_model=dict)
def add_person(
    entry: PhoneBookEntry,
    current_user: AuthUser = Depends(require_role("readwrite")),
    db=Depends(get_db),
):
    # Check for duplicate by phone number
    existing = db.query(PhoneBook).filter_by(phone_number=entry.phoneNumber).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Person with this phone number already exists",
        )

    record = PhoneBook(name=entry.name, phone_number=entry.phoneNumber)
    db.add(record)
    db.commit()

    log_action("ADD", current_user.username, f"name={entry.name}, phone={entry.phoneNumber}")
    return {"message": "Person added successfully"}


@app.put("/PhoneBook/deleteByName", response_model=dict)
def delete_by_name(
    name: str,
    current_user: AuthUser = Depends(require_role("readwrite")),
    db=Depends(get_db),
):
    # Validate name input via regex
    if not is_valid_name(name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid name format",
        )

    person = db.query(PhoneBook).filter_by(name=name).first()
    if not person:
        log_action("DELETE_BY_NAME_NOT_FOUND", current_user.username, f"name={name}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Person not found in the database",
        )

    db.delete(person)
    db.commit()

    log_action("DELETE_BY_NAME", current_user.username, f"name={name}")
    return {"message": "Person deleted successfully"}


@app.put("/PhoneBook/deleteByNumber", response_model=dict)
def delete_by_number(
    number: str,
    current_user: AuthUser = Depends(require_role("readwrite")),
    db=Depends(get_db),
):
    # Validate phone number via regex
    if not is_valid_phone(number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid phone number format",
        )

    person = db.query(PhoneBook).filter_by(phone_number=number).first()
    if not person:
        log_action("DELETE_BY_NUMBER_NOT_FOUND", current_user.username, f"number={number}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Person not found in the database",
        )

    db.delete(person)
    db.commit()

    log_action("DELETE_BY_NUMBER", current_user.username, f"number={number}")
    return {"message": "Person deleted successfully"}
