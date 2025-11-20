# Secure PhoneBook API — README

## Overview

This project implements a secure PhoneBook REST API using FastAPI, SQLite, and Docker. The API supports authentication, authorization, input validation, SQL injection protection, audit logging, and complete test coverage using `pytest`.

All **65/65 tests pass** both locally and inside Docker, ensuring the API meets all security and validation requirements.

---

## Features

### 1. Authentication (HTTP Basic)

| Username | Password   | Role      |
| -------- | ---------- | --------- |
| reader   | readerpass | read      |
| admin    | adminpass  | readwrite |

- `reader` → can only list
- `admin` → can add + delete + list

Role enforcement is done using FastAPI dependency injection.

### 2. Authorization

Endpoints enforce permissions:

- `GET /PhoneBook/list` → `read` or `readwrite`
- `POST /PhoneBook/add` → `readwrite` only
- `DELETE /PhoneBook/deleteByName` → `readwrite`
- `DELETE /PhoneBook/deleteByNumber` → `readwrite`

### 3. Input Validation

Input validation protects against:

- SQL injection
- XSS tags (`<script>`, `<Script>`)
- Invalid names (digits, multiple apostrophes, too many words, etc.)
- Invalid phone numbers (strict regex whitelist)
- Dangerous patterns (`ext`, `/`, `<`, `>`)

All validation is done with:

- Custom regex rules
- Pydantic validators
- Strict whitelist-based formats

### 4. Audit Logging

All user actions are logged in `audit.log` with:

```
action=ADD user=admin detail=name=Bruce, phone=123-1234
action=AUTH_FAIL user=anonymous detail=unknown_user=xyz
action=DELETE_BY_NUMBER user=admin detail=number=123-1234
```

### 5. Database

- SQLite local DB (`phonebook.db`)
- SQLAlchemy ORM
- Safe queries using `filter_by` (prevents injection)

### 6. Automated Testing

`pytest` tests validate:

- Authentication failures
- Authorization failures
- Valid add operations
- Invalid names
- Invalid phone numbers
- SQL injection attempts
- Delete operations
- Duplicate entries

All **65 tests pass successfully**.

---

## Installation & Setup

### 1. Create a virtual environment

```bash
python3 -m venv env
source env/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the application

```bash
uvicorn app:app --reload
```

API is now available at: 👉 http://127.0.0.1:8000  
Docs: 👉 http://127.0.0.1:8000/docs

---

## Running Tests Locally

```bash
pytest -v
```

**Expected:**

```
65 passed, 0 failed
```

---

## Docker Instructions

### 1. Build the Docker image

```bash
docker build -t secure-phonebook .
```

### 2. Run the Docker container

```bash
docker run -p 8000:8000 secure-phonebook
```

### 3. Run tests inside Docker

```bash
docker run --rm --entrypoint pytest secure-phonebook -v
```

**Expected output:**

```
65 passed, 1 warning in 0.4s
```

---

## API Endpoints

### GET /PhoneBook/list

List all phonebook entries (reader/admin allowed)

### POST /PhoneBook/add

Add a new entry (admin only)

**Request JSON:**

```json
{
  "name": "Bruce Schneier",
  "phoneNumber": "123-1234"
}
```

### PUT /PhoneBook/deleteByName?name=Bruce%20Schneier

Delete by name (admin only)

### PUT /PhoneBook/deleteByNumber?number=123-1234

Delete by phone number (admin only)

---

## Security Measures Summary

- Whitelist-based regex validation
- Pydantic validation blocks bad input
- Rejects SQL injection patterns
- Rejects XSS
- HTTP Basic auth (constant-time password comparison)
- Role-based access control
- Full audit logging
- Docker containerization isolation
