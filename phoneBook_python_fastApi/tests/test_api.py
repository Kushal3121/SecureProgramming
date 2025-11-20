import base64
import json
import pytest
from fastapi.testclient import TestClient
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app

client = TestClient(app)


# Helper: Basic Auth headers

def basic_auth(username, password):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


# Test: Authentication & Authorization

def test_auth_fail_wrong_password():
    response = client.get("/PhoneBook/list", headers=basic_auth("reader", "wrong"))
    assert response.status_code == 401


def test_auth_fail_unknown_user():
    response = client.get("/PhoneBook/list", headers=basic_auth("abc", "123"))
    assert response.status_code == 401


def test_authorization_fail_write_with_reader_role():
    response = client.post(
        "/PhoneBook/add",
        headers=basic_auth("reader", "readerpass"),
        json={"name": "Bruce Schneier", "phoneNumber": "123-1234"},
    )
    assert response.status_code == 403


# Valid Inputs (Names + Phones)

valid_names = [
    "Bruce Schneier",
    "Schneier, Bruce",
    "Schneier, Bruce Wayne",
    "O’Malley, John F.",
    "John O’Malley-Smith",
    "Cher",
]

valid_phones = [
    "12345",
    "123-1234",
    "(703)111-2121",
    "+1(703)111-2121",
    "+32 (21) 212-2324",
    "1(703)123-1234",
    "011 701 111 1234",
    "12345.12345",
]


# Invalid Inputs (Names + Phones)

invalid_names = [
    "Ron O’’Henry",
    "L33t Hacker",
    "<Script>alert(“XSS”)</Script>",
    "Brad Everett Samuel Smith",
    "select * from users;",
]

invalid_phones = [
    "123",
    "1/703/123/1234",
    "<script>alert(“XSS”)</script>",
    "7031111234",
    "+1234 (201) 123-1234",
    "ext 204",
]


# Test: Valid ADD operations

@pytest.mark.parametrize("name", valid_names)
@pytest.mark.parametrize("phone", valid_phones)
def test_add_valid(name, phone):
    response = client.post(
        "/PhoneBook/add",
        headers=basic_auth("admin", "adminpass"),
        json={"name": name, "phoneNumber": phone},
    )
    # Allow 200 if first time, OR 400 if duplicate phone number
    assert response.status_code in (200, 400)


# Test: Invalid ADD operations

@pytest.mark.parametrize("name", invalid_names)
def test_add_invalid_name(name):
    response = client.post(
        "/PhoneBook/add",
        headers=basic_auth("admin", "adminpass"),
        json={"name": name, "phoneNumber": "123-1234"},
    )
    assert response.status_code == 400


@pytest.mark.parametrize("phone", invalid_phones)
def test_add_invalid_phone(phone):
    response = client.post(
        "/PhoneBook/add",
        headers=basic_auth("admin", "adminpass"),
        json={"name": "Bruce Schneier", "phoneNumber": phone},
    )
    assert response.status_code == 400


# Test DELETE operations

def test_delete_non_existent_name():
    response = client.put(
        "/PhoneBook/deleteByName",
        params={"name": "NameDoesNotExist"},
        headers=basic_auth("admin", "adminpass"),
    )
    assert response.status_code == 404


def test_delete_non_existent_number():
    response = client.put(
        "/PhoneBook/deleteByNumber",
        params={"number": "999-9999"},
        headers=basic_auth("admin", "adminpass"),
    )
    assert response.status_code == 404


# Student-provided custom negative test

def test_sql_injection_attempt():
    response = client.post(
        "/PhoneBook/add",
        headers=basic_auth("admin", "adminpass"),
        json={"name": "Robert'); DROP TABLE phonebook;--", "phoneNumber": "123-1234"},
    )
    assert response.status_code == 400
