import pytest

from flowguard import Guard, Policy

DESTINATIONS = {
    "internal_db": "HIGHLY_SENSITIVE",
    "analytics": "SENSITIVE",
    "trusted_api": "CONFIDENTIAL",
    "external_api": "PUBLIC",
}

EMPLOYEE = {
    "id": "E011",
    "name": "Kim Min-jun",
    "email": "minjun.kim@corp.com",
    "department": "Engineering",
    "salary": 85000,
    "ssn": "123-45-6791",
}


@pytest.fixture
def policy():
    return Policy.default(destinations=DESTINATIONS)


@pytest.fixture
def guard(policy):
    g = Guard(policy)
    g.observe(EMPLOYEE, source="db.read_employee")
    return g
