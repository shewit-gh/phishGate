import email
from email import policy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "data" / "samples"
TEMPLATES = ROOT / "data" / "templates"


@pytest.fixture
def benign_msg():
    return email.message_from_bytes((SAMPLES / "benign_invoice.eml").read_bytes(), policy=policy.default)


@pytest.fixture
def injected_msg():
    return email.message_from_bytes((SAMPLES / "injected_reset.eml").read_bytes(), policy=policy.default)
