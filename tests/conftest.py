import pytest
import random


@pytest.fixture(autouse=True)
def seed_random():
    random.seed()
