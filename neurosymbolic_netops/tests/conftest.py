import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.inventory import load_testbed  # noqa: E402


@pytest.fixture(scope="session")
def testbed():
    return load_testbed()


@pytest.fixture
def net(testbed):
    from core.config_ir import copy_network
    return copy_network(testbed.network)
