"""Make sure every name listed in a package's __all__ actually exists."""

import importlib

import pytest


@pytest.mark.parametrize("module_name", ["anp", "anp.ap2"])
def test_all_names_are_importable(module_name):
    module = importlib.import_module(module_name)
    missing = [name for name in module.__all__ if not hasattr(module, name)]
    assert not missing, f"{module_name}.__all__ lists names that don't exist: {missing}"


def test_star_import():
    namespace = {}
    exec("from anp import *", namespace)
    assert "ANPClient" in namespace
