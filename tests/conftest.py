"""Shared test fixtures — automatic cleanup of ~/.cloakmcp/ test artifacts.

Every test that creates a Vault or backup generates a unique project slug
in ~/.cloakmcp/ (keys, vaults, backups).  Without cleanup, thousands of
orphaned entries accumulate over repeated test runs.

This module provides an autouse fixture that snapshots the slug directories
before each test and removes any new entries on teardown.
"""
from __future__ import annotations
import os
import shutil

import pytest

from cloakmcp.storage import KEYS_DIR, VAULTS_DIR, BACKUPS_DIR


def _list_entries(directory: str) -> set:
    """List entries in a directory, returning empty set if it doesn't exist."""
    try:
        return set(os.listdir(directory))
    except FileNotFoundError:
        return set()


@pytest.fixture(autouse=True)
def _cleanup_cloakmcp_artifacts():
    """Remove key/vault/backup artifacts created during this test."""
    before = {
        KEYS_DIR: _list_entries(KEYS_DIR),
        VAULTS_DIR: _list_entries(VAULTS_DIR),
        BACKUPS_DIR: _list_entries(BACKUPS_DIR),
    }
    yield
    for directory, old_entries in before.items():
        current = _list_entries(directory)
        for entry in current - old_entries:
            target = os.path.join(directory, entry)
            if os.path.isfile(target):
                try:
                    os.remove(target)
                except OSError:
                    pass
            elif os.path.isdir(target):
                shutil.rmtree(target, ignore_errors=True)
