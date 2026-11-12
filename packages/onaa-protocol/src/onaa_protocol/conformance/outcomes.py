"""Exceptions a live conformance test raises to report its outcome (shared by the live runner modules)."""

from __future__ import annotations


class Fail(Exception):
    pass


class Skip(Exception):
    pass


class NotApplicable(Exception):
    pass
