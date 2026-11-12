"""Load the ONAA Protocol v0.1 JSON Schemas (draft 2020-12).

The package bundles byte-identical copies of ``specs/schemas/onaa/v0.1/*.schema.json`` (checked by
``tests/test_schemas.py``), so it works both from a repository checkout and from an installed wheel.
"""

from __future__ import annotations

import json
from functools import cache
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

SCHEMA_FILES = {
    "envelope": "envelope.schema.json",
    "service-handoff": "service-handoff.schema.json",
    "agent-card-extension-params": "agent-card-extension-params.schema.json",
    "registry-trust-view": "registry-trust-view.schema.json",
    "attestation": "attestation.schema.json",
    "jws-signature": "jws-signature.schema.json",
    "conformance-trigger": "conformance-trigger.schema.json",
}
ID_PREFIX = "urn:onaa:schema:v0.1:"


@cache
def load_schema(name: str) -> dict[str, Any]:
    """Return a bundled schema by short name (see ``SCHEMA_FILES``)."""
    text = resources.files("onaa_protocol").joinpath("schemas", SCHEMA_FILES[name]).read_text(encoding="utf-8")
    return json.loads(text)


@cache
def registry() -> Registry:
    resources_ = [(ID_PREFIX + n, Resource.from_contents(load_schema(n))) for n in SCHEMA_FILES]
    return Registry().with_resources(resources_)


@cache
def validator(name: str, pointer: str = "") -> Draft202012Validator:
    """Validator for a schema, or for a ``$defs`` sub-schema when ``pointer`` is e.g. ``"#/$defs/statusRecord"``."""
    schema: dict[str, Any] = {"$ref": ID_PREFIX + name + pointer} if pointer else load_schema(name)
    return Draft202012Validator(schema, registry=registry(), format_checker=Draft202012Validator.FORMAT_CHECKER)


def errors(name: str, instance: Any, pointer: str = "") -> list[str]:
    """Sorted human-readable schema errors as ``"<json-path>: <message>"`` (empty list = valid)."""
    out = []
    for err in validator(name, pointer).iter_errors(instance):
        path = "/".join(str(p) for p in err.absolute_path)
        out.append(f"/{path}: {err.message}")
    return sorted(out)
