"""Write specs/openapi.json from the app (deterministic, no network)."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from onaa_registry.config import Settings
from onaa_registry.main import create_app

out = Path(__file__).resolve().parents[3] / "specs" / "openapi.json"
spec = create_app(Settings(database_url="sqlite://")).openapi()
out.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n")
print(f"wrote {out}")
