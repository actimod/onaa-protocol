# ONAA Registry Steward (`apps/steward`)

System A2A agent of the ONAA registry. Design, autonomy levels and safety: `docs/REGISTRY_STEWARD.md`.

```bash
pip install -e apps/api -e packages/onaa-protocol -e 'apps/steward[dev]'
cd apps/steward && pytest            # includes the spec section 6 MVP scenario
```

Hosted: the registry container mounts it at `/steward` (`apps/mcp-registry/onaa_mcp_registry/hosted.py`).
Standalone against a registry: `ONAA_STEWARD_REGISTRY_URL=... ONAA_STEWARD_TOKEN=... onaa-steward serve`.

| Env | Default | Meaning |
|---|---|---|
| `ONAA_STEWARD_ENABLED` | `1` | Hosted app: mount `/steward` and run the sweep |
| `ONAA_STEWARD_TOKEN` | random per process (hosted) | Policy Service token; registry and steward must share it |
| `ONAA_STEWARD_INTERVAL` | `1800` | Seconds between sweeps (minimum 60) |
| `ONAA_STEWARD_SWEEP_LIMIT` | `50` | Listings probed per sweep |
| `ONAA_STEWARD_RATE_LIMIT` | `30` | A2A requests per caller per minute (reports: 1/6 of it) |
| `ONAA_STEWARD_FIRST_DELAY` | `20` | Seconds after start before publishing its listing and the first sweep |
| `ANTHROPIC_API_KEY` | unset | Enables plain-language conversation (`ask`); unset = conversation off (secret, never in Git) |
| `ONAA_STEWARD_CHAT` | `1` | `0` turns conversation off even when a key is set |
| `ONAA_STEWARD_CHAT_MODEL` | `claude-opus-5-5` | Model used for conversation |
| `ONAA_STEWARD_CHAT_EFFORT` | `low` | Model effort (cost control) |
| `ONAA_STEWARD_CHAT_DAILY_LIMIT` | `200` | Answered questions per day, per process; after that `ask` declines until midnight |
