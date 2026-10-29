# Contributing

Thanks for helping. SovereignMCP is source-available under the PolyForm Shield License (see `LICENSE`).

## Contributor agreement
By submitting a contribution you confirm you have the right to, and you license it to the project owner under terms that allow the owner to
use, modify, sublicense and relicense it (including in commercial offerings). A CLA bot may ask you to sign on your first pull request.

## Development

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev,bridges]"
python -m unittest discover -s tests -t . -v
```

## Ground rules
- Security-sensitive code **fails closed**. If it can't understand an input, it blocks or asks a human.
- Every bypass you fix gets a regression test in `tests/`.
- Nothing from a tool call's arguments or results may leave the machine in cloud mode. `tests/test_egress.py` enforces it; keep it green.
- Never commit secrets (tokens, keys, `policy.yaml` with real hashes, audit databases).
