# Patchi Web Preview — Run Doc

## How to reproduce artifacts
- No build step needed — pure Python (FastAPI + Jinja2 templates)
- Dependencies installed via `pip install -e .` or `uv pip install -e .`

## How to run the server
```bash
cd C:\Users\ehis\source\repos\Patchi_COMPLETE
python -m patchi web --port 1612 --host 127.0.0.1
```

The server serves the dashboard at http://127.0.0.1:1612/
