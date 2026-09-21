#!/usr/bin/env bash
# Launch the OSINT Framework Streamlit dashboard (WSL / Linux / macOS safe).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# Activate venv if present
if [[ -f .venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
elif [[ -f venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source venv/bin/activate
fi

# Make the package importable regardless of how Streamlit resolves paths
export PYTHONPATH="${ROOT}${PYTHONPATH:+:$PYTHONPATH}"

PORT="${PORT:-8501}"
HOST="${HOST:-0.0.0.0}"

# Seed a user-level Streamlit config if missing (WSL-friendly defaults)
mkdir -p "${HOME}/.streamlit"
if [[ ! -f "${HOME}/.streamlit/config.toml" ]]; then
  cat > "${HOME}/.streamlit/config.toml" << 'EOF'
[browser]
gatherUsageStats = false

[server]
headless = true
address = "0.0.0.0"
port = 8501
fileWatcherType = "poll"
EOF
fi

echo "============================================================"
echo " OSINT Framework — Streamlit UI"
echo "============================================================"
echo " Binding : http://${HOST}:${PORT}"
echo ""
echo " Open this URL in your Windows browser (WSL cannot auto-open):"
echo "   →  http://localhost:${PORT}"
echo ""
echo " Press Ctrl+C to stop."
echo "============================================================"
echo ""

exec python -m streamlit run osint_framework/app.py \
  --server.address "${HOST}" \
  --server.port "${PORT}" \
  --server.headless true \
  --browser.gatherUsageStats false
