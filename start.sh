#!/usr/bin/env bash
# ProxyPulse CLI: запуск на macOS / Linux (создаёт .venv и ставит зависимости при первом старте).
set -euo pipefail
cd "$(dirname "$0")"

export PYTHONUTF8=1

find_python() {
    local candidate
    for candidate in python3.13 python3.12 python3.11 python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 \
            && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

if ! PYTHON_BIN="$(find_python)"; then
    echo "[ошибка] Не найден Python 3.11+. Установите его (https://www.python.org/downloads/ или через пакетный менеджер)."
    exit 1
fi

if [ ! -x ".venv/bin/python" ]; then
    echo "[setup] Создаю виртуальное окружение..."
    "$PYTHON_BIN" -m venv .venv
fi

if [ ! -f ".venv/deps_installed.flag" ]; then
    echo "[setup] Устанавливаю зависимости..."
    .venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
    touch .venv/deps_installed.flag
fi

exec .venv/bin/python main.py
