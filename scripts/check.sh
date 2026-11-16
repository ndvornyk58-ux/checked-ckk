#!/usr/bin/env bash
# Полная проверка качества: тот же набор, что обязателен для закрытия каждой фазы.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== ruff (стиль и типичные ошибки)";    ruff check .
echo "== ruff format (единый формат)";       ruff format --check .
echo "== mypy (типы; strict для ядра)";      mypy app
echo "== import-linter (границы слоёв)";    lint-imports
echo "== pytest";                            python -m pytest "$@"
echo "Все проверки пройдены."
