# Статус реализации

Фиксируются только реально работающие и покрытые тестами функции.

## PHASE 1 — Architecture ✅ (16.11.2026)

Сделано и проверено:
- Архитектура (`docs/ARCHITECTURE.md`) и 8 ADR (`docs/adr/`).
- Скелет пакетов по слоям; у каждого пакета задокументирована ответственность (проверяется тестом).
- Границы слоёв — 4 контракта import-linter; тест падает при нарушении (проверено намеренным нарушением).
- Доменная модель: `Cookie`, `SecretValue` (маскирование в str/repr/format/логах), `Finding`,
  перечисления `ValidationStatus` (со сведением к худшему), `Severity`, `SameSite`, `ValueState`, `SourceFormat`.
- Схема БД из 17 таблиц + FTS5 trigram с триггерами; миграция `0001`, upgrade/downgrade.
- Тест против дрейфа ORM ↔ миграции.
- Каталоги данных: `CIP_DATA_DIR`, портативный режим (`portable.flag`), каталог пользователя ОС.
- CLI: `info`, `db upgrade`, `db status`.
- Инструменты качества: ruff, ruff format, mypy (strict для ядра), import-linter, pytest;
  `scripts/check.sh` и `scripts/check.ps1`.

Результат проверок: ruff — чисто; mypy — 0 ошибок; import-linter — 4/4; pytest — 28 passed.

Ещё не реализовано (по плану): парсеры, импорт, валидация, шифрование, репозитории (PHASE 2);
GUI (PHASE 3); остальные модули (PHASE 4+). Запуск `python main.py` без аргументов сообщает,
что GUI появится в PHASE 3.

## Окружение разработки
Linux-контейнер без дисплея, 1 CPU, 3,9 ГБ RAM, Python 3.12.3. Визуальная проверка GUI
и тесты на Windows — на стороне пользователя.
