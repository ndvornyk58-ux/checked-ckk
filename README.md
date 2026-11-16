# Cookie Inspector Pro

Локальная desktop-платформа для анализа, проверки и аудита безопасности HTTP cookies
собственных веб-приложений и тестовых сред.

> Статус: **PHASE 2 завершена** — ядро: парсеры, импорт, валидация, шифрование, запросы. GUI — PHASE 3.
> Подробно: [`docs/STATUS.md`](docs/STATUS.md). Устройство: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Требования
Python 3.12+.

## Установка для разработки
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Запуск (командная строка; GUI — с PHASE 3)
```bash
python main.py info                                   # где лежат данные, состояние схемы
python main.py key init                               # создать ключ шифрования (keyring или мастер-пароль)
python main.py import ./cookies --project demo        # импорт файлов/каталогов + проверка
python main.py stats --project demo                   # сводка
python main.py list --project demo --status invalid   # записи (значения не выводятся)
python main.py validate --project demo                # повторная проверка
```
Форматы: Netscape, JSON (массив, Playwright, одиночный объект), JSON Lines, CSV, CIPX.
Тестовые файлы — в `test_data/` (`python scripts/gen_test_data.py fixtures` пересоздаёт их).

### Портативный режим
Создайте пустой файл `portable.flag` рядом с `main.py` (или с `.exe` сборки) — все данные будут
храниться в `./data` рядом с приложением, а не в профиле пользователя.

## Проверки
```bash
./scripts/check.sh           # Linux/macOS
.\scripts\check.ps1          # Windows PowerShell
python -m pytest -m perf -s  # производительность (CIP_PERF_N=500000 для большого набора)
```

## Принципы
- Всё обрабатывается локально; значения cookies хранятся только зашифрованными.
- Структурно корректная cookie не считается действительной сессией.
- Сетевая диагностика — только для собственных подтверждённых endpoint'ов (ADR-0004).
- Защита браузеров не обходится (ADR-0005).
