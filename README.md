# Cookie Inspector Pro

Локальная desktop-платформа для анализа, проверки и аудита безопасности HTTP cookies
собственных веб-приложений и тестовых сред.

> Статус: **PHASE 1 завершена** — архитектура, модель данных, схема БД, инструменты качества.
> Подробно: [`docs/STATUS.md`](docs/STATUS.md). Устройство: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Требования
Python 3.12+.

## Установка для разработки
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Запуск
```bash
python main.py info          # где лежат данные, состояние схемы
python main.py db upgrade    # создать/обновить базу
python main.py db status
```

### Портативный режим
Создайте пустой файл `portable.flag` рядом с `main.py` (или с `.exe` сборки) — все данные будут
храниться в `./data` рядом с приложением, а не в профиле пользователя.

## Проверки
```bash
./scripts/check.sh           # Linux/macOS
.\scripts\check.ps1          # Windows PowerShell
```

## Принципы
- Всё обрабатывается локально; значения cookies хранятся только зашифрованными.
- Структурно корректная cookie не считается действительной сессией.
- Сетевая диагностика — только для собственных подтверждённых endpoint'ов (ADR-0004).
- Защита браузеров не обходится (ADR-0005).
