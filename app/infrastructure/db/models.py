"""ORM-схема хранилища (SQLAlchemy 2.0).

Принципы:
* Значение cookie хранится только в зашифрованном виде (``value_ciphertext``), рядом —
  ключевой HMAC (``value_hmac``) для поиска дубликатов без расшифровки. Открытого значения в БД нет.
* Время — целые секунды Unix UTC: одинаково в SQLite и PostgreSQL, дёшево индексируется.
* Схема не использует возможностей только SQLite, кроме полнотекстового индекса FTS5,
  который создаётся в миграции отдельно и только для диалекта sqlite.
* Перечисления хранятся строками (native_enum=False) — переносимо и читаемо.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.domain.enums import (
    FindingEngine,
    SameSite,
    Severity,
    SourceFormat,
    ValidationStatus,
    ValueState,
)

NAMING = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def _enum(e: type[Any], name: str) -> Enum:
    return Enum(e, name=name, native_enum=False, values_callable=lambda x: [m.value for m in x], length=32)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)
    type_annotation_map = {dict[str, Any]: JSON, list[Any]: JSON}  # noqa: RUF012 — API SQLAlchemy


# --------------------------------------------------------------------------- проекты и настройки
class Project(Base):
    """Рабочее пространство: изолированный набор импортов, cookies и диагностик."""

    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)


class Setting(Base):
    """Пользовательские настройки (несекретные), ключ-значение."""

    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON)
    updated_at: Mapped[int] = mapped_column(Integer)


class KeyStore(Base):
    """Обёрнутый ключ шифрования данных (DEK). Сам DEK в открытом виде не хранится.

    ``kdf`` — способ получения ключа-обёртки: системный keyring или scrypt от мастер-пароля.
    ``key_check`` — зашифрованная контрольная строка для проверки правильности ключа.
    """

    __tablename__ = "key_store"
    id: Mapped[int] = mapped_column(primary_key=True)
    purpose: Mapped[str] = mapped_column(String(32), unique=True)
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary)
    kdf: Mapped[str] = mapped_column(String(32))
    kdf_params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    key_check: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[int] = mapped_column(Integer)
    rotated_at: Mapped[int | None] = mapped_column(Integer)


# --------------------------------------------------------------------------- импорт
class ImportBatch(Base):
    """Одна операция импорта (может включать много файлов)."""

    __tablename__ = "import_batches"
    __table_args__ = (CheckConstraint("status IN ('running','completed','cancelled','failed')", name="status"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    started_at: Mapped[int] = mapped_column(Integer)
    finished_at: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class SourceFile(Base):
    """Метаданные импортированного файла. sha256 позволяет распознать повторный импорт."""

    __tablename__ = "source_files"
    id: Mapped[int] = mapped_column(primary_key=True)
    batch_id: Mapped[int] = mapped_column(ForeignKey("import_batches.id", ondelete="CASCADE"), index=True)
    path: Mapped[str] = mapped_column(Text)
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    detected_format: Mapped[SourceFormat | None] = mapped_column(_enum(SourceFormat, "source_format"))
    format_confidence: Mapped[float | None]
    status: Mapped[str] = mapped_column(String(16))
    records_ok: Mapped[int] = mapped_column(Integer, default=0)
    records_failed: Mapped[int] = mapped_column(Integer, default=0)
    records_duplicate: Mapped[int] = mapped_column(Integer, default=0)


class ImportErrorRow(Base):
    """Ошибка разбора конкретной строки/записи. Сообщение не содержит значения cookie."""

    __tablename__ = "import_errors"
    id: Mapped[int] = mapped_column(primary_key=True)
    source_file_id: Mapped[int] = mapped_column(ForeignKey("source_files.id", ondelete="CASCADE"), index=True)
    line: Mapped[int | None] = mapped_column(Integer)
    code: Mapped[str] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(Text)


# --------------------------------------------------------------------------- cookies
class CookieRow(Base):
    """Сохранённая cookie. Значение — только шифротекст (nonce||ciphertext||tag)."""

    __tablename__ = "cookies"
    __table_args__ = (
        Index("ix_cookies_project_domain", "project_id", "domain"),
        Index("ix_cookies_project_name", "project_id", "name"),
        Index("ix_cookies_project_expires", "project_id", "expires_at"),
        Index("ix_cookies_project_status", "project_id", "validation_status"),
        Index("ix_cookies_project_severity", "project_id", "max_severity"),
        Index("ix_cookies_project_identity", "project_id", "identity_hash"),
        Index("ix_cookies_project_value_hmac", "project_id", "value_hmac"),
        Index("ix_cookies_project_imported", "project_id", "imported_at", "id"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    batch_id: Mapped[int | None] = mapped_column(ForeignKey("import_batches.id", ondelete="SET NULL"), index=True)
    source_file_id: Mapped[int | None] = mapped_column(ForeignKey("source_files.id", ondelete="SET NULL"))
    source_line: Mapped[int | None] = mapped_column(Integer)
    source_format: Mapped[SourceFormat] = mapped_column(_enum(SourceFormat, "source_format"))

    name: Mapped[str] = mapped_column(Text)
    domain: Mapped[str] = mapped_column(Text)
    path: Mapped[str] = mapped_column(Text, default="/")
    host_only: Mapped[bool] = mapped_column(Boolean, default=False)
    partitioned: Mapped[bool] = mapped_column(Boolean, default=False)

    value_state: Mapped[ValueState] = mapped_column(_enum(ValueState, "value_state"))
    value_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    value_hmac: Mapped[bytes | None] = mapped_column(LargeBinary)
    value_length: Mapped[int | None] = mapped_column(Integer)

    expires_at: Mapped[int | None] = mapped_column(Integer)
    created_at_source: Mapped[int | None] = mapped_column(Integer)
    last_accessed_at: Mapped[int | None] = mapped_column(Integer)
    secure: Mapped[bool] = mapped_column(Boolean, default=False)
    http_only: Mapped[bool] = mapped_column(Boolean, default=False)
    same_site: Mapped[SameSite] = mapped_column(_enum(SameSite, "same_site"))

    identity_hash: Mapped[bytes] = mapped_column(LargeBinary)
    validation_status: Mapped[ValidationStatus | None] = mapped_column(_enum(ValidationStatus, "validation_status"))
    max_severity: Mapped[Severity | None] = mapped_column(_enum(Severity, "severity"))
    analyzed_at: Mapped[int | None] = mapped_column(Integer)
    is_test_session: Mapped[bool] = mapped_column(Boolean, default=False)
    imported_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)


class AnalysisRun(Base):
    """Запуск валидации или анализа безопасности (для истории и сравнения до/после)."""

    __tablename__ = "analysis_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    engine: Mapped[FindingEngine] = mapped_column(_enum(FindingEngine, "finding_engine"))
    ruleset_version: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[int] = mapped_column(Integer)
    finished_at: Mapped[int | None] = mapped_column(Integer)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class FindingRow(Base):
    """Находка правила по cookie в рамках запуска анализа."""

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_run_severity", "run_id", "severity"),
        Index("ix_findings_run_rule", "run_id", "rule_id"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("analysis_runs.id", ondelete="CASCADE"))
    cookie_id: Mapped[int] = mapped_column(ForeignKey("cookies.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(100))
    engine: Mapped[FindingEngine] = mapped_column(_enum(FindingEngine, "finding_engine"))
    status: Mapped[ValidationStatus | None] = mapped_column(_enum(ValidationStatus, "validation_status"))
    severity: Mapped[Severity | None] = mapped_column(_enum(Severity, "severity"))
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    risk: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")


# --------------------------------------------------------------------------- диагностика сессий
class DiagnosticEndpoint(Base):
    """Endpoint из allowlist проекта (ADR-0004). Запросы возможны только при verification_state
    'local' (localhost/приватная сеть/.test/.local) или 'verified' (подтверждён токен)."""

    __tablename__ = "diagnostic_endpoints"
    __table_args__ = (
        CheckConstraint("verification_state IN ('local','unverified','verified')", name="verification_state"),
        UniqueConstraint("project_id", "url"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(String(8), default="GET")
    verification_state: Mapped[str] = mapped_column(String(16))
    verification_token: Mapped[str | None] = mapped_column(String(128))
    verified_at: Mapped[int | None] = mapped_column(Integer)
    expected_markers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[int] = mapped_column(Integer)


class DiagnosticRun(Base):
    """Одна диагностическая проверка. ``outcome`` описывает совпадение с ожидаемыми маркерами,
    а не «валидность сессии» (правило 11 ТЗ)."""

    __tablename__ = "diagnostic_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("diagnostic_endpoints.id", ondelete="CASCADE"), index=True)
    cookie_id: Mapped[int | None] = mapped_column(ForeignKey("cookies.id", ondelete="SET NULL"))
    pair_id: Mapped[str | None] = mapped_column(String(36), index=True)
    phase: Mapped[str | None] = mapped_column(String(8))  # before / after
    started_at: Mapped[int] = mapped_column(Integer)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    status_code: Mapped[int | None] = mapped_column(Integer)
    outcome: Mapped[str] = mapped_column(String(32))
    matched_markers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    response_meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)


# --------------------------------------------------------------------------- фоновые задачи
class Job(Base):
    """Пакетная задача. Состояние персистентно — прерванная задача продолжается после перезапуска."""

    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint("status IN ('queued','running','paused','completed','cancelled','failed')", name="status"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), index=True)
    max_workers: Mapped[int] = mapped_column(Integer, default=1)
    progress_done: Mapped[int] = mapped_column(Integer, default=0)
    progress_total: Mapped[int] = mapped_column(Integer, default=0)
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[int] = mapped_column(Integer)
    started_at: Mapped[int | None] = mapped_column(Integer)
    finished_at: Mapped[int | None] = mapped_column(Integer)


class JobTask(Base):
    """Единица работы внутри задачи; ``checkpoint`` хранит позицию для resume."""

    __tablename__ = "job_tasks"
    __table_args__ = (Index("ix_job_tasks_job_status", "job_id", "status"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    checkpoint: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    log_path: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[int | None] = mapped_column(Integer)
    finished_at: Mapped[int | None] = mapped_column(Integer)


# --------------------------------------------------------------------------- история, фильтры, пресеты, плагины
class Operation(Base):
    """Журнал операций (Activity Timeline / Processing History). Без значений cookies."""

    __tablename__ = "operations"
    __table_args__ = (Index("ix_operations_project_ts", "project_id", "ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    ts: Mapped[int] = mapped_column(Integer, index=True)
    kind: Mapped[str] = mapped_column(String(48))
    outcome: Mapped[str] = mapped_column(String(16))
    summary: Mapped[str] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class SavedFilter(Base):
    __tablename__ = "saved_filters"
    __table_args__ = (UniqueConstraint("project_id", "name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(200))
    query: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[int] = mapped_column(Integer)


class Preset(Base):
    """Пресеты импорта/экспорта и профили конфигурации."""

    __tablename__ = "presets"
    __table_args__ = (
        UniqueConstraint("kind", "name"),
        CheckConstraint("kind IN ('import','export','config_profile','validation_rules')", name="kind"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(200))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)


class PluginRecord(Base):
    """Установленный плагин и выданные ему пользователем возможности."""

    __tablename__ = "plugins"
    plugin_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    version: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    trust_level: Mapped[str] = mapped_column(String(16), default="isolated")
    granted_capabilities: Mapped[list[Any]] = mapped_column(JSON, default=list)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    installed_at: Mapped[int] = mapped_column(Integer)
