import re
from dataclasses import dataclass
from enum import Enum

from backend.verification.sqli_contract import (
    SqliEvidenceStrength,
)


class DatabaseFamily(str, Enum):
    MYSQL = "MYSQL"
    POSTGRESQL = "POSTGRESQL"
    MSSQL = "MSSQL"
    ORACLE = "ORACLE"
    SQLITE = "SQLITE"


@dataclass(frozen=True)
class DatabaseErrorSignature:
    signature_id: str
    db_family: DatabaseFamily
    pattern: str


@dataclass(frozen=True)
class DatabaseErrorMatch:
    signature_id: str
    db_family: DatabaseFamily
    matched_text: str
    location: str
    strength: SqliEvidenceStrength = (
        SqliEvidenceStrength.SUPPORTING
    )


DATABASE_ERROR_SIGNATURES: tuple[DatabaseErrorSignature, ...] = (
    DatabaseErrorSignature(
        signature_id="MYSQL_SYNTAX_001",
        db_family=DatabaseFamily.MYSQL,
        pattern=(
            r"(?i)\bYou have an error in your SQL syntax\b"
        ),
    ),
    DatabaseErrorSignature(
        signature_id="MYSQL_SYNTAX_002",
        db_family=DatabaseFamily.MYSQL,
        pattern=(
            r"(?i)\bcheck the manual that corresponds to your "
            r"(?:MySQL|MariaDB) server version\b"
        ),
    ),
    DatabaseErrorSignature(
        signature_id="MYSQL_DRIVER_001",
        db_family=DatabaseFamily.MYSQL,
        pattern=(
            r"(?i)\b(?:mysql|mysqli|PDOException).*?"
            r"(?:syntax|query|statement|error)\b"
        ),
    ),
    DatabaseErrorSignature(
        signature_id="MYSQL_COLUMN_COUNT_ERROR",
        db_family=DatabaseFamily.MYSQL,
        pattern=(
            r"(?i)\bThe used SELECT statements have a different "
            r"number of columns\b"
        ),
    ),
    DatabaseErrorSignature(
        signature_id="POSTGRESQL_SYNTAX_001",
        db_family=DatabaseFamily.POSTGRESQL,
        pattern=(
            r"(?i)\bERROR:\s*(?:syntax error|invalid input syntax|"
            r"operator does not exist|unterminated .* string)\b"
        ),
    ),
    DatabaseErrorSignature(
        signature_id="POSTGRESQL_DRIVER_001",
        db_family=DatabaseFamily.POSTGRESQL,
        pattern=(
            r"(?i)\b(?:PostgreSQL|PSQLException|pg_query|pg_exec)\b"
            r".*\b(?:ERROR|error|syntax|query)\b"
        ),
    ),
    DatabaseErrorSignature(
        signature_id="MSSQL_QUOTE_001",
        db_family=DatabaseFamily.MSSQL,
        pattern=(
            r"(?i)\bUnclosed quotation mark after the character "
            r"string\b"
        ),
    ),
    DatabaseErrorSignature(
        signature_id="MSSQL_DRIVER_001",
        db_family=DatabaseFamily.MSSQL,
        pattern=(
            r"(?i)\b(?:Microsoft SQL Server|SqlException|"
            r"System\.Data\.SqlClient\.SqlException)\b"
        ),
    ),
    DatabaseErrorSignature(
        signature_id="MSSQL_SYNTAX_001",
        db_family=DatabaseFamily.MSSQL,
        pattern=r"(?i)\bIncorrect syntax near\b",
    ),
    DatabaseErrorSignature(
        signature_id="MSSQL_CONVERSION_001",
        db_family=DatabaseFamily.MSSQL,
        pattern=(
            r"(?i)\bConversion failed when converting\b"
        ),
    ),
    DatabaseErrorSignature(
        signature_id="ORACLE_ERROR_001",
        db_family=DatabaseFamily.ORACLE,
        pattern=r"(?i)\bORA-\d{5}\b",
    ),
    DatabaseErrorSignature(
        signature_id="ORACLE_DRIVER_001",
        db_family=DatabaseFamily.ORACLE,
        pattern=r"(?i)\bOracle(?:Exception| error)\b",
    ),
    DatabaseErrorSignature(
        signature_id="SQLITE_ERROR_001",
        db_family=DatabaseFamily.SQLITE,
        pattern=r"(?i)\bSQLite(?:Exception| error)\b",
    ),
    DatabaseErrorSignature(
        signature_id="SQLITE_DRIVER_001",
        db_family=DatabaseFamily.SQLITE,
        pattern=r"(?i)\bsqlite3_(?:exec|prepare|step)\b",
    ),
    DatabaseErrorSignature(
        signature_id="SQLITE_SYNTAX_001",
        db_family=DatabaseFamily.SQLITE,
        pattern=(
            r'''(?i)\bnear\s+["']?.+?["']?:\s*syntax error\b'''
        ),
    ),
)


def find_database_error_matches(
    text: str | None,
    *,
    location: str = "response_body",
) -> tuple[DatabaseErrorMatch, ...]:
    body = text or ""
    matches: list[DatabaseErrorMatch] = []

    for signature in DATABASE_ERROR_SIGNATURES:
        for match in re.finditer(
            signature.pattern,
            body,
        ):
            matches.append(
                DatabaseErrorMatch(
                    signature_id=signature.signature_id,
                    db_family=signature.db_family,
                    matched_text=match.group(0),
                    location=location,
                )
            )

    return tuple(matches)
