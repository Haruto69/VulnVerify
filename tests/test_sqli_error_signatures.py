import pytest

from backend.verification.sqli_contract import SqliEvidenceStrength
from backend.verification.sqli_error_signatures import (
    DATABASE_ERROR_SIGNATURES,
    DatabaseFamily,
    find_database_error_matches,
)
from backend.verification.sqli_union_based import (
    MYSQL_COLUMN_COUNT_SIGNATURE,
)


def signature_ids(text: str) -> set[str]:
    return {
        match.signature_id
        for match in find_database_error_matches(text)
    }


# ---------------------------------------------------------------------
# Signature table shape
# ---------------------------------------------------------------------


def test_signature_ids_are_unique():
    ids = [
        signature.signature_id
        for signature in DATABASE_ERROR_SIGNATURES
    ]

    assert len(ids) == len(set(ids))


def test_all_authoritative_v1_signature_ids_are_present():
    ids = {
        signature.signature_id
        for signature in DATABASE_ERROR_SIGNATURES
    }

    assert {
        "MYSQL_SYNTAX_001",
        "MYSQL_SYNTAX_002",
        "MYSQL_DRIVER_001",
        "MYSQL_COLUMN_COUNT_ERROR",
        "POSTGRESQL_SYNTAX_001",
        "POSTGRESQL_DRIVER_001",
        "MSSQL_SYNTAX_001",
        "MSSQL_QUOTE_001",
        "MSSQL_DRIVER_001",
        "ORACLE_ERROR_001",
        "ORACLE_DRIVER_001",
        "SQLITE_ERROR_001",
        "SQLITE_SYNTAX_001",
    }.issubset(ids)


def test_every_signature_declares_a_known_database_family():
    for signature in DATABASE_ERROR_SIGNATURES:
        assert isinstance(signature.db_family, DatabaseFamily)


def test_signature_family_matches_its_id_prefix():
    prefixes = {
        "MYSQL": DatabaseFamily.MYSQL,
        "POSTGRESQL": DatabaseFamily.POSTGRESQL,
        "MSSQL": DatabaseFamily.MSSQL,
        "ORACLE": DatabaseFamily.ORACLE,
        "SQLITE": DatabaseFamily.SQLITE,
    }

    for signature in DATABASE_ERROR_SIGNATURES:
        prefix = signature.signature_id.split("_")[0]

        assert signature.db_family == prefixes[prefix]


def test_all_signatures_are_case_insensitive():
    for signature in DATABASE_ERROR_SIGNATURES:
        assert signature.pattern.startswith("(?i)")


# ---------------------------------------------------------------------
# Per-signature positive matches
# ---------------------------------------------------------------------


POSITIVE_CASES = [
    (
        "MYSQL_SYNTAX_001",
        DatabaseFamily.MYSQL,
        "You have an error in your SQL syntax near '1'' at line 1",
    ),
    (
        "MYSQL_SYNTAX_002",
        DatabaseFamily.MYSQL,
        "check the manual that corresponds to your MariaDB "
        "server version for the right syntax",
    ),
    (
        "MYSQL_DRIVER_001",
        DatabaseFamily.MYSQL,
        "Warning: mysqli_query(): unable to run query",
    ),
    (
        "MYSQL_COLUMN_COUNT_ERROR",
        DatabaseFamily.MYSQL,
        "The used SELECT statements have a different number of columns",
    ),
    (
        "POSTGRESQL_SYNTAX_001",
        DatabaseFamily.POSTGRESQL,
        'ERROR: syntax error at or near "1"',
    ),
    (
        "POSTGRESQL_DRIVER_001",
        DatabaseFamily.POSTGRESQL,
        "org.postgresql.util.PSQLException: ERROR: relation missing",
    ),
    (
        "MSSQL_SYNTAX_001",
        DatabaseFamily.MSSQL,
        "Incorrect syntax near ''.",
    ),
    (
        "MSSQL_QUOTE_001",
        DatabaseFamily.MSSQL,
        "Unclosed quotation mark after the character string ''.",
    ),
    (
        "MSSQL_DRIVER_001",
        DatabaseFamily.MSSQL,
        "System.Data.SqlClient.SqlException was unhandled",
    ),
    (
        "MSSQL_CONVERSION_001",
        DatabaseFamily.MSSQL,
        "Conversion failed when converting the varchar value 'a'",
    ),
    (
        "ORACLE_ERROR_001",
        DatabaseFamily.ORACLE,
        "ORA-01756: quoted string not properly terminated",
    ),
    (
        "ORACLE_DRIVER_001",
        DatabaseFamily.ORACLE,
        "Oracle error while executing the statement",
    ),
    (
        "SQLITE_ERROR_001",
        DatabaseFamily.SQLITE,
        "SQLiteException: unrecognized token",
    ),
    (
        "SQLITE_DRIVER_001",
        DatabaseFamily.SQLITE,
        "sqlite3_prepare failed for the supplied statement",
    ),
    (
        "SQLITE_SYNTAX_001",
        DatabaseFamily.SQLITE,
        'near "WHERE": syntax error',
    ),
]


@pytest.mark.parametrize(
    "signature_id,db_family,text",
    POSITIVE_CASES,
    ids=[case[0] for case in POSITIVE_CASES],
)
def test_signature_positive_match(signature_id, db_family, text):
    matches = [
        match
        for match in find_database_error_matches(text)
        if match.signature_id == signature_id
    ]

    assert matches, f"{signature_id} did not match its own sample"
    assert matches[0].db_family == db_family
    assert matches[0].matched_text
    assert matches[0].location == "response_body"


def test_every_declared_signature_has_a_positive_case():
    covered = {case[0] for case in POSITIVE_CASES}

    declared = {
        signature.signature_id
        for signature in DATABASE_ERROR_SIGNATURES
    }

    assert declared == covered


# ---------------------------------------------------------------------
# Negative matches
# ---------------------------------------------------------------------


NEGATIVE_BODIES = [
    "",
    "<html><body><h1>Welcome</h1></body></html>",
    "An unexpected application error occurred. Please try again later.",
    "<html><body><h1>500 Internal Server Error</h1></body></html>",
    "<html><body><h1>404 Not Found</h1></body></html>",
    "Welcome back, user 4821. Last login 2026-08-17T10:00:00Z",
    "Your search for 'select' returned 0 results.",
    "Validation failed: the id field must be an integer.",
    "Access denied. You do not have permission to view this page.",
]


@pytest.mark.parametrize("body", NEGATIVE_BODIES)
def test_non_database_text_produces_no_matches(body):
    assert find_database_error_matches(body) == ()


def test_none_body_produces_no_matches():
    assert find_database_error_matches(None) == ()


@pytest.mark.parametrize(
    "signature_id,db_family,text",
    POSITIVE_CASES,
    ids=[case[0] for case in POSITIVE_CASES],
)
def test_signature_does_not_match_a_plain_success_page(
    signature_id,
    db_family,
    text,
):
    assert signature_id not in signature_ids(
        "<html><body><h1>Welcome</h1>Order 42 confirmed.</body></html>"
    )


# ---------------------------------------------------------------------
# Matching mechanics
# ---------------------------------------------------------------------


def test_matching_is_case_insensitive():
    assert "MYSQL_SYNTAX_001" in signature_ids(
        "YOU HAVE AN ERROR IN YOUR SQL SYNTAX"
    )


def test_repeated_occurrences_are_all_reported():
    body = (
        "ORA-01756: first failure\n"
        "ORA-00933: second failure"
    )

    matches = [
        match
        for match in find_database_error_matches(body)
        if match.signature_id == "ORACLE_ERROR_001"
    ]

    assert len(matches) == 2
    assert {match.matched_text for match in matches} == {
        "ORA-01756",
        "ORA-00933",
    }


def test_match_location_can_be_overridden():
    matches = find_database_error_matches(
        "Incorrect syntax near ''.",
        location="response_header",
    )

    assert matches
    assert all(
        match.location == "response_header"
        for match in matches
    )


def test_matched_text_is_the_matching_span():
    matches = find_database_error_matches(
        "<p>Incorrect syntax near ';'</p>"
    )

    assert matches[0].matched_text == "Incorrect syntax near"


# ---------------------------------------------------------------------
# MYSQL_COLUMN_COUNT_ERROR is SUPPORTING evidence only
# ---------------------------------------------------------------------


COLUMN_COUNT_TEXT = (
    "The used SELECT statements have a different number of columns"
)


def test_column_count_error_maps_to_the_authoritative_signature():
    matches = find_database_error_matches(COLUMN_COUNT_TEXT)

    assert len(matches) == 1

    match = matches[0]

    assert match.signature_id == "MYSQL_COLUMN_COUNT_ERROR"
    assert match.db_family == DatabaseFamily.MYSQL
    assert match.db_family.value == "MYSQL"
    assert match.matched_text == COLUMN_COUNT_TEXT
    assert match.location == "response_body"


def test_column_count_error_strength_is_supporting():
    match = find_database_error_matches(COLUMN_COUNT_TEXT)[0]

    assert match.strength == SqliEvidenceStrength.SUPPORTING
    assert match.strength.value == "SUPPORTING"
    assert match.strength != SqliEvidenceStrength.STRONG


def test_every_database_error_match_defaults_to_supporting_strength():
    for _, _, text in POSITIVE_CASES:
        for match in find_database_error_matches(text):
            assert (
                match.strength
                == SqliEvidenceStrength.SUPPORTING
            )


def test_column_count_signature_constant_matches_the_signature_id():
    assert (
        MYSQL_COLUMN_COUNT_SIGNATURE
        == "MYSQL_COLUMN_COUNT_ERROR"
    )


def test_column_count_error_does_not_imply_a_union_marker():
    """
    The column-count error is DATABASE_ERROR evidence. It carries no
    UNION-specific output of its own, so nothing in the match names a
    UNION result.
    """

    match = find_database_error_matches(COLUMN_COUNT_TEXT)[0]

    assert "UNION" not in match.signature_id
    assert "union" not in match.matched_text.lower()


def test_column_count_error_is_not_a_syntax_signature():
    assert signature_ids(COLUMN_COUNT_TEXT) == {
        "MYSQL_COLUMN_COUNT_ERROR"
    }
