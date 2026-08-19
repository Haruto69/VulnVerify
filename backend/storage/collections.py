"""
SQLite-backed drop-in replacements for the plain dicts
backend/storage/repository.py used to export (scans,
normalized_findings, verified_findings, ground_truth).

Every class here implements collections.abc.MutableMapping, so all
existing call sites -- backend/services/scan_service.py,
backend/services/ground_truth_service.py, and the several dozen
existing tests that do things like
`scans[scan_id] = {...}`, `normalized_findings.get(scan_id, [])`,
`"finding_id" in verified_findings[scan_id]`, or `scans.clear()` --
keep working completely unchanged. Only __getitem__, __setitem__,
__delitem__, __iter__, and __len__ need to be implemented per class;
MutableMapping supplies get/pop/clear/update/keys/values/items/__eq__/
__contains__ on top of those five, with the exact same semantics a
plain dict already had.

Each key (a scan_id) maps to either one record (ScanStore) or a
*whole* per-scan collection (NormalizedFindingsStore/
VerifiedFindingsStore/GroundTruthStore hold a list or a
{finding_id: model} dict for that scan_id). Every write through these
classes therefore replaces that scan's entire collection in one
transaction (delete-then-insert) rather than mutating a live nested
object returned by a previous read -- the existing code never relies
on mutating such a nested object in place (see the persistent-storage
task's own audit of every `dict[key][key2] = value` pattern in the
codebase; the one place that did, ground_truth_service.py, was
adjusted to the same load-merge-write-back style used here).
"""

from collections.abc import MutableMapping

from backend.models.ground_truth import GroundTruthLabel
from backend.models.normalized_finding import NormalizedFinding
from backend.models.verified_finding import VerifiedFinding
from backend.storage.db import get_connection


class ScanStore(MutableMapping):
    """
    scan_id -> plain dict with the exact keys
    backend/services/scan_service.py has always used: scan_id,
    filename, content_type, scanner, status, error.
    """

    _COLUMNS = (
        "scan_id",
        "filename",
        "content_type",
        "scanner",
        "status",
        "error",
    )

    def __getitem__(self, scan_id: str) -> dict:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()

        if row is None:
            raise KeyError(scan_id)

        return {column: row[column] for column in self._COLUMNS}

    def __setitem__(self, scan_id: str, value: dict) -> None:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, filename, content_type, scanner,
                    status, error
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    filename=excluded.filename,
                    content_type=excluded.content_type,
                    scanner=excluded.scanner,
                    status=excluded.status,
                    error=excluded.error
                """,
                (
                    scan_id,
                    value.get("filename"),
                    value.get("content_type"),
                    value.get("scanner"),
                    value.get("status"),
                    value.get("error"),
                ),
            )

    def __delitem__(self, scan_id: str) -> None:
        with get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM scans WHERE scan_id = ?",
                (scan_id,),
            )
            if cursor.rowcount == 0:
                raise KeyError(scan_id)

    def __iter__(self):
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT scan_id FROM scans"
            ).fetchall()
        return iter([row["scan_id"] for row in rows])

    def __len__(self) -> int:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM scans"
            ).fetchone()
        return row["n"]

    def clear(self) -> None:
        with get_connection() as conn:
            conn.execute("DELETE FROM scans")


class NormalizedFindingsStore(MutableMapping):
    """
    scan_id -> list[NormalizedFinding], in the order they were saved.
    """

    def __getitem__(self, scan_id: str) -> list[NormalizedFinding]:
        with get_connection() as conn:
            rows = conn.execute(
                """
                SELECT data FROM normalized_findings
                WHERE scan_id = ?
                ORDER BY position ASC
                """,
                (scan_id,),
            ).fetchall()

        if not rows:
            raise KeyError(scan_id)

        return [
            NormalizedFinding.model_validate_json(row["data"])
            for row in rows
        ]

    def __setitem__(
        self,
        scan_id: str,
        value: list[NormalizedFinding],
    ) -> None:
        with get_connection() as conn:
            conn.execute(
                "DELETE FROM normalized_findings WHERE scan_id = ?",
                (scan_id,),
            )

            conn.executemany(
                """
                INSERT INTO normalized_findings (
                    finding_id, scan_id, category, position, data
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        finding.finding_id,
                        scan_id,
                        finding.vulnerability.category,
                        position,
                        finding.model_dump_json(),
                    )
                    for position, finding in enumerate(value)
                ],
            )

    def __delitem__(self, scan_id: str) -> None:
        with get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM normalized_findings WHERE scan_id = ?",
                (scan_id,),
            )
            if cursor.rowcount == 0:
                raise KeyError(scan_id)

    def __iter__(self):
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT scan_id FROM normalized_findings"
            ).fetchall()
        return iter([row["scan_id"] for row in rows])

    def __len__(self) -> int:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(DISTINCT scan_id) AS n "
                "FROM normalized_findings"
            ).fetchone()
        return row["n"]

    def clear(self) -> None:
        with get_connection() as conn:
            conn.execute("DELETE FROM normalized_findings")


class VerifiedFindingsStore(MutableMapping):
    """
    scan_id -> {finding_id: VerifiedFinding} for that scan.
    """

    def __getitem__(self, scan_id: str) -> dict[str, VerifiedFinding]:
        with get_connection() as conn:
            rows = conn.execute(
                """
                SELECT finding_id, data FROM verified_findings
                WHERE scan_id = ?
                """,
                (scan_id,),
            ).fetchall()

        if not rows:
            raise KeyError(scan_id)

        return {
            row["finding_id"]: VerifiedFinding.model_validate_json(
                row["data"]
            )
            for row in rows
        }

    def __setitem__(
        self,
        scan_id: str,
        value: dict[str, VerifiedFinding],
    ) -> None:
        with get_connection() as conn:
            conn.execute(
                "DELETE FROM verified_findings WHERE scan_id = ?",
                (scan_id,),
            )

            conn.executemany(
                """
                INSERT INTO verified_findings (
                    finding_id, scan_id, status, confidence, data
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        finding_id,
                        scan_id,
                        finding.classification.status,
                        finding.classification.confidence,
                        finding.model_dump_json(),
                    )
                    for finding_id, finding in value.items()
                ],
            )

    def __delitem__(self, scan_id: str) -> None:
        with get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM verified_findings WHERE scan_id = ?",
                (scan_id,),
            )
            if cursor.rowcount == 0:
                raise KeyError(scan_id)

    def __iter__(self):
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT scan_id FROM verified_findings"
            ).fetchall()
        return iter([row["scan_id"] for row in rows])

    def __len__(self) -> int:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(DISTINCT scan_id) AS n "
                "FROM verified_findings"
            ).fetchone()
        return row["n"]

    def clear(self) -> None:
        with get_connection() as conn:
            conn.execute("DELETE FROM verified_findings")


class GroundTruthStore(MutableMapping):
    """
    scan_id -> {finding_id: GroundTruthLabel} for that scan.
    """

    def __getitem__(self, scan_id: str) -> dict[str, GroundTruthLabel]:
        with get_connection() as conn:
            rows = conn.execute(
                """
                SELECT finding_id, data FROM ground_truth_labels
                WHERE scan_id = ?
                """,
                (scan_id,),
            ).fetchall()

        if not rows:
            raise KeyError(scan_id)

        return {
            row["finding_id"]: GroundTruthLabel.model_validate_json(
                row["data"]
            )
            for row in rows
        }

    def __setitem__(
        self,
        scan_id: str,
        value: dict[str, GroundTruthLabel],
    ) -> None:
        with get_connection() as conn:
            conn.execute(
                "DELETE FROM ground_truth_labels WHERE scan_id = ?",
                (scan_id,),
            )

            conn.executemany(
                """
                INSERT INTO ground_truth_labels (
                    scan_id, finding_id, expected_status, note, data
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        finding_id,
                        label.expected_status,
                        label.note,
                        label.model_dump_json(),
                    )
                    for finding_id, label in value.items()
                ],
            )

    def __delitem__(self, scan_id: str) -> None:
        with get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM ground_truth_labels WHERE scan_id = ?",
                (scan_id,),
            )
            if cursor.rowcount == 0:
                raise KeyError(scan_id)

    def __iter__(self):
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT scan_id FROM ground_truth_labels"
            ).fetchall()
        return iter([row["scan_id"] for row in rows])

    def __len__(self) -> int:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(DISTINCT scan_id) AS n "
                "FROM ground_truth_labels"
            ).fetchone()
        return row["n"]

    def clear(self) -> None:
        with get_connection() as conn:
            conn.execute("DELETE FROM ground_truth_labels")
