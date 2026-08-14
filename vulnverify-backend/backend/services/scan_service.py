from uuid import uuid4

from backend.storage.repository import scans


def create_scan(filename: str, content_type: str):
    scan_id = str(uuid4())

    scan = {
        "scan_id": scan_id,
        "filename": filename,
        "content_type": content_type,
        "status": "UPLOADED"
    }

    scans[scan_id] = scan

    return scan


def get_all_scans():
    return list(scans.values())


def get_scan(scan_id: str):
    return scans.get(scan_id)