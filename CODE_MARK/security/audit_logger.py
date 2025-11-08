import json, os, datetime
from pathlib import Path

LOG_DIR = Path("outputs/audit_logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

class AuditLogger:
    def _write(self, entry):
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        path = LOG_DIR / f"audit_{ts}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(entry, f, indent=2)
        return entry

    def log_scan_operation(self, **kwargs):
        entry = {"operation": "scan", "timestamp_utc": datetime.datetime.utcnow().isoformat()+"Z", **kwargs}
        return self._write(entry)

    def log_linking_operation(self, **kwargs):
        entry = {"operation": "linking", "timestamp_utc": datetime.datetime.utcnow().isoformat()+"Z", **kwargs}
        return self._write(entry)

    def log_erasure_operation(self, **kwargs):
        entry = {"operation": "erasure", "timestamp_utc": datetime.datetime.utcnow().isoformat()+"Z", **kwargs}
        return self._write(entry)

    def log_access_operation(self, **kwargs):
        entry = {"operation": "access", "timestamp_utc": datetime.datetime.utcnow().isoformat()+"Z", **kwargs}
        return self._write(entry)

    def get_recent_logs(self, limit=20):
        logs = sorted(LOG_DIR.glob("audit_*.json"), reverse=True)
        return [json.load(open(l)) for l in logs[:limit]]

    def get_logs_by_user(self, user):
        """Get all logs for a specific user"""
        all_logs = []
        for log_file in sorted(LOG_DIR.glob("audit_*.json"), reverse=True):
            try:
                log_data = json.load(open(log_file))
                # Check various user fields
                if (log_data.get("user") == user or 
                    log_data.get("requested_by") == user):
                    all_logs.append(log_data)
            except Exception as e:
                print(f"Error reading {log_file}: {e}")
        return all_logs

    def get_logs_by_entity(self, entity_id):
        """Get all logs related to a specific entity"""
        all_logs = []
        for log_file in sorted(LOG_DIR.glob("audit_*.json"), reverse=True):
            try:
                log_data = json.load(open(log_file))
                if log_data.get("entity_id") == entity_id:
                    all_logs.append(log_data)
            except Exception as e:
                print(f"Error reading {log_file}: {e}")
        return all_logs