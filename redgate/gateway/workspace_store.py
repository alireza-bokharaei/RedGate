"""Durable mission, asset, evidence and retest storage for Redstrike 2.1.

Graphs are projections of authoritative rows, not a second, drifting copy of
findings. All identities and deduplication keys are computed by the application.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import sqlite3
import uuid
from typing import Any

from gateway.db import Database, utc_now_iso

TERMINAL_STATES = frozenset({"cancelled", "completed", "failed", "budget_exhausted"})
ACTIVE_STATES = ("running", "pausing", "cancelling")


class WorkspaceConflict(ValueError):
    """A concurrent request or an invalid lifecycle transition was refused."""


class MissionBudgetExceeded(ValueError):
    """A finite action budget or absolute mission deadline was reached."""


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


class WorkspaceStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _asset(
        conn: sqlite3.Connection,
        engagement_id: str,
        kind: str,
        locator: str,
        host: str,
        parent_id: str | None = None,
    ) -> str:
        digest = hashlib.sha256(f"{engagement_id}\0{kind}\0{locator}".encode()).hexdigest()[:24]
        asset_id = f"ast-{digest}"
        now = utc_now_iso()
        conn.execute(
            """INSERT INTO workspace_assets
               (asset_id, engagement_id, kind, locator, host, parent_id, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(engagement_id, kind, locator) DO UPDATE SET last_seen=excluded.last_seen""",
            (asset_id, engagement_id, kind, locator, host, parent_id, now, now),
        )
        return asset_id

    @staticmethod
    def host_kind(host: str) -> str:
        try:
            ipaddress.ip_address(host)
            return "ip"
        except ValueError:
            return "domain"

    def create_mission(
        self,
        *,
        engagement_id: str,
        requested_by: str,
        name: str,
        goal: str,
        targets: list[str],
        skill: dict[str, Any],
        http: dict[str, Any],
        capture_evidence: bool,
        max_actions: int,
        max_seconds: int,
    ) -> dict[str, Any]:
        mission_id, now = new_id("msn"), utc_now_iso()
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO missions
                   (mission_id, engagement_id, requested_by, name, goal, skill_id, skill_snapshot_json,
                    http_json, capture_evidence, max_actions, max_seconds, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    mission_id,
                    engagement_id,
                    requested_by,
                    name,
                    goal,
                    skill["skill_id"],
                    canonical_json(skill),
                    canonical_json(http),
                    int(capture_evidence),
                    max_actions,
                    max_seconds,
                    now,
                    now,
                ),
            )
            for position, host in enumerate(targets):
                asset_id = self._asset(conn, engagement_id, self.host_kind(host), host, host)
                conn.execute(
                    """INSERT INTO mission_intents (intent_id, mission_id, asset_id, position, target)
                       VALUES (?, ?, ?, ?, ?)""",
                    (new_id("int"), mission_id, asset_id, position, host),
                )
        return self.get_mission(mission_id) or {}

    @staticmethod
    def _mission(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["skill_snapshot"] = json.loads(item.pop("skill_snapshot_json"))
        item["http"] = json.loads(item.pop("http_json"))
        item["capture_evidence"] = bool(item["capture_evidence"])
        return item

    def get_mission(self, mission_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM missions WHERE mission_id=?", (mission_id,)
            ).fetchone()
            if not row:
                return None
            intents = conn.execute(
                "SELECT * FROM mission_intents WHERE mission_id=? ORDER BY position", (mission_id,)
            ).fetchall()
        item = self._mission(row)
        item["intents"] = [dict(r) for r in intents]
        return item

    def list_missions(
        self, engagement_id: str, limit: int = 30, offset: int = 0
    ) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                """SELECT m.mission_id, m.engagement_id, m.requested_by, m.name, m.goal, m.skill_id,
                          m.status, m.max_actions, m.used_actions, m.max_seconds, m.deadline_at,
                          m.created_at, m.updated_at, m.error, COUNT(i.intent_id) AS total_intents,
                          SUM(CASE WHEN i.status='completed' THEN 1 ELSE 0 END) AS completed_intents
                   FROM missions m LEFT JOIN mission_intents i ON i.mission_id=m.mission_id
                   WHERE m.engagement_id=? GROUP BY m.mission_id
                   ORDER BY m.created_at DESC, m.mission_id LIMIT ? OFFSET ?""",
                (engagement_id, limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def start_mission(self, mission_id: str) -> dict[str, Any]:
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM missions WHERE mission_id=?", (mission_id,)
            ).fetchone()
            if not row or row["status"] not in {"draft", "paused"}:
                raise WorkspaceConflict("Only draft or paused missions can be started.")
            now = dt.datetime.now(dt.timezone.utc)
            if row["deadline_at"] and dt.datetime.fromisoformat(row["deadline_at"]) <= now:
                raise MissionBudgetExceeded(
                    "The mission deadline has expired; create a new mission."
                )
            active = conn.execute(
                "SELECT requested_by FROM missions WHERE status IN ('running','pausing','cancelling')"
            ).fetchall()
            if len(active) >= 2 or any(r["requested_by"] == row["requested_by"] for r in active):
                raise WorkspaceConflict(
                    "At most two missions globally and one per operator may run at once."
                )
            deadline = (
                row["deadline_at"] or (now + dt.timedelta(seconds=row["max_seconds"])).isoformat()
            )
            conn.execute(
                """UPDATE missions SET status='running', deadline_at=?, started_at=COALESCE(started_at,?),
                   updated_at=?, error='' WHERE mission_id=?""",
                (deadline, now.isoformat(), now.isoformat(), mission_id),
            )
        return self.get_mission(mission_id) or {}

    def control(self, mission_id: str, action: str) -> dict[str, Any]:
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT status FROM missions WHERE mission_id=?", (mission_id,)
            ).fetchone()
            if not row or row["status"] in TERMINAL_STATES:
                raise WorkspaceConflict(
                    "A terminal mission cannot be changed; create a new mission."
                )
            current = row["status"]
            if action == "pause":
                if current == "cancelling":
                    raise WorkspaceConflict("Cancellation is already in progress.")
                next_status = "pausing" if current in {"running", "pausing"} else "paused"
            elif action == "cancel":
                next_status = "cancelling" if current in ACTIVE_STATES else "cancelled"
                if next_status == "cancelled":
                    conn.execute(
                        "UPDATE mission_intents SET status='cancelled', finished_at=? "
                        "WHERE mission_id=? AND status='pending'",
                        (utc_now_iso(), mission_id),
                    )
            else:
                raise WorkspaceConflict("Unsupported mission action.")
            now = utc_now_iso()
            conn.execute(
                "UPDATE missions SET status=?, updated_at=?, finished_at=? WHERE mission_id=?",
                (next_status, now, now if next_status == "cancelled" else None, mission_id),
            )
        return self.get_mission(mission_id) or {}

    def finish(self, mission_id: str, status: str, error: str = "") -> None:
        if status not in TERMINAL_STATES | {"paused"}:
            raise ValueError("Invalid completion status.")
        now = utc_now_iso()
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE missions SET status=?, error=?, updated_at=?, finished_at=? WHERE mission_id=?",
                (status, error[:500], now, None if status == "paused" else now, mission_id),
            )
            if status == "cancelled":
                conn.execute(
                    "UPDATE mission_intents SET status='cancelled', finished_at=? "
                    "WHERE mission_id=? AND status IN ('pending','running')",
                    (now, mission_id),
                )

    def reserve_action(self, mission_id: str) -> None:
        """Reserve BEFORE I/O, under BEGIN IMMEDIATE; failures never refund attempts."""
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM missions WHERE mission_id=?", (mission_id,)
            ).fetchone()
            if not row or row["status"] not in {"running", "pausing"}:
                raise WorkspaceConflict("Mission is no longer executable.")
            if row["used_actions"] >= row["max_actions"]:
                raise MissionBudgetExceeded("Mission action budget exhausted.")
            if not row["deadline_at"] or dt.datetime.fromisoformat(
                row["deadline_at"]
            ) <= dt.datetime.now(dt.timezone.utc):
                raise MissionBudgetExceeded("Mission deadline exceeded.")
            conn.execute(
                "UPDATE missions SET used_actions=used_actions+1, updated_at=? WHERE mission_id=?",
                (utc_now_iso(), mission_id),
            )

    def start_intent(self, intent_id: str) -> None:
        with self.db.transaction() as conn:
            changed = conn.execute(
                "UPDATE mission_intents SET status='running', attempts=attempts+1, started_at=?, error='' "
                "WHERE intent_id=? AND status='pending'",
                (utc_now_iso(), intent_id),
            ).rowcount
            if changed != 1:
                raise WorkspaceConflict("This intent is already claimed.")

    def finish_intent(
        self, intent_id: str, status: str, *, run_id: str | None = None, error: str = ""
    ) -> None:
        if status not in {"completed", "failed", "pending", "cancelled"}:
            raise ValueError("Invalid intent status.")
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE mission_intents SET status=?, run_id=COALESCE(?,run_id), error=?, finished_at=? "
                "WHERE intent_id=? AND status='running'",
                (
                    status,
                    run_id,
                    error[:500],
                    None if status == "pending" else utc_now_iso(),
                    intent_id,
                ),
            )

    def checkpoint_run(self, intent_id: str, run_id: str) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE mission_intents SET run_id=? WHERE intent_id=? AND status='running'",
                (run_id, intent_id),
            )

    def recover_interrupted(self) -> list[dict[str, Any]]:
        """Restart is fail-closed: never resume target contact without an operator."""
        with self.db.transaction() as conn:
            rows = conn.execute(
                "SELECT mission_id, engagement_id, status FROM missions "
                "WHERE status IN ('running','pausing','cancelling')"
            ).fetchall()
            for row in rows:
                mission_id = row["mission_id"]
                state = "cancelled" if row["status"] == "cancelling" else "paused"
                conn.execute(
                    "UPDATE missions SET status=?, updated_at=?, error=? WHERE mission_id=?",
                    (
                        state,
                        utc_now_iso(),
                        "Gateway restarted; explicit resume required.",
                        mission_id,
                    ),
                )
                conn.execute(
                    """UPDATE mission_intents SET status=CASE
                         WHEN run_id IS NOT NULL THEN 'completed'
                         WHEN ?='cancelled' THEN 'cancelled' ELSE 'pending' END,
                       error='Interrupted by gateway restart; action reservations retained.'
                       WHERE mission_id=? AND status='running'""",
                    (state, mission_id),
                )
                if state == "cancelled":
                    conn.execute(
                        "UPDATE mission_intents SET status='cancelled' WHERE mission_id=? AND status='pending'",
                        (mission_id,),
                    )
        return [dict(r) for r in rows]

    def ingest_run(self, run: dict[str, Any]) -> None:
        """Called only after successful scope checks by the recon agent."""
        engagement_id, run_id = str(run["engagement_id"]), str(run["run_id"])
        with self.db.transaction() as conn:
            for entry in run.get("discovered_assets", []):
                if not entry.get("in_scope"):
                    continue
                host = str(entry["asset"])
                asset_id = self._asset(conn, engagement_id, self.host_kind(host), host, host)
                # Merely discovering a subdomain is not proof that it was tested.
                if host == run["root_target"] and any(
                    s.get("status") == "completed" for s in run.get("steps", [])
                ):
                    conn.execute(
                        "INSERT OR IGNORE INTO asset_runs VALUES (?,?)", (asset_id, run_id)
                    )
            root = str(run["root_target"])
            root_id = self._asset(conn, engagement_id, self.host_kind(root), root, root)
            host_part = f"[{root}]" if ":" in root else root
            for port in run.get("summary_stats", {}).get("open_ports", [])[:10]:
                service_id = self._asset(
                    conn, engagement_id, "service", f"tcp://{host_part}:{int(port)}", root, root_id
                )
                conn.execute("INSERT OR IGNORE INTO asset_runs VALUES (?,?)", (service_id, run_id))

    def list_assets(
        self, engagement_id: str, limit: int = 200, offset: int = 0
    ) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                """SELECT a.*,
                     (SELECT COUNT(*) FROM asset_runs r WHERE r.asset_id=a.asset_id) AS run_count,
                     (SELECT COUNT(*) FROM http_evidence e WHERE e.asset_id=a.asset_id) AS evidence_count
                   FROM workspace_assets a WHERE a.engagement_id=?
                   ORDER BY a.first_seen, a.asset_id LIMIT ? OFFSET ?""",
                (engagement_id, limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def coverage(self, engagement_id: str) -> dict[str, int]:
        with self.db.connection() as conn:
            row = conn.execute(
                """SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN
                   EXISTS(SELECT 1 FROM asset_runs r WHERE r.asset_id=a.asset_id) OR
                   EXISTS(SELECT 1 FROM http_evidence e WHERE e.asset_id=a.asset_id)
                   THEN 1 ELSE 0 END),0) AS tested
                   FROM workspace_assets a WHERE a.engagement_id=?""",
                (engagement_id,),
            ).fetchone()
        total, tested = int(row["total"]), int(row["tested"])
        return {"total": total, "tested": tested, "untested": total - tested}

    def save_evidence(
        self,
        *,
        engagement_id: str,
        captured_by: str,
        target: str,
        payload: dict[str, Any],
        mission_id: str | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        evidence_id, now = new_id("evd"), utc_now_iso()
        raw = canonical_json(payload)
        digest = hashlib.sha256(raw.encode()).hexdigest()
        with self.db.transaction() as conn:
            for table, key, value in (
                ("missions", "mission_id", mission_id),
                ("recon_runs", "run_id", run_id),
            ):
                if value is not None:
                    row = conn.execute(
                        f"SELECT engagement_id FROM {table} WHERE {key}=?", (value,)
                    ).fetchone()
                    if not row or row["engagement_id"] != engagement_id:
                        raise ValueError("Evidence reference belongs to another engagement.")
            parent = self._asset(conn, engagement_id, self.host_kind(target), target, target)
            asset_id = self._asset(conn, engagement_id, "endpoint", payload["url"], target, parent)
            conn.execute(
                """INSERT INTO http_evidence
                   (evidence_id, engagement_id, asset_id, mission_id, run_id, captured_by,
                    target, payload_json, sha256, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    evidence_id,
                    engagement_id,
                    asset_id,
                    mission_id,
                    run_id,
                    captured_by,
                    target,
                    raw,
                    digest,
                    now,
                ),
            )
        return self.get_evidence(evidence_id) or {}

    @staticmethod
    def _evidence(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        raw = item.pop("payload_json")
        item["payload"] = json.loads(raw)
        item["integrity_valid"] = hmac.compare_digest(
            hashlib.sha256(raw.encode()).hexdigest(), item["sha256"]
        )
        return item

    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM http_evidence WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
        return self._evidence(row) if row else None

    def list_evidence(
        self,
        engagement_id: str,
        *,
        mission_id: str | None = None,
        run_id: str | None = None,
        limit: int = 30,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        where, args = ["engagement_id=?"], [engagement_id]
        for column, value in (("mission_id", mission_id), ("run_id", run_id)):
            if value is not None:
                where.append(f"{column}=?")
                args.append(value)
        with self.db.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM http_evidence WHERE {' AND '.join(where)} ORDER BY created_at DESC, evidence_id LIMIT ? OFFSET ?",
                [*args, limit, offset],
            ).fetchall()
        return [self._evidence(r) for r in rows]

    def save_retest(
        self,
        *,
        finding_id: int,
        engagement_id: str,
        requested_by: str,
        evidence_id: str,
        outcome: str,
        note: str,
    ) -> dict[str, Any]:
        item = dict(
            retest_id=new_id("rts"),
            finding_id=finding_id,
            engagement_id=engagement_id,
            requested_by=requested_by,
            evidence_id=evidence_id,
            outcome=outcome,
            note=note,
            created_at=utc_now_iso(),
        )
        with self.db.transaction() as conn:
            rows = [
                conn.execute(
                    f"SELECT engagement_id FROM {table} WHERE {key}=?", (value,)
                ).fetchone()
                for table, key, value in (
                    ("recon_findings", "id", finding_id),
                    ("http_evidence", "evidence_id", evidence_id),
                )
            ]
            if any(r is None or r["engagement_id"] != engagement_id for r in rows):
                raise ValueError("Retest references must belong to the same engagement.")
            conn.execute(
                "INSERT INTO finding_retests VALUES (:retest_id,:finding_id,:engagement_id,:requested_by,:evidence_id,:outcome,:note,:created_at)",
                item,
            )
        return item

    def list_retests(self, finding_id: int) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM finding_retests WHERE finding_id=? ORDER BY created_at DESC LIMIT 100",
                (finding_id,),
            ).fetchall()
        return [dict(r) for r in rows]
