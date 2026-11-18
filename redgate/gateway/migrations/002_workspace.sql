-- RedGate 2.1.0: additive migration. Existing v2 runs, findings, policies and
-- audit entries are deliberately left untouched. Applied transactionally.

CREATE TABLE workspace_assets (
    asset_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    kind TEXT NOT NULL CHECK (kind IN ('domain', 'ip', 'service', 'endpoint')),
    locator TEXT NOT NULL,
    host TEXT NOT NULL,
    parent_id TEXT REFERENCES workspace_assets(asset_id),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (engagement_id, kind, locator)
);
CREATE INDEX idx_assets_engagement ON workspace_assets(engagement_id, last_seen DESC);

CREATE TABLE asset_runs (
    asset_id TEXT NOT NULL REFERENCES workspace_assets(asset_id),
    run_id TEXT NOT NULL REFERENCES recon_runs(run_id),
    PRIMARY KEY (asset_id, run_id)
);

CREATE TABLE missions (
    mission_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    requested_by TEXT NOT NULL,
    name TEXT NOT NULL,
    goal TEXT NOT NULL,
    skill_id TEXT NOT NULL,
    skill_snapshot_json TEXT NOT NULL,
    http_json TEXT NOT NULL,
    capture_evidence INTEGER NOT NULL DEFAULT 1 CHECK (capture_evidence IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN (
        'draft', 'running', 'pausing', 'paused', 'cancelling', 'cancelled',
        'completed', 'failed', 'budget_exhausted'
    )),
    max_actions INTEGER NOT NULL CHECK (max_actions BETWEEN 1 AND 64),
    used_actions INTEGER NOT NULL DEFAULT 0 CHECK (used_actions >= 0 AND used_actions <= max_actions),
    max_seconds INTEGER NOT NULL CHECK (max_seconds BETWEEN 10 AND 1800),
    deadline_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_missions_engagement ON missions(engagement_id, created_at DESC);
CREATE INDEX idx_missions_status ON missions(status);

CREATE TABLE mission_intents (
    intent_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL REFERENCES missions(mission_id),
    asset_id TEXT NOT NULL REFERENCES workspace_assets(asset_id),
    position INTEGER NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'running', 'completed', 'failed', 'cancelled'
    )),
    attempts INTEGER NOT NULL DEFAULT 0,
    run_id TEXT REFERENCES recon_runs(run_id),
    error TEXT NOT NULL DEFAULT '',
    started_at TEXT,
    finished_at TEXT,
    UNIQUE (mission_id, position)
);
CREATE INDEX idx_intents_mission ON mission_intents(mission_id, position);

CREATE TABLE http_evidence (
    evidence_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    asset_id TEXT NOT NULL REFERENCES workspace_assets(asset_id),
    mission_id TEXT REFERENCES missions(mission_id),
    run_id TEXT REFERENCES recon_runs(run_id),
    captured_by TEXT NOT NULL,
    target TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    created_at TEXT NOT NULL
);
CREATE INDEX idx_evidence_engagement ON http_evidence(engagement_id, created_at DESC);
CREATE INDEX idx_evidence_mission ON http_evidence(mission_id);
CREATE INDEX idx_evidence_run ON http_evidence(run_id);
CREATE TRIGGER evidence_no_update BEFORE UPDATE ON http_evidence
BEGIN SELECT RAISE(ABORT, 'HTTP evidence is immutable'); END;
CREATE TRIGGER evidence_no_delete BEFORE DELETE ON http_evidence
BEGIN SELECT RAISE(ABORT, 'HTTP evidence is immutable'); END;

CREATE TABLE finding_retests (
    retest_id TEXT PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES recon_findings(id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    requested_by TEXT NOT NULL,
    evidence_id TEXT NOT NULL REFERENCES http_evidence(evidence_id),
    outcome TEXT NOT NULL CHECK (outcome IN ('still_present', 'not_observed', 'inconclusive')),
    note TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_retests_finding ON finding_retests(finding_id, created_at DESC);
CREATE TRIGGER retest_no_update BEFORE UPDATE ON finding_retests
BEGIN SELECT RAISE(ABORT, 'Retest history is immutable'); END;
CREATE TRIGGER retest_no_delete BEFORE DELETE ON finding_retests
BEGIN SELECT RAISE(ABORT, 'Retest history is immutable'); END;
