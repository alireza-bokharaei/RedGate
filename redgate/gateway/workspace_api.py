"""Authenticated workspace API; every reference is authorized before mutation/I/O."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Callable, Iterator

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse

from gateway.auth import OperatorPrincipal
from gateway.evidence import redact_text
from gateway.missions import MissionService
from gateway.sandbox_client import SandboxClientError
from gateway.workspace_models import (
    EvidenceCaptureRequest,
    HTTPSettings,
    MissionControlRequest,
    MissionCreateRequest,
    RetestRequest,
)
from gateway.workspace_store import MissionBudgetExceeded, WorkspaceConflict


def workspace_router(
    service: MissionService,
    get_principal: Callable[..., OperatorPrincipal],
    ensure_access: Callable[[OperatorPrincipal, str], None],
) -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["Mission workspace · 2.1"])
    store, db = service.store, service.db

    @contextmanager
    def operation(principal: OperatorPrincipal, engagement_id: str, name: str) -> Iterator[None]:
        try:
            yield
        except (
            PermissionError,
            MissionBudgetExceeded,
            WorkspaceConflict,
            ValueError,
            SandboxClientError,
        ) as exc:
            if isinstance(exc, PermissionError):
                code = 403
            elif isinstance(exc, (MissionBudgetExceeded, WorkspaceConflict)):
                code = 409
            elif isinstance(exc, SandboxClientError):
                code = 502
            else:
                code = 422
            detail = redact_text(str(exc))[:500]
            db.write_audit_log(
                engagement_id=engagement_id,
                operator_id=principal.operator_id,
                target="-",
                tool_or_script=f"workspace:{name}",
                status="error" if code == 502 else "rejected",
                rejection_reason=detail,
            )
            raise HTTPException(status_code=code, detail=detail) from exc

    def mission_for(
        mission_id: str, principal: OperatorPrincipal, *, mutate: bool = False
    ) -> dict[str, Any]:
        mission = store.get_mission(mission_id)
        if not mission:
            raise HTTPException(status_code=404, detail="Mission not found.")
        ensure_access(principal, mission["engagement_id"])
        if mutate and mission["requested_by"] != principal.operator_id and not principal.is_admin():
            db.write_audit_log(
                engagement_id=mission["engagement_id"],
                operator_id=principal.operator_id,
                target=mission_id,
                tool_or_script="workspace:mission_owner",
                status="rejected",
                rejection_reason="Only the owner or an assigned admin can control a mission.",
            )
            raise HTTPException(
                status_code=403,
                detail="Only the owner or an assigned admin can control this mission.",
            )
        return mission

    def finding_for(finding_id: int, principal: OperatorPrincipal) -> dict[str, Any]:
        finding = db.get_finding(finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found.")
        ensure_access(principal, finding["engagement_id"])
        return finding

    def evidence_for(evidence_id: str, principal: OperatorPrincipal) -> dict[str, Any]:
        evidence = store.get_evidence(evidence_id)
        if not evidence:
            raise HTTPException(status_code=404, detail="Evidence not found.")
        ensure_access(principal, evidence["engagement_id"])
        return evidence

    @router.get("/workspace")
    async def workspace_snapshot(
        engagement_id: str = Query(min_length=3, max_length=64),
        mission_id: str | None = Query(default=None, max_length=64),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        """One bounded read for the dashboard; polling never starts a scan."""
        ensure_access(principal, engagement_id)
        missions = store.list_missions(engagement_id, limit=30)
        selected = None
        if mission_id:
            selected = mission_for(mission_id, principal)
            if selected["engagement_id"] != engagement_id:
                raise HTTPException(
                    status_code=404, detail="Mission not found in the selected engagement."
                )
        elif missions:
            selected = store.get_mission(missions[0]["mission_id"])
        return {
            "missions": missions,
            "selected_mission": selected,
            "asset_graph": service.asset_graph(engagement_id),
            "exploration_graph": service.exploration_graph(selected)
            if selected
            else {"nodes": [], "edges": []},
            "evidence": store.list_evidence(
                engagement_id, mission_id=selected["mission_id"] if selected else None, limit=20
            ),
        }

    @router.post("/missions", status_code=201)
    async def create_mission(
        request: MissionCreateRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with operation(principal, request.engagement_id, "mission_create"):
            return {"mission": service.create(request, principal)}

    @router.get("/missions")
    async def list_missions(
        engagement_id: str = Query(min_length=3, max_length=64),
        limit: int = Query(default=30, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=10000),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return {
            "missions": store.list_missions(engagement_id, limit, offset),
            "limit": limit,
            "offset": offset,
        }

    @router.get("/missions/{mission_id}")
    async def get_mission(
        mission_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        return {"mission": mission_for(mission_id, principal)}

    @router.post("/missions/{mission_id}/control")
    async def control_mission(
        mission_id: str,
        request: MissionControlRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        mission = mission_for(mission_id, principal, mutate=True)
        with operation(principal, mission["engagement_id"], "mission_control"):
            if request.action in {"start", "resume"}:
                expected = "draft" if request.action == "start" else "paused"
                if mission["status"] != expected:
                    raise WorkspaceConflict(f"'{request.action}' requires a {expected} mission.")
                updated = await service.start(mission_id, principal)
            else:
                updated = store.control(mission_id, request.action)
                service.audit(updated, request.action, principal.operator_id)
            return {"mission": updated}

    @router.get("/missions/{mission_id}/graph")
    async def mission_graph(
        mission_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        mission = mission_for(mission_id, principal)
        return {
            "asset_graph": service.asset_graph(mission["engagement_id"]),
            "exploration_graph": service.exploration_graph(mission),
        }

    @router.get("/missions/{mission_id}/report.md")
    async def mission_report(
        mission_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> PlainTextResponse:
        mission = mission_for(mission_id, principal)
        service.audit(
            mission,
            "report_export",
            principal.operator_id,
            detail="Exported Markdown mission report.",
        )
        return PlainTextResponse(
            service.report(mission),
            media_type="text/markdown",
            headers={
                "Content-Disposition": f'attachment; filename="{mission_id}.md"',
                "Cache-Control": "no-store",
            },
        )

    @router.get("/missions/{mission_id}/export.json")
    async def mission_export(
        mission_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> JSONResponse:
        mission = mission_for(mission_id, principal)
        # Export an explicitly bounded, redacted package. No archive paths or
        # caller-controlled filesystem reads are involved.
        runs = [db.get_recon_run(i["run_id"]) for i in mission["intents"] if i["run_id"]]
        evidence = store.list_evidence(mission["engagement_id"], mission_id=mission_id, limit=101)
        retests = {
            str(f["id"]): store.list_retests(f["id"])
            for run in runs
            if run
            for f in run["findings"]
        }
        payload = {
            "format": "redgate-workspace/2.1",
            "mission": mission,
            "exploration_graph": service.exploration_graph(mission),
            "evidence": evidence[:100],
            "retests": retests,
            "runs": runs,
            "limits": {
                "evidence": 100,
                "evidence_truncated": len(evidence) > 100,
                "retests_per_finding": 100,
            },
        }
        service.audit(
            mission,
            "export",
            principal.operator_id,
            detail="Exported workspace; HTTP evidence is redacted.",
        )
        return JSONResponse(
            payload,
            headers={
                "Content-Disposition": f'attachment; filename="{mission_id}.json"',
                "Cache-Control": "no-store",
            },
        )

    @router.get("/assets")
    async def list_assets(
        engagement_id: str = Query(min_length=3, max_length=64),
        limit: int = Query(default=100, ge=1, le=200),
        offset: int = Query(default=0, ge=0, le=10000),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        assets = store.list_assets(engagement_id, limit, offset)
        for asset in assets:
            asset["in_scope"] = service.scope.evaluate_target(
                engagement_id, asset["host"], resolve_dns=False
            ).allowed
        return {
            "assets": assets,
            "coverage": store.coverage(engagement_id),
            "limit": limit,
            "offset": offset,
        }

    @router.get("/assets/graph")
    async def assets_graph(
        engagement_id: str = Query(min_length=3, max_length=64),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return service.asset_graph(engagement_id)

    @router.post("/evidence/capture", status_code=201)
    async def capture_evidence(
        request: EvidenceCaptureRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with operation(principal, request.engagement_id, "evidence_capture"):
            settings = HTTPSettings(**request.model_dump(exclude={"engagement_id", "target"}))
            return {
                "evidence": await service.evidence.capture(
                    principal=principal,
                    engagement_id=request.engagement_id,
                    target=request.target,
                    settings=settings,
                )
            }

    @router.get("/evidence")
    async def list_evidence(
        engagement_id: str = Query(min_length=3, max_length=64),
        mission_id: str | None = Query(default=None, max_length=64),
        limit: int = Query(default=30, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=10000),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return {
            "evidence": store.list_evidence(
                engagement_id, mission_id=mission_id, limit=limit, offset=offset
            ),
            "limit": limit,
            "offset": offset,
        }

    @router.get("/evidence/{evidence_id}")
    async def get_evidence(
        evidence_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        return {"evidence": evidence_for(evidence_id, principal)}

    @router.get("/evidence/{evidence_id}/export.json")
    async def export_evidence(
        evidence_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> JSONResponse:
        evidence = evidence_for(evidence_id, principal)
        db.write_audit_log(
            engagement_id=evidence["engagement_id"],
            operator_id=principal.operator_id,
            target=evidence["target"],
            tool_or_script="evidence:export",
            params={"evidence_id": evidence_id, "sha256": evidence["sha256"]},
            status="completed",
        )
        return JSONResponse(
            {"evidence": evidence},
            headers={
                "Content-Disposition": f'attachment; filename="{evidence_id}.json"',
                "Cache-Control": "no-store",
            },
        )

    @router.get("/recon/findings/{finding_id}/retests")
    async def get_retests(
        finding_id: int, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        finding_for(finding_id, principal)
        return {"retests": store.list_retests(finding_id)}

    @router.get("/recon/findings/{finding_id}/evidence")
    async def get_finding_evidence(
        finding_id: int, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        finding = finding_for(finding_id, principal)
        return {
            "evidence": store.list_evidence(
                finding["engagement_id"], run_id=finding["run_id"], limit=100
            )
        }

    @router.post("/recon/findings/{finding_id}/retest", status_code=201)
    async def retest_finding(
        finding_id: int,
        request: RetestRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        finding = finding_for(finding_id, principal)
        with operation(principal, finding["engagement_id"], "finding_retest"):
            return await service.evidence.retest(finding, principal, request.note)

    return router
