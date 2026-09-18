"""Tests for ZeroDay Upgrade Architecture v2.0 components."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from zeroday.agents.matrix import get_agent_definition
from zeroday.attack_graph import (
    AttackEdgeType,
    AttackGraph,
    AttackNodeType,
    AttackPathAnalyzer,
)
from zeroday.defense import (
    PurpleTeamEngine,
    SigmaRuleGenerator,
    SuricataRuleGenerator,
    YaraRuleGenerator,
)
from zeroday.findings import (
    EvidenceVault,
    Finding,
    FindingDeduplicator,
    FindingLifecycleManager,
    FindingSeverity,
    FindingStatus,
    FindingValidator,
    InvalidFindingTransitionError,
    PoCSpec,
    RemediationSpec,
)
from zeroday.intelligence import (
    Asset,
    AssetCriticality,
    AssetGraph,
    AssetType,
    CweDatabase,
    ExposureLevel,
    MitreCoverageMatrix,
    ThreatModelingEngine,
    lookup_owasp,
)
from zeroday.orchestration import (
    CoordinationBus,
    ScheduledTask,
    TaskScheduler,
)
from zeroday.policy import (
    ActionPolicyConfig,
    ActionPolicyEngine,
    ActionRiskLevel,
    ApprovalManager,
    ApprovalStatus,
    KillCondition,
    KillSwitch,
    PermissionValidator,
    ScopeConfig,
    ScopeEngine,
)
from zeroday.remediation import (
    AutomatedRetestVerifier,
    PatchGenerator,
    RemediationAdvisor,
    SecurityRegressionEngine,
)
from zeroday.reporting import (
    ComplianceMapper,
    ExecutiveReportGenerator,
    TechnicalReportGenerator,
)
from zeroday.risk import (
    ContextAwareRiskEngine,
    ZeroDaySecurityScore,
)
from zeroday.storage import AuditLogRecord, Database, ScanRecord
from zeroday.tools.registry import (
    ToolRegistry,
    redact_sensitive,
)


if TYPE_CHECKING:
    from pathlib import Path


# ============================================================================
# 1. Policy & Safety Tests
# ============================================================================


def test_scope_engine_domain_wildcard_and_fail_closed():
    config = ScopeConfig(
        allowed_domains=["*.example.com", "app.test"],
        denied_domains=["admin.example.com", "internal.*"],
    )
    engine = ScopeEngine(config)

    # Allowed subdomains
    assert engine.is_in_scope("api.example.com").allowed
    assert engine.is_in_scope("sub.dev.example.com").allowed
    assert engine.is_in_scope("app.test").allowed

    # Denied subdomains
    assert not engine.is_in_scope("admin.example.com").allowed
    assert not engine.is_in_scope("internal.corp").allowed

    # Out of scope
    assert not engine.is_in_scope("evil.com").allowed

    # Fail closed on empty/malformed
    assert not engine.is_in_scope("").allowed
    assert not engine.is_in_scope("   ").allowed


def test_scope_engine_cidr_and_ports():
    config = ScopeConfig(
        allowed_ips=["192.168.1.0/24", "10.0.0.1"],
        denied_ips=["192.168.1.50"],
        allowed_ports=[80, 443, 8080],
        denied_ports=[22, 3306],
    )
    engine = ScopeEngine(config)

    # IP within allowed CIDR
    assert engine.is_in_scope("192.168.1.10", port=80).allowed
    assert engine.is_in_scope("10.0.0.1", port=443).allowed

    # Explicit denied IP in CIDR
    assert not engine.is_in_scope("192.168.1.50", port=80).allowed

    # Denied port
    assert not engine.is_in_scope("192.168.1.10", port=22).allowed

    # Unallowed port
    assert not engine.is_in_scope("192.168.1.10", port=9000).allowed


def test_scope_engine_rate_limit():
    config = ScopeConfig(max_requests_per_minute=2)
    engine = ScopeEngine(config)

    assert engine.check_rate_limit().allowed
    assert engine.check_rate_limit().allowed
    assert not engine.check_rate_limit().allowed


def test_permission_validator():
    validator = PermissionValidator()

    # Recon agent allowed tools
    assert validator.check_tool_permission("recon", "shell").allowed
    assert validator.check_tool_permission("recon", "browser").allowed

    # Source agent not allowed outbound network
    assert not validator.check_network_permission("source").allowed

    # Web agent allowed network
    assert validator.check_network_permission("web").allowed

    # Fail closed for unknown agent
    assert not validator.check_tool_permission("unknown_agent", "shell").allowed


def test_action_policy_engine_risk():
    engine = ActionPolicyEngine(ActionPolicyConfig(auto_approve_high=False))

    # Dangerous command blocked
    decision_danger = engine.evaluate_shell_command("rm -rf /")
    assert not decision_danger.allowed
    assert decision_danger.risk_level == ActionRiskLevel.HIGH

    # Active tool is medium risk
    decision_med = engine.evaluate_shell_command("sqlmap -u http://example.com")
    assert decision_med.risk_level == ActionRiskLevel.MEDIUM

    # Safe read-only is low risk
    decision_low = engine.evaluate_shell_command("ls -la")
    assert decision_low.risk_level == ActionRiskLevel.LOW

    # HTTP DELETE is high risk requiring approval
    http_del = engine.evaluate_http_request("DELETE", "http://example.com/api/user/1")
    assert http_del.risk_level == ActionRiskLevel.HIGH
    assert http_del.requires_approval


@pytest.mark.asyncio
async def test_approval_manager():
    manager = ApprovalManager(default_timeout_s=5.0)
    req = manager.create_request(
        scan_id="scan-1",
        agent_id="web",
        action="delete_user",
        risk="HIGH",
        target="http://example.com/user/1",
        reason="Test deletion endpoint",
    )
    assert req.status == ApprovalStatus.PENDING

    # Approve request
    manager.approve(req.approval_id, resolved_by="admin")
    assert req.status == ApprovalStatus.APPROVED


def test_kill_switch():
    kill_switch = KillSwitch()
    assert not kill_switch.is_triggered

    events = []
    kill_switch.register_callback(events.append)

    evt = kill_switch.trigger(
        KillCondition.SCOPE_VIOLATION,
        reason="Target attempted out-of-scope egress to 8.8.8.8",
    )
    assert kill_switch.is_triggered
    assert len(events) == 1
    assert evt.condition == KillCondition.SCOPE_VIOLATION


# ============================================================================
# 2. Tool Registry & Sensitive Redaction Tests
# ============================================================================


def test_redact_sensitive():
    text = "Authorization: Bearer secret_token_123456789 and api_key='abcdef123456789'"
    redacted = redact_sensitive(text)
    assert "secret_token_123456789" not in redacted
    assert "REDACTED" in redacted


def test_tool_registry_contract():
    registry = ToolRegistry()
    contract = registry.record_execution(
        tool_id="shell",
        agent_id="recon",
        scan_id="scan-001",
        raw_arguments={"cmd": "whoami"},
        start_time=100.0,
        end_time=100.5,
        exit_code=0,
        stdout="root\n",
        stderr="",
    )
    assert contract.exit_code == 0
    assert len(contract.stdout_hash) == 64  # sha256
    assert len(registry.get_contracts("scan-001")) == 1


# ============================================================================
# 3. Intelligence Engine Tests
# ============================================================================


def test_attack_surface_and_threat_model():
    asset_graph = AssetGraph()
    domain = Asset(
        asset_id="asset-domain-1",
        type=AssetType.DOMAIN,
        hostname="example.com",
        criticality=AssetCriticality.HIGH,
        exposure=ExposureLevel.INTERNET_FACING,
    )
    endpoint = Asset(
        asset_id="asset-ep-1",
        type=AssetType.ENDPOINT,
        hostname="example.com",
        port=443,
        parent_id="asset-domain-1",
    )
    asset_graph.add_asset(domain)
    asset_graph.add_asset(endpoint)

    assert len(asset_graph.list_assets()) == 2
    assert len(asset_graph.get_children("asset-domain-1")) == 1

    # Generate STRIDE threat model
    tm_engine = ThreatModelingEngine()
    tm = tm_engine.build_threat_model("example.com", [domain, endpoint])
    assert len(tm.actors) >= 2
    assert len(tm.threats) >= 3


def test_mitre_and_owasp_and_cwe():
    # MITRE ATT&CK Matrix
    matrix = MitreCoverageMatrix()
    matrix.record_test("T1190")
    matrix.record_finding("T1190", evidence_count=2)
    summary = matrix.get_summary()
    assert summary["tested_techniques"] >= 1
    assert summary["total_findings"] >= 1

    # OWASP lookup
    owasp_a1 = lookup_owasp("A01:2021")
    assert owasp_a1 is not None
    assert owasp_a1.name == "Broken Access Control"

    # CWE database
    cwe89 = CweDatabase.get("CWE-89")
    assert cwe89 is not None
    assert cwe89.name == "SQL Injection"
    assert cwe89.typical_severity == "CRITICAL"


# ============================================================================
# 4. Findings & Evidence Vault Tests
# ============================================================================


def test_finding_lifecycle_and_validation():
    finding = Finding(
        finding_id="ZD-F-000001",
        title="SQL Injection in /api/items",
        severity=FindingSeverity.HIGH,
        confidence=0.95,
        cvss=8.5,
        cwe=["CWE-89"],
        owasp=["A03:2021"],
        endpoint="/api/items",
        method="GET",
        status=FindingStatus.POTENTIAL,
        poc=PoCSpec(
            request_content="GET /api/items?id=1' OR '1'='1 HTTP/1.1\nHost: example.com\n",
            steps=["Inject single quote payload", "Observe SQL error syntax"],
        ),
    )

    validator = FindingValidator()
    is_valid, _ = validator.validate_evidence(finding)
    assert is_valid

    # State transitions
    FindingLifecycleManager.transition(finding, FindingStatus.OBSERVED)
    assert finding.status == FindingStatus.OBSERVED

    FindingLifecycleManager.transition(finding, FindingStatus.UNDER_VALIDATION)
    assert finding.status == FindingStatus.UNDER_VALIDATION

    FindingLifecycleManager.transition(finding, FindingStatus.CONFIRMED)
    assert finding.status == FindingStatus.CONFIRMED

    # Invalid transition raises error
    with pytest.raises(InvalidFindingTransitionError):
        FindingLifecycleManager.transition(finding, FindingStatus.POTENTIAL)


def test_finding_deduplication():
    f1 = Finding(
        finding_id="ZD-F-001",
        title="SQL Injection in id parameter",
        severity=FindingSeverity.HIGH,
        confidence=0.8,
        cvss=8.0,
        cwe=["CWE-89"],
        endpoint="/api/search",
    )
    f2 = Finding(
        finding_id="ZD-F-002",
        title="SQL Injection in id parameter",
        severity=FindingSeverity.HIGH,
        confidence=0.95,  # Higher confidence
        cvss=8.5,
        cwe=["CWE-89"],
        endpoint="/api/search",
    )
    deduper = FindingDeduplicator()
    results = deduper.deduplicate([f1, f2])
    assert len(results) == 1
    assert results[0].finding_id == "ZD-F-002"


def test_evidence_vault_tamper_evident(tmp_path: Path):
    vault = EvidenceVault(tmp_path)
    hashes = vault.store_evidence(
        finding_id="ZD-F-000001",
        scan_id="scan-001",
        agent_id="web",
        request_text="GET /admin HTTP/1.1\nHost: example.com\n",
        response_text="HTTP/1.1 200 OK\nSecret Data\n",
        commands_text="curl -i http://example.com/admin",
    )
    assert "request.txt" in hashes
    assert "response.txt" in hashes
    assert "metadata.json" in hashes

    # Verify vault integrity
    is_valid, mismatches = vault.verify_vault_integrity("ZD-F-000001")
    assert is_valid
    assert len(mismatches) == 0

    # Tamper with file and verify detection
    req_file = tmp_path / "evidence" / "ZD-F-000001" / "request.txt"
    req_file.write_text("TAMPERED DATA", encoding="utf-8")
    is_valid_after, mismatches_after = vault.verify_vault_integrity("ZD-F-000001")
    assert not is_valid_after
    assert any("Hash mismatch" in m for m in mismatches_after)


# ============================================================================
# 5. Risk Engine & Security Score Tests
# ============================================================================


def test_context_aware_risk_and_security_score():
    finding = Finding(
        finding_id="ZD-F-001",
        title="IDOR in user profile",
        severity=FindingSeverity.HIGH,
        confidence=0.95,
        cvss=8.1,
        cwe=["CWE-639"],
        endpoint="/api/users/123",
        poc=PoCSpec(request_content="GET /api/users/123 HTTP/1.1\n"),
    )
    asset = Asset(
        asset_id="asset-1",
        type=AssetType.ENDPOINT,
        criticality=AssetCriticality.HIGH,
        exposure=ExposureLevel.INTERNET_FACING,
    )

    risk_result = ContextAwareRiskEngine.calculate_risk(finding, asset)
    assert risk_result.score > 70.0
    assert risk_result.tier in ("CRITICAL", "HIGH")

    # Overall security score
    score_report = ZeroDaySecurityScore.calculate_posture_score([finding], previous_score=80)
    assert score_report.current_score < 100
    assert score_report.score_delta != 0


# ============================================================================
# 6. Attack Graph & Path Analysis Tests
# ============================================================================


def test_attack_graph_path_finding():
    graph = AttackGraph()

    # Nodes
    graph.add_node("n0", AttackNodeType.ASSET, "Internet", is_entry_point=True)
    graph.add_node("n1", AttackNodeType.SERVICE, "Public Web API")
    graph.add_node("n2", AttackNodeType.VULNERABILITY, "Auth Bypass")
    graph.add_node("n3", AttackNodeType.USER, "User Account")
    graph.add_node("n4", AttackNodeType.VULNERABILITY, "IDOR Vulnerability")
    graph.add_node("n5", AttackNodeType.DATA, "Customer Database", is_critical_asset=True)

    # Edges
    graph.add_edge("n0", "n1", AttackEdgeType.CONNECTS, weight=1.0)
    graph.add_edge("n1", "n2", AttackEdgeType.AFFECTS, weight=1.0)
    graph.add_edge("n2", "n3", AttackEdgeType.AUTHENTICATES, weight=1.0)
    graph.add_edge("n3", "n4", AttackEdgeType.USES, weight=1.0)
    graph.add_edge("n4", "n5", AttackEdgeType.ACCESSES, weight=1.0)

    analyzer = AttackPathAnalyzer(graph)
    paths = analyzer.find_paths_to_critical_assets()
    assert len(paths) >= 1
    assert paths[0].nodes == ["n0", "n1", "n2", "n3", "n4", "n5"]
    assert paths[0].reaches_critical_asset

    # Mermaid diagram output
    mermaid = graph.to_mermaid()
    assert "graph TD" in mermaid
    assert "n0" in mermaid


# ============================================================================
# 7. Defense & Purple Teaming Tests
# ============================================================================


def test_purple_team_and_detection_rules():
    pt_engine = PurpleTeamEngine()
    result = pt_engine.evaluate_attack(
        attack_id="ATK-001",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        attack_successful=True,
        telemetry_generated=True,
        telemetry_collected=True,
        detection_triggered=False,  # Detection gap!
    )
    assert result.outcome == "ATTACK_SUCCESS_DETECTION_FAILED"
    assert "detection rule fired" in result.gap_summary

    # Generate Sigma rule for the gap
    sigma = SigmaRuleGenerator.generate_web_rule(
        title="Detect SQL Injection on /api/search",
        technique_id="T1190",
        path_pattern="/api/search",
        method="GET",
    )
    assert sigma.format == "sigma"
    assert "cs-uri-stem|contains: '/api/search'" in sigma.content

    # Generate YARA rule
    yara = YaraRuleGenerator.generate_rule(
        name="web_shell_detection",
        strings=["eval($_POST", "system($_GET"],
    )
    assert yara.format == "yara"
    assert "system($_GET" in yara.content

    # Generate Suricata rule
    suricata = SuricataRuleGenerator.generate_http_rule(
        message="SQLi probe in /api/search",
        uri_pattern="/api/search?id=",
        sid=9000001,
    )
    assert "sid:9000001" in suricata.content


# ============================================================================
# 8. Remediation & Regression Tests
# ============================================================================


def test_remediation_and_regression_engine():
    finding = Finding(
        finding_id="ZD-F-001",
        title="SQL Injection",
        severity=FindingSeverity.HIGH,
        confidence=0.9,
        cvss=8.5,
        cwe=["CWE-89"],
        endpoint="/api/items",
        method="GET",
        poc=PoCSpec(request_content="GET /api/items?id=1' OR '1'='1 HTTP/1.1\n"),
    )

    # 1. Recommendation
    rec = RemediationAdvisor.generate_recommendation(finding)
    assert "parameterized" in rec.recommendation.lower()

    # 2. Patch generation
    orig = "def get_item(id):\n    return db.execute(f'SELECT * FROM items WHERE id = {id}')\n"
    fixed = "def get_item(id):\n    return db.execute('SELECT * FROM items WHERE id = ?', (id,))\n"
    patch = PatchGenerator.create_diff("app/db.py", orig, fixed, "Fix SQL injection")
    assert "SELECT * FROM items WHERE id = ?" in patch.diff_text

    # 3. Security Regression test creation
    reg_engine = SecurityRegressionEngine()
    test_spec = reg_engine.create_regression_test(finding)
    assert test_spec.finding_id == "ZD-F-001"
    assert 400 in test_spec.expected_status or 403 in test_spec.expected_status

    # 4. Retest verification
    retest_success = AutomatedRetestVerifier.evaluate_retest(
        finding, test_spec, actual_http_status=400, actual_response_body="Bad Request"
    )
    assert retest_success.status == "RESOLVED"
    assert finding.status == FindingStatus.RESOLVED


# ============================================================================
# 9. Multi-Agent Matrix & Orchestration Tests
# ============================================================================


@pytest.mark.asyncio
async def test_orchestration_and_coordination_bus():
    bus = CoordinationBus()
    received_events = []

    bus.subscribe("finding.created", received_events.append)

    await bus.publish(
        "finding.created",
        scan_id="scan-123",
        agent_id="web",
        payload={"finding_id": "ZD-F-001"},
    )
    assert len(received_events) == 1
    assert received_events[0].payload["finding_id"] == "ZD-F-001"

    # Task scheduler
    scheduler = TaskScheduler()
    t1 = ScheduledTask(task_id="t1", name="Recon", agent_type="recon", priority=1)
    t2 = ScheduledTask(
        task_id="t2", name="Web Testing", agent_type="web", depends_on=["t1"], priority=2
    )
    scheduler.add_task(t1)
    scheduler.add_task(t2)

    ready = scheduler.get_ready_tasks()
    assert len(ready) == 1
    assert ready[0].task_id == "t1"

    # Complete t1 -> t2 should become ready
    scheduler.mark_completed("t1")
    ready_after = scheduler.get_ready_tasks()
    assert len(ready_after) == 1
    assert ready_after[0].task_id == "t2"


def test_agent_matrix_completeness():
    expected_roles = [
        "root",
        "recon",
        "web",
        "api",
        "source",
        "auth",
        "authorization",
        "business_logic",
        "cloud",
        "container",
        "k8s",
        "secrets",
        "supply_chain",
        "validation",
        "detection",
        "remediation",
    ]
    for role in expected_roles:
        defn = get_agent_definition(role)
        assert defn is not None
        assert defn.role == role
        assert len(defn.system_prompt_snippet) > 10


# ============================================================================
# 10. Database & Reporting Tests
# ============================================================================


def test_storage_database(tmp_path: Path):
    db_file = tmp_path / "zeroday.db"
    db = Database(db_file)

    scan = ScanRecord(
        scan_id="scan-999",
        project_id="proj-1",
        target="http://example.com",
        status="completed",
        scan_mode="deep",
        safety_mode="controlled",
    )
    db.insert_scan(scan)

    retrieved = db.get_scan("scan-999")
    assert retrieved is not None
    assert retrieved["scan_id"] == "scan-999"
    assert retrieved["target"] == "http://example.com"

    audit = AuditLogRecord(
        log_id="log-1",
        project_id="proj-1",
        scan_id="scan-999",
        agent_id="recon",
        action="nmap_scan",
        target="example.com",
        outcome="ALLOWED",
    )
    db.insert_audit_log(audit)
    logs = db.list_audit_logs("scan-999")
    assert len(logs) == 1
    assert logs[0]["action"] == "nmap_scan"


def test_reporting_generators():
    finding = Finding(
        finding_id="ZD-F-001",
        title="SQL Injection",
        severity=FindingSeverity.CRITICAL,
        confidence=0.98,
        cvss=9.8,
        cwe=["CWE-89"],
        owasp=["A03:2021"],
        endpoint="/api/login",
        method="POST",
        description="SQL injection in username field",
        impact="Complete database compromise",
        poc=PoCSpec(request_content="POST /api/login HTTP/1.1\nusername=admin'--"),
        remediation=RemediationSpec(recommendation="Use parameterized SQL queries"),
    )

    # Executive report
    posture = ZeroDaySecurityScore.calculate_posture_score([finding])
    exec_rep = ExecutiveReportGenerator.generate_report(
        "Project X", "https://example.com", [finding], posture
    )
    assert "ZeroDay Executive Security Posture Assessment" in exec_rep
    assert "ZD-F-001" in exec_rep

    # Technical Markdown report
    tech_rep = TechnicalReportGenerator.generate_report(
        scan_id="scan-123",
        target="https://example.com",
        findings=[finding],
    )
    assert "ZeroDay Penetration Test & Security Validation Report" in tech_rep
    assert "/api/login" in tech_rep

    # Compliance mapping
    comp_map = ComplianceMapper.map_findings([finding])
    assert "PCI_DSS" in comp_map
    assert any(c.control_id == "Req 6.5.1" for c in comp_map["PCI_DSS"])
