"""Deep end-to-end demonstration of ZeroDay v2.0 Architecture.

Demonstrates:
Discover -> Model -> Plan -> Test -> Observe -> Reason
-> Validate -> Correlate -> Score -> Detect -> Remediate
-> Retest -> Report
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from pathlib import Path

# Add project root to sys.path if needed
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from zeroday.agents.matrix import AGENT_MATRIX, get_agent_definition
from zeroday.attack_graph import (
    AttackEdgeType,
    AttackGraph,
    AttackNodeType,
    AttackPathAnalyzer,
)
from zeroday.defense import (
    DetectionEngine,
    DetectionGap,
    PurpleTeamEngine,
    SecurityControlValidator,
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
    SecurityKnowledgeGraph,
    ThreatModelingEngine,
    lookup_owasp,
)
from zeroday.orchestration import (
    AgentManager,
    CoordinationBus,
    CoverageManager,
    ScheduledTask,
    TaskManager,
    TaskScheduler,
)
from zeroday.policy import (
    ActionPolicyConfig,
    ActionPolicyEngine,
    ActionRiskLevel,
    ApprovalManager,
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
    JsonReportGenerator,
    TechnicalReportGenerator,
)
from zeroday.risk import (
    ContextAwareRiskEngine,
    CvssCalculator,
    ZeroDaySecurityScore,
)
from zeroday.storage import AuditLogRecord, Database, ScanRecord
from zeroday.tools.registry import ToolRegistry, redact_sensitive


def print_banner(title: str) -> None:
    sep = "=" * 76
    print(f"\n{sep}\n  {title}\n{sep}")


def print_step(step_num: int, name: str, details: str) -> None:
    print(f"\n[PHASE {step_num}] {name.upper()}")
    print(f"  --> {details}")


async def run_deep_demo() -> None:
    start_time = time.time()
    scan_id = "ZD-SCAN-2026-DEMO"
    target = "https://app.example.test"
    run_dir = ROOT / "zeroday_runs" / "v2_demo_deep_run"
    run_dir.mkdir(parents=True, exist_ok=True)

    print_banner("ZeroDay v2.0 — Deep Autonomous Security Validation Run")
    print(f"Scan ID   : {scan_id}")
    print(f"Target    : {target}")
    print(f"Directory : {run_dir}")

    # ------------------------------------------------------------------------
    # Phase 1: Policy Engine & Deterministic Scope Validation
    # ------------------------------------------------------------------------
    print_step(1, "Policy & Scope Enforcement", "Validating scope boundary and rate limits (Fail Closed)")
    scope_config = ScopeConfig(
        allowed_domains=["*.example.test", "app.example.test"],
        denied_domains=["admin.example.test", "internal.*"],
        allowed_ports=[80, 443, 8080],
        denied_ports=[22, 3306],
        max_requests_per_minute=300,
    )
    scope_engine = ScopeEngine(scope_config)

    # In-scope test
    dec_target = scope_engine.is_in_scope(target)
    print(f"  Target Scope Check   : '{target}' -> ALLOWED={dec_target.allowed} ({dec_target.reason})")

    # Out-of-scope test (Fail Closed)
    out_target = "https://unauthorized-victim.org"
    dec_out = scope_engine.is_in_scope(out_target)
    print(f"  Out-of-Scope Check   : '{out_target}' -> ALLOWED={dec_out.allowed} ({dec_out.reason})")

    # Action risk policy check
    policy_engine = ActionPolicyEngine()
    shell_action = policy_engine.evaluate_shell_command("sqlmap -u https://app.example.test/items?id=1")
    print(f"  Action Risk Analysis : 'sqlmap' -> Risk: {shell_action.risk_level.value} (Requires Approval: {shell_action.requires_approval})")

    # ------------------------------------------------------------------------
    # Phase 2: Event Stream & Coordination Bus
    # ------------------------------------------------------------------------
    print_step(2, "Coordination Bus", "Starting append-oriented event stream")
    bus = CoordinationBus()
    bus.subscribe("*", lambda e: print(f"    [EVENT] {e.event_type} | Agent: {e.agent_id}"))

    await bus.publish("scan.started", scan_id=scan_id, agent_id="root", payload={"target": target})

    # ------------------------------------------------------------------------
    # Phase 3: Attack Surface Discovery & Asset Graph
    # ------------------------------------------------------------------------
    print_step(3, "Attack Surface Modeling", "Mapping asset topology and exposure")
    asset_graph = AssetGraph()

    root_domain = Asset(
        asset_id="AST-001",
        type=AssetType.DOMAIN,
        hostname="example.test",
        criticality=AssetCriticality.HIGH,
        exposure=ExposureLevel.INTERNET_FACING,
    )
    web_app = Asset(
        asset_id="AST-002",
        type=AssetType.APPLICATION,
        hostname="app.example.test",
        port=443,
        service="NGINX + Node.js/Express",
        parent_id="AST-001",
        criticality=AssetCriticality.HIGH,
        exposure=ExposureLevel.INTERNET_FACING,
    )
    api_endpoint_users = Asset(
        asset_id="AST-003",
        type=AssetType.ENDPOINT,
        hostname="app.example.test",
        port=443,
        service="/api/v1/users/{id}",
        parent_id="AST-002",
        criticality=AssetCriticality.CRITICAL,
        exposure=ExposureLevel.INTERNET_FACING,
    )
    api_endpoint_search = Asset(
        asset_id="AST-004",
        type=AssetType.ENDPOINT,
        hostname="app.example.test",
        port=443,
        service="/api/v1/products/search",
        parent_id="AST-002",
        criticality=AssetCriticality.HIGH,
        exposure=ExposureLevel.INTERNET_FACING,
    )
    db_asset = Asset(
        asset_id="AST-005",
        type=AssetType.DATABASE,
        hostname="internal-postgres.internal",
        port=5432,
        service="PostgreSQL 16",
        parent_id="AST-002",
        criticality=AssetCriticality.CRITICAL,
        exposure=ExposureLevel.INTERNAL,
    )

    for a in [root_domain, web_app, api_endpoint_users, api_endpoint_search, db_asset]:
        asset_graph.add_asset(a)

    print(f"  Discovered Assets    : {len(asset_graph.list_assets())} nodes mapped across domain, endpoints, and backend DB")

    # ------------------------------------------------------------------------
    # Phase 4: Automated STRIDE Threat Modeling
    # ------------------------------------------------------------------------
    print_step(4, "STRIDE Threat Modeling", "Deriving threats, entry points, and trust boundaries")
    tm_engine = ThreatModelingEngine()
    threat_model = tm_engine.build_threat_model("app.example.test", asset_graph.list_assets())
    print(f"  Threat Model ID      : {threat_model.model_id}")
    print(f"  Threat Actors        : {len(threat_model.actors)} modeled (Unauthenticated External, Malicious Tenant)")
    print(f"  Entry Points         : {len(threat_model.entry_points)} entry points across trust boundaries")
    print(f"  Generated Threats    : {len(threat_model.threats)} STRIDE threats identified")

    # ------------------------------------------------------------------------
    # Phase 5: Multi-Agent Orchestration & Task Dispatch
    # ------------------------------------------------------------------------
    print_step(5, "Agent Graph Orchestration", "Root Agent scheduling specialized testing tasks")
    agent_mgr = AgentManager()
    scheduler = TaskScheduler()

    recon_agent = agent_mgr.spawn_agent("recon", "ReconSpecialist")
    web_agent = agent_mgr.spawn_agent("web", "WebApplicationSpecialist")
    api_agent = agent_mgr.spawn_agent("api", "ApiSecuritySpecialist")
    authz_agent = agent_mgr.spawn_agent("authorization", "AccessControlSpecialist")

    # Scheduled DAG
    t1 = ScheduledTask("T-01", "Subdomain & Port Recon", "recon", priority=1)
    t2 = ScheduledTask("T-02", "Web SQLi & Input Validation", "web", depends_on=["T-01"], priority=2)
    t3 = ScheduledTask("T-03", "BOLA / IDOR Access Control Audit", "authorization", depends_on=["T-01"], priority=2)
    scheduler.add_task(t1)
    scheduler.add_task(t2)
    scheduler.add_task(t3)

    ready_tasks = scheduler.get_ready_tasks()
    print(f"  Ready Tasks in DAG   : {[t.name for t in ready_tasks]}")
    scheduler.mark_completed("T-01")
    ready_after = scheduler.get_ready_tasks()
    print(f"  Unblocked Next Tasks : {[t.name for t in ready_after]}")

    # ------------------------------------------------------------------------
    # Phase 6: Tool Execution Contract & Secret Redaction
    # ------------------------------------------------------------------------
    print_step(6, "Tool Execution Contract", "Auditing tool run with secret redaction and SHA-256 hashes")
    tool_registry = ToolRegistry()
    raw_args = {"url": "https://app.example.test/api/v1/auth", "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token12345"}
    contract = tool_registry.record_execution(
        tool_id="shell",
        agent_id=web_agent.agent_id,
        scan_id=scan_id,
        raw_arguments=raw_args,
        start_time=time.time(),
        end_time=time.time() + 0.4,
        exit_code=0,
        stdout="HTTP/1.1 200 OK\n{\"status\":\"authenticated\"}",
        stderr="",
    )
    print(f"  Tool Executed        : tool={contract.tool_id}, exit_code={contract.exit_code}")
    print(f"  Sanitized Arguments  : {contract.sanitized_arguments}")
    print(f"  SHA-256 Stdout Hash  : {contract.stdout_hash[:16]}... (tamper-resistant)")

    # ------------------------------------------------------------------------
    # Phase 7: Finding Lifecycle & Tamper-Evident Evidence Vault
    # ------------------------------------------------------------------------
    print_step(7, "Findings Validation & Evidence Vault", "Proving vulnerabilities with cryptographically hashed proof")
    vault = EvidenceVault(run_dir)

    # Finding 1: Broken Access Control (BOLA / IDOR)
    finding_idor = Finding(
        finding_id="ZD-F-000001",
        title="Broken Object Level Authorization (BOLA/IDOR) on /api/v1/users/{id}",
        severity=FindingSeverity.HIGH,
        confidence=0.96,
        cvss=8.1,
        cwe=["CWE-639"],
        owasp=["A01:2021", "API1:2023"],
        attack=["T1068"],
        asset_id="AST-003",
        endpoint="/api/v1/users/{id}",
        method="GET",
        description="Tenant A is able to retrieve confidential billing data of Tenant B by changing the integer ID in the URL.",
        impact="Unauthorized horizontal disclosure of customer PII and financial records.",
        status=FindingStatus.POTENTIAL,
        poc=PoCSpec(
            request_content="GET /api/v1/users/42 HTTP/1.1\nHost: app.example.test\nAuthorization: Bearer tenant_a_token\n",
            steps=["Authenticate as Tenant A", "Request /api/v1/users/42 (Tenant B)", "Observe HTTP 200 with Tenant B data"],
        ),
    )

    # Finding 2: SQL Injection in search
    finding_sqli = Finding(
        finding_id="ZD-F-000002",
        title="SQL Injection in /api/v1/products/search",
        severity=FindingSeverity.CRITICAL,
        confidence=0.98,
        cvss=9.8,
        cwe=["CWE-89"],
        owasp=["A03:2021"],
        attack=["T1190"],
        asset_id="AST-004",
        endpoint="/api/v1/products/search",
        method="GET",
        description="The 'q' parameter is directly concatenated into a PostgreSQL query allowing arbitrary command execution.",
        impact="Full database exfiltration, database takeover, and backend host compromise.",
        status=FindingStatus.POTENTIAL,
        poc=PoCSpec(
            request_content="GET /api/v1/products/search?q=1'%20UNION%20SELECT%20username,password_hash%20FROM%20users-- HTTP/1.1\nHost: app.example.test\n",
            steps=["Submit single quote payload", "Observe SQL error syntax", "Extract table metadata via UNION payload"],
        ),
    )

    # Validate findings and store evidence
    validator = FindingValidator()
    findings = [finding_idor, finding_sqli]

    for f in findings:
        validator.verify_finding(f)
        hashes = vault.store_evidence(
            f.finding_id,
            scan_id=scan_id,
            agent_id=web_agent.agent_id,
            request_text=f.poc.request_content,
            response_text="HTTP/1.1 200 OK\n{\"id\":42,\"secret\":\"sensitive_data\"}",
            commands_text=f"curl -i '{target}{f.endpoint}'",
        )
        is_intact, _ = vault.verify_vault_integrity(f.finding_id)
        print(f"  Evidence Vault [{f.finding_id}]: Stored 5 artifacts | SHA-256 Verified={is_intact}")

    # Deduplicate
    deduper = FindingDeduplicator()
    deduped_findings = deduper.deduplicate(findings)

    # ------------------------------------------------------------------------
    # Phase 8: Context-Aware Risk Engine & Posture Score
    # ------------------------------------------------------------------------
    print_step(8, "Context-Aware Risk Engine", "Prioritizing findings by business context")
    for f in deduped_findings:
        f_asset = asset_graph.get_asset(f.asset_id)
        risk_res = ContextAwareRiskEngine.calculate_risk(f, f_asset)
        print(f"  Finding [{f.finding_id}]: CVSS={f.cvss} -> Business Risk Score: {risk_res.score} / 100 ({risk_res.tier})")

    score_report = ZeroDaySecurityScore.calculate_posture_score(deduped_findings, detection_coverage=75.0, previous_score=71)
    print(f"  ZeroDay Security Score : {score_report.current_score} / 100 (Change: {score_report.score_delta:+} pts)")

    # ------------------------------------------------------------------------
    # Phase 9: Attack Graph & Exploit Path Intelligence
    # ------------------------------------------------------------------------
    print_step(9, "Attack Graph Intelligence", "Modeling multi-stage breach paths to crown jewels")
    attack_graph = AttackGraph()

    attack_graph.add_node("entry", AttackNodeType.ASSET, "Public Internet", is_entry_point=True)
    attack_graph.add_node("api", AttackNodeType.SERVICE, "Public API (/api/v1/products/search)")
    attack_graph.add_node("sqli", AttackNodeType.VULNERABILITY, "SQL Injection (CWE-89)")
    attack_graph.add_node("db_creds", AttackNodeType.CREDENTIAL, "DB Superuser Credentials")
    attack_graph.add_node("crown_jewel", AttackNodeType.DATA, "Customer Financial Database", is_critical_asset=True)

    attack_graph.add_edge("entry", "api", AttackEdgeType.CONNECTS, weight=1.0)
    attack_graph.add_edge("api", "sqli", AttackEdgeType.AFFECTS, weight=1.0)
    attack_graph.add_edge("sqli", "db_creds", AttackEdgeType.ESCALATES, weight=1.0)
    attack_graph.add_edge("db_creds", "crown_jewel", AttackEdgeType.ACCESSES, weight=1.0)

    analyzer = AttackPathAnalyzer(attack_graph)
    paths = analyzer.find_paths_to_critical_assets()
    for p in paths:
        path_str = " -> ".join(p.labels)
        print(f"  Critical Exploit Path  : {path_str} (Confidence: {int(p.confidence * 100)}%)")

    # ------------------------------------------------------------------------
    # Phase 10: Defense & Purple Team Validation
    # ------------------------------------------------------------------------
    print_step(10, "Purple Team Validation & Detection Engineering", "Validating Blue Team detection rules")
    pt_engine = PurpleTeamEngine()
    pt_res = pt_engine.evaluate_attack(
        attack_id="ATK-001",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        attack_successful=True,
        telemetry_generated=True,
        telemetry_collected=True,
        detection_triggered=False,  # Detection gap!
    )
    print(f"  Purple Team Outcome  : {pt_res.outcome}")
    print(f"  Identified Gap       : {pt_res.gap_summary}")

    # Generate Sigma, YARA, Suricata rules for defenders
    sigma_rule = SigmaRuleGenerator.generate_web_rule(
        title="Detect SQLi on /api/v1/products/search",
        technique_id="T1190",
        path_pattern="/api/v1/products/search",
        method="GET",
    )
    suricata_rule = SuricataRuleGenerator.generate_http_rule(
        message="ZeroDay SQLi attempt against products API",
        uri_pattern="/api/v1/products/search?q=",
        technique_id="T1190",
    )
    yara_rule = YaraRuleGenerator.generate_rule(
        name="web_shell_detection",
        strings=["SELECT * FROM pg_catalog", "pg_read_file("],
    )
    print(f"  Generated Sigma Rule : {sigma_rule.rule_id} ({sigma_rule.name})")
    print(f"  Generated Suricata   : {suricata_rule.rule_id}")
    print(f"  Generated YARA Rule  : {yara_rule.rule_id}")

    # ------------------------------------------------------------------------
    # Phase 11: Remediation, Patching & CI/CD Regression Retesting
    # ------------------------------------------------------------------------
    print_step(11, "Remediation & Regression Retesting", "Proposing code diff and creating automated CI/CD tests")
    rec_sqli = RemediationAdvisor.generate_recommendation(finding_sqli)
    print(f"  Root Cause Analysis  : {rec_sqli.root_cause}")
    print(f"  Recommended Fix      : {rec_sqli.recommendation}")

    # Generate patch (unified diff)
    orig_code = "const results = await db.query(`SELECT * FROM products WHERE name LIKE '%${q}%'`);\n"
    fixed_code = "const results = await db.query('SELECT * FROM products WHERE name LIKE $1', [`%${q}%`]);\n"
    patch = PatchGenerator.create_diff("backend/services/products.js", orig_code, fixed_code, "Fix SQL injection using parameterized query")
    print("  Proposed Patch Diff  :")
    for line in patch.diff_text.splitlines():
        print(f"    {line}")

    # Create CI/CD regression test
    reg_engine = SecurityRegressionEngine()
    reg_test = reg_engine.create_regression_test(finding_sqli)
    print(f"  CI/CD Regression Test: Created spec '{reg_test.test_id}' for {reg_test.title}")

    # Verify fix
    retest_result = AutomatedRetestVerifier.evaluate_retest(
        finding_sqli,
        reg_test,
        actual_http_status=400,
        actual_response_body="Invalid search parameter",
    )
    print(f"  Retest Verification  : Finding status transitioned to {retest_result.status} (Verified secure response: HTTP {retest_result.observed_response_code})")

    # ------------------------------------------------------------------------
    # Phase 12: Persistent SQLite Storage & Formal Reports
    # ------------------------------------------------------------------------
    print_step(12, "Persistent Storage & Reporting", "Writing records to SQLite and generating reports")
    db_file = run_dir / "zeroday_v2.db"
    db = Database(db_file)

    db.insert_scan(
        ScanRecord(
            scan_id=scan_id,
            project_id="PROJ-001",
            target=target,
            status="completed",
            scan_mode="deep",
            safety_mode="controlled",
            completed_at=time.time(),
            summary={"score": score_report.current_score, "findings": len(deduped_findings)},
        )
    )
    db.insert_audit_log(
        AuditLogRecord(
            log_id="LOG-001",
            project_id="PROJ-001",
            scan_id=scan_id,
            agent_id="root",
            action="scan.completed",
            target=target,
            outcome="SUCCESS",
        )
    )

    # Write Technical Markdown Report
    tech_rep = TechnicalReportGenerator.generate_report(
        scan_id=scan_id,
        target=target,
        findings=deduped_findings,
        scope_summary=scope_config.__dict__,
        mitre_summary={"tested_techniques": 4, "total_techniques": 11, "coverage_percent": 36.4, "detection_gaps": 1},
        purple_team_summary=pt_engine.get_summary(),
    )
    (run_dir / "penetration_test_report.md").write_text(tech_rep, encoding="utf-8")

    # Write Executive Report
    exec_rep = ExecutiveReportGenerator.generate_report(
        project_name="E-Commerce Core Platform",
        target_name=target,
        findings=deduped_findings,
        posture_score=score_report,
        top_attack_paths=[p.to_dict() for p in paths],
    )
    (run_dir / "executive_report.md").write_text(exec_rep, encoding="utf-8")

    # Write Machine-Readable JSON Report
    json_rep = JsonReportGenerator.generate_json(
        scan_id=scan_id,
        target=target,
        findings=deduped_findings,
        metadata={"security_score": score_report.current_score},
    )
    (run_dir / "report.json").write_text(json_rep, encoding="utf-8")

    # Compliance Mapping
    comp_map = ComplianceMapper.map_findings(deduped_findings)
    (run_dir / "compliance_matrix.json").write_text(
        json.dumps({k: [c.to_dict() for c in v] for k, v in comp_map.items()}, indent=2),
        encoding="utf-8",
    )

    elapsed = time.time() - start_time
    print_banner(f"DEMO COMPLETED SUCCESSFULLY IN {elapsed:.2f} SECONDS")
    print(f"  Artifacts Generated in: {run_dir.resolve()}")
    print("  - penetration_test_report.md  (Full Technical Pentest Report)")
    print("  - executive_report.md         (Executive C-Level Posture Summary)")
    print("  - report.json                 (Machine-Readable Vulnerability Export)")
    print("  - compliance_matrix.json      (SOC 2, PCI DSS, ISO 27001, NIST CSF Mapping)")
    print("  - zeroday_v2.db               (SQLite Persistent Multi-Tenant Store)")
    print("  - evidence/ZD-F-000001/       (Tamper-Evident Evidence Vault with SHA-256 Digests)")
    print("  - evidence/ZD-F-000002/       (Tamper-Evident Evidence Vault with SHA-256 Digests)")


if __name__ == "__main__":
    asyncio.run(run_deep_demo())
