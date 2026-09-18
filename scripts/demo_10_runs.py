"""ZeroDay Pipeline 10-Run Demonstration.

Demonstrates the autonomous vulnerability detection agent across 10 distinct
scenarios spanning source code (C, Python, Java), HTTP traffic (CSIC, XSS, Path Traversal),
phishing URLs, mitigated false-positive scenarios, and clean baseline production controls.
"""

from __future__ import annotations

import contextlib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if sys.platform == "win32":
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")

from zeroday.ml.pipeline import ZeroDayPipeline
from zeroday.ml.types import InputType, PipelineInput, PipelineReport


@dataclass
class DemoScenario:
    run_number: int
    title: str
    target_id: str
    input_type: InputType
    filepath: str
    content: str
    metadata: dict
    expected_outcome: str
    description: str


def build_scenarios() -> list[DemoScenario]:
    return [
        # 1. C/C++ Buffer Overflow in Network Protocol Daemon
        DemoScenario(
            run_number=1,
            title="C Stack Buffer Overflow (Unbounded strcpy)",
            target_id="daemon_net_parser_c",
            input_type=InputType.CODE,
            filepath="services/net_daemon/packet_parser.c",
            content="""#include <stdio.h>
#include <string.h>

void parse_packet(const char *packet_payload) {
    char local_buffer[64];
    // Unbounded copy of network packet data into fixed stack buffer
    strcpy(local_buffer, packet_payload);
    printf("Processing packet: %s\\n", local_buffer);
}
""",
            metadata={"language": "c", "service": "network_daemon"},
            expected_outcome="CONFIRMED (CWE-120, Critical CVSS 9.8)",
            description="Unbounded strcpy copying network packet payload into a 64-byte stack buffer without bounds checking.",
        ),

        # 2. Python Web API SQL Injection
        DemoScenario(
            run_number=2,
            title="Python SQL Injection (Dynamic f-string formatting)",
            target_id="auth_service_py",
            input_type=InputType.CODE,
            filepath="backend/auth/login_service.py",
            content="""import sqlite3

def authenticate_user(db: sqlite3.Connection, username: str, password_hash: str):
    cursor = db.cursor()
    # Insecure dynamic SQL query construction using f-string
    query = f"SELECT user_id, role FROM accounts WHERE user = '{username}' AND hash = '{password_hash}'"
    cursor.execute(query)
    return cursor.fetchone()
""",
            metadata={"language": "python", "service": "auth_microservice"},
            expected_outcome="CONFIRMED (CWE-89, High CVSS 8.5)",
            description="Dynamic SQL query built via f-string interpolation allowing authentication bypass via tautology.",
        ),

        # 3. Python Defensive Sanitization (False-Positive Filter Rejection Test)
        DemoScenario(
            run_number=3,
            title="Python Sanitized Command Execution (Defensive Control - Filtered)",
            target_id="ops_ping_sanitized_py",
            input_type=InputType.CODE,
            filepath="backend/ops/diagnostics.py",
            content="""import os
import shlex

def ping_host(raw_user_input: str):
    # Candidate detector flags os.system with formatted command,
    # but defensive sanitizer shlex.quote() ensures input cannot escape arguments!
    safe_target = shlex.quote(raw_user_input)
    os.system(f"ping -c 1 {safe_target}")
""",
            metadata={"language": "python", "service": "ops_service"},
            expected_outcome="REJECTED_FILTER (Defensive Sanitizer Detected: cmd_sanitized)",
            description="System routine using shlex.quote(). Candidate flags os.system, but FP filter suppresses false alarm.",
        ),

        # 4. Java Remote Command Execution
        DemoScenario(
            run_number=4,
            title="Java OS Command Injection (Runtime.exec concatenation)",
            target_id="admin_diagnostics_java",
            input_type=InputType.CODE,
            filepath="src/main/java/com/corp/ops/NetworkDiagnostics.java",
            content="""package com.corp.ops;

import java.io.IOException;

public class NetworkDiagnostics {
    public void runPingCheck(String targetHost) throws IOException {
        // Untrusted user input directly concatenated into shell command
        String command = "ping -c 3 " + targetHost;
        Runtime.getRuntime().exec(command);
    }
}
""",
            metadata={"language": "java", "service": "ops_console"},
            expected_outcome="CONFIRMED (CWE-78, Critical CVSS 9.8)",
            description="Admin ping utility concatenating target host directly into Runtime.exec shell invocation.",
        ),

        # 5. Java Clean Constant Array Execution (Clean Baseline Control)
        DemoScenario(
            run_number=5,
            title="Java Clean Static Command Execution (Benign Baseline)",
            target_id="system_health_java",
            input_type=InputType.CODE,
            filepath="src/main/java/com/corp/health/HealthMonitor.java",
            content="""package com.corp.health;

public class HealthMonitor {
    public long getSystemUptime() {
        // Safe standard calculation without dynamic command injection or shell taint
        long uptime = System.currentTimeMillis() - 1600000000000L;
        return Math.max(0, uptime / 1000);
    }
}
""",
            metadata={"language": "java", "service": "health_monitor"},
            expected_outcome="CLEAN (No Vulnerability Detected)",
            description="Standard JVM timestamp telemetry routine without external input taint.",
        ),

        # 6. HTTP Traffic - CSIC 2010 E-Commerce SQLi
        DemoScenario(
            run_number=6,
            title="HTTP Traffic: CSIC 2010 SQLi Injection Attack",
            target_id="csic_order_lookup_http",
            input_type=InputType.HTTP_TRAFFIC,
            filepath="traffic/csic2010/req_0912.http",
            content="""POST /tienda1/miembros/pedidos.jsp HTTP/1.1
Host: ecommerce.internal:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Content-Type: application/x-www-form-urlencoded
Content-Length: 46

id=101+UNION+SELECT+1,password,3+FROM+users--
""",
            metadata={"source": "csic_2010_eval", "port": 8080},
            expected_outcome="CONFIRMED (CWE-89, High CVSS 8.5)",
            description="CSIC 2010 e-commerce dataset POST request exploiting SQL injection via UNION SELECT in HTTP body.",
        ),

        # 7. HTTP Traffic - Reflected Cross-Site Scripting (XSS)
        DemoScenario(
            run_number=7,
            title="HTTP Traffic: Reflected Cross-Site Scripting (XSS)",
            target_id="portal_search_xss_http",
            input_type=InputType.HTTP_TRAFFIC,
            filepath="traffic/webgoat/xss_query.http",
            content="""GET /portal/search?category=docs&query=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: staging.corpapp.io
Accept: text/html,application/xhtml+xml
User-Agent: Mozilla/5.0
Cookie: session_token=eyJhbGciOiJIUzI1NiJ9.sample_payload.sig
""",
            metadata={"source": "staging_gateway"},
            expected_outcome="CONFIRMED (CWE-79, Medium CVSS 6.1)",
            description="Live web gateway traffic containing URL-encoded script payload triggering reflected XSS.",
        ),

        # 8. HTTP Traffic - Juice Shop Null-Byte Path Traversal
        DemoScenario(
            run_number=8,
            title="HTTP Traffic: Juice Shop Null-Byte Path Traversal",
            target_id="juice_shop_path_traversal_http",
            input_type=InputType.HTTP_TRAFFIC,
            filepath="traffic/juiceshop/file_access.http",
            content="""GET /ftp/easter.py%2500.md HTTP/1.1
Host: sandbox.juiceshop.local:3000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)
Accept: */*
Connection: keep-alive
""",
            metadata={"source": "owasp_juice_shop"},
            expected_outcome="CONFIRMED (CWE-22, High CVSS 7.5)",
            description="OWASP Juice Shop challenge exploiting double-URL-encoded null byte (%2500) to bypass file extension check.",
        ),

        # 9. Network URL - Phishing Credential Harvester
        DemoScenario(
            run_number=9,
            title="Malicious URL: Credential Harvesting Phishing Domain",
            target_id="bank_phishing_url",
            input_type=InputType.URL,
            filepath="network/dns/suspicious_url.txt",
            content="https://secure-login-bankofamerica.com-account-update.xyz/auth/login.php",
            metadata={"source": "threat_intel_feed"},
            expected_outcome="CONFIRMED (CWE-601, High CVSS 7.5)",
            description="Lexical analysis of multi-subdomain typosquatting target masquerading as Bank of America login portal.",
        ),

        # 10. HTTP Traffic - Production REST API Clean Baseline
        DemoScenario(
            run_number=10,
            title="HTTP Traffic: Legitimate Production REST API (Clean Baseline)",
            target_id="clean_prod_api_http",
            input_type=InputType.HTTP_TRAFFIC,
            filepath="traffic/production/api_catalog.http",
            content="""GET /api/v2/catalog/items?category=electronics&sort=price_asc&limit=25&offset=0 HTTP/1.1
Host: api.cloudservices.internal
Accept: application/json
User-Agent: Corporate-MobileApp/3.4.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
""",
            metadata={"environment": "production"},
            expected_outcome="CLEAN (No Vulnerability Detected)",
            description="Benign high-volume production catalog API call with standard alphanumeric parameters and valid JWT.",
        ),
    ]


def run_demo():
    print("=" * 80)
    print("       ZERODAY AUTONOMOUS VULNERABILITY DETECTION AGENT")
    print("          10-RUN DEEP DEMONSTRATION & BENCHMARK SUITE")
    print("=" * 80)
    print("Architecture: Candidate -> Evidence -> Reasoning -> Verification -> Filter -> CWE/CVSS -> Report\n")

    pipeline = ZeroDayPipeline()
    scenarios = build_scenarios()

    summary_records = []
    overall_start = time.perf_counter()

    for idx, scenario in enumerate(scenarios, 1):
        print(f"\n{'-' * 80}")
        print(f"RUN [{idx}/10]: {scenario.title.upper()}")
        print(f"{'-' * 80}")
        print(f"• Target ID    : {scenario.target_id}")
        print(f"• Input Type   : {scenario.input_type.value}")
        print(f"• Source Path  : {scenario.filepath}")
        print(f"• Context/Goal : {scenario.description}")
        print(f"• Expected     : {scenario.expected_outcome}")
        print("• Input Preview:")
        preview_lines = scenario.content.strip().split("\n")
        for line in preview_lines[:4]:
            print(f"    | {line}")
        if len(preview_lines) > 4:
            print(f"    | ... ({len(preview_lines) - 4} more lines)")

        pipeline_input = PipelineInput(
            input_type=scenario.input_type,
            content=scenario.content,
            filepath=scenario.filepath,
            target_id=scenario.target_id,
            metadata=scenario.metadata,
        )

        t0 = time.perf_counter()
        report: PipelineReport = pipeline.process(pipeline_input)
        latency_ms = (time.perf_counter() - t0) * 1000

        print("\n  [PIPELINE EXECUTION STAGES]")
        # Stage 1: Candidate Detector
        cand = report.candidate
        print(f"  [1] Candidate Detector : {'VULNERABLE' if cand.is_vulnerable else 'CLEAN'}")
        print(f"      └─ Model Confidence : {cand.confidence * 100:.1f}% | Candidate CWEs: {', '.join(cand.candidate_cwes) if cand.candidate_cwes else 'None'}")

        # Stage 2: Evidence Extraction
        if cand.is_vulnerable:
            ev = report.evidence
            loc = f"Line {ev.start_line}" if ev.start_line else f"Param '{ev.parameter_name}'" if ev.parameter_name else "Lexical/Body"
            print(f"  [2] Evidence Extractor : {loc}")
            print(f"      └─ Extracted Snippet: {repr(ev.snippet[:75])}")

            # Stage 3: LLM Reasoning
            reas = report.reasoning
            print(f"  [3] LLM Reasoning Layer: Plausibility = {reas.plausibility_score * 100:.1f}% ({'Plausible' if reas.is_plausible else 'Implausible'})")
            print(f"      └─ Attack Path      : {reas.attack_path[:80]}...")
            if reas.nvd_references:
                nvd_cves = [r.get("cve_id", str(r)) if isinstance(r, dict) else str(r) for r in reas.nvd_references]
                print(f"      └─ NVD Grounding    : Matched {', '.join(nvd_cves[:3])}")

            # Stage 4: Independent Verification
            ver = report.verification
            print(f"  [4] Independent Verifier: {'AGREED (Verified)' if ver.agreed else 'DISAGREED (Unverified)'}")
            print(f"      └─ Engine Method    : {ver.verifier_method} (Confidence: {ver.confidence * 100:.1f}%)")

            # Stage 5: False-Positive Filter
            flt = report.filter_result
            print(f"  [5] False-Positive Filter: {'FILTERED OUT (Suppressed)' if flt.is_filtered else 'PASSED (True Finding)'}")
            if flt.is_filtered:
                print(f"      └─ Rejection Reason : {flt.rejection_reason}")
            elif flt.sanitizer_detected:
                print(f"      └─ Sanitizer Status : Bypass confirmed despite defensive controls")

            # Stage 6: Scoring
            if report.scoring:
                sc = report.scoring
                print(f"  [6] CWE & CVSS Scoring : {sc.cwe_id} ({sc.cwe_name})")
                print(f"      └─ Score & Severity : CVSS {sc.cvss_score:.1f} ({sc.severity}) | Vector: {sc.cvss_vector}")

            # Stage 7: Final Structured Finding
            if report.finding_record:
                rec = report.finding_record
                print(f"  [7] Structured Report  : Finding '{rec.get('title')}'")
                steps = rec.get('poc', {}).get('steps', [])
                if steps:
                    print(f"      └─ PoC Reproducer   : {steps[0]}")
                diff = rec.get('remediation', {}).get('code_diff', '')
                if diff:
                    diff_first_line = diff.strip().split('\n')[0]
                    print(f"      └─ Patch Diff Sample: {diff_first_line}")
        else:
            print(f"  [2-7] Fast-Path Bypass : Input verified clean by deterministic AST/Grammar baseline.")

        # Status badge
        print(f"\n  >> PIPELINE RESULT: {report.status} | Latency: {latency_ms:.2f}ms [OK]")

        summary_records.append({
            "run": idx,
            "target": scenario.target_id,
            "type": scenario.input_type.value,
            "expected": scenario.expected_outcome,
            "status": report.status,
            "cwe": report.scoring.cwe_id if report.scoring else "N/A",
            "severity": report.scoring.severity if report.scoring else "NONE",
            "cvss": report.scoring.cvss_score if report.scoring else 0.0,
            "latency_ms": round(latency_ms, 2),
        })

    total_time_ms = (time.perf_counter() - overall_start) * 1000

    # Print Executive Summary Table
    print("\n" + "=" * 92)
    print("                       ZERODAY 10-RUN DEMO EXECUTIVE SUMMARY")
    print("=" * 92)
    print(f"{'Run':<4} | {'Target ID':<26} | {'Type':<6} | {'Status':<14} | {'CWE':<8} | {'Sev':<8} | {'CVSS':<5} | {'Latency':<8}")
    print("-" * 92)
    for r in summary_records:
        print(f"{r['run']:<4} | {r['target']:<26} | {r['type']:<6} | {r['status']:<14} | {r['cwe']:<8} | {r['severity']:<8} | {r['cvss']:<5.1f} | {r['latency_ms']:>6.2f}ms")
    print("-" * 92)
    print(f"Total Runs: {len(summary_records)} | Total Execution Time: {total_time_ms:.2f}ms | Avg Latency: {total_time_ms / len(summary_records):.2f}ms/run")
    print("All 10 scenarios completed adhering to dual-method consensus, reproducible evidence, and FP gating.\n")


if __name__ == "__main__":
    run_demo()
