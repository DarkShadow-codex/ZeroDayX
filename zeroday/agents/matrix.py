"""Specialized Agent Matrix & Capability Registry for ZeroDay v2.0."""

from __future__ import annotations

from dataclasses import dataclass

from zeroday.policy.permissions import DEFAULT_AGENT_CAPABILITIES, AgentCapabilities


@dataclass(slots=True)
class AgentRoleDefinition:
    role: str
    display_name: str
    primary_responsibility: str
    capabilities: AgentCapabilities
    system_prompt_snippet: str


AGENT_MATRIX: dict[str, AgentRoleDefinition] = {
    "root": AgentRoleDefinition(
        role="root",
        display_name="Root Orchestrator",
        primary_responsibility="Understand target, threat modeling, attack strategy, task spawning, posture review",
        capabilities=DEFAULT_AGENT_CAPABILITIES["root"],
        system_prompt_snippet="You are the Root Security Orchestrator. You build threat models, plan multi-stage red team tests, spawn specialized child agents, correlate discoveries, and generate the final posture assessment.",
    ),
    "recon": AgentRoleDefinition(
        role="recon",
        display_name="Reconnaissance Agent",
        primary_responsibility="Attack-surface discovery: subdomains, ports, endpoints, technologies, and services",
        capabilities=DEFAULT_AGENT_CAPABILITIES["recon"],
        system_prompt_snippet="You are the Reconnaissance Specialist. You map the attack surface by enumerating domains, ports, routes, and software fingerprints without launching destructive exploits.",
    ),
    "web": AgentRoleDefinition(
        role="web",
        display_name="Web Application Security Agent",
        primary_responsibility="Web vulnerability assessment: OWASP Top 10, SQLi, XSS, SSRF, CSRF, input validation",
        capabilities=DEFAULT_AGENT_CAPABILITIES["web"],
        system_prompt_snippet="You are the Web Application Security Specialist. You evaluate web endpoints against OWASP Top 10 vulnerabilities with reproducible proof of concepts.",
    ),
    "api": AgentRoleDefinition(
        role="api",
        display_name="API Security Agent",
        primary_responsibility="REST & GraphQL security, BOLA/IDOR, mass assignment, endpoint rate limits",
        capabilities=DEFAULT_AGENT_CAPABILITIES["api"],
        system_prompt_snippet="You are the API Security Specialist. You inspect API specifications, analyze schemas, test for BOLA/IDOR, and identify broken function level authorization.",
    ),
    "source": AgentRoleDefinition(
        role="source",
        display_name="Source Review & SAST Agent",
        primary_responsibility="White-box code analysis, taint tracking, insecure libraries, secret leaks",
        capabilities=DEFAULT_AGENT_CAPABILITIES["source"],
        system_prompt_snippet="You are the White-box Code Auditor. You statically analyze source trees, trace untrusted inputs to dangerous sinks, and pinpoint vulnerable logic.",
    ),
    "auth": AgentRoleDefinition(
        role="auth",
        display_name="Authentication Intelligence Agent",
        primary_responsibility="Password policies, MFA, session fixation, JWT validation, OAuth flows",
        capabilities=DEFAULT_AGENT_CAPABILITIES["auth"],
        system_prompt_snippet="You are the Authentication Specialist. You test login mechanisms, token issuance, session lifetimes, and credential recovery workflows.",
    ),
    "authorization": AgentRoleDefinition(
        role="authorization",
        display_name="Authorization & Access Control Agent",
        primary_responsibility="Horizontal and vertical privilege escalation, RBAC, ABAC, multi-tenant isolation",
        capabilities=DEFAULT_AGENT_CAPABILITIES["authorization"],
        system_prompt_snippet="You are the Authorization Specialist. You test role boundaries, cross-tenant isolation, and object-level permissions.",
    ),
    "business_logic": AgentRoleDefinition(
        role="business_logic",
        display_name="Business Logic Agent",
        primary_responsibility="Workflow state abuse, step skipping, coupon/payment tampering, duplicate transactions",
        capabilities=DEFAULT_AGENT_CAPABILITIES["business_logic"],
        system_prompt_snippet="You are the Business Logic Specialist. You model multi-step workflows (checkout, payment, activation) and test for sequence tampering and race conditions.",
    ),
    "cloud": AgentRoleDefinition(
        role="cloud",
        display_name="Cloud Security Agent",
        primary_responsibility="AWS/Azure/GCP IAM, public buckets, metadata endpoints, serverless configurations",
        capabilities=DEFAULT_AGENT_CAPABILITIES["cloud"],
        system_prompt_snippet="You are the Cloud Security Specialist. You audit cloud service configurations, metadata access (IMDSv1/v2), and IAM permission boundaries.",
    ),
    "container": AgentRoleDefinition(
        role="container",
        display_name="Container Security Agent",
        primary_responsibility="Docker image inspection, Dockerfile auditing, privilege escalation via host mounts",
        capabilities=DEFAULT_AGENT_CAPABILITIES["container"],
        system_prompt_snippet="You are the Container Security Specialist. You review Dockerfiles, container capabilities, root execution, and dangerous socket mounts.",
    ),
    "k8s": AgentRoleDefinition(
        role="k8s",
        display_name="Kubernetes Security Agent",
        primary_responsibility="K8s RBAC, Pod security policies, ServiceAccounts, NetworkPolicies, API server exposure",
        capabilities=DEFAULT_AGENT_CAPABILITIES["k8s"],
        system_prompt_snippet="You are the Kubernetes Security Specialist. You assess cluster manifests, ServiceAccount permissions, and network isolation policies.",
    ),
    "secrets": AgentRoleDefinition(
        role="secrets",
        display_name="Secrets Intelligence Agent",
        primary_responsibility="Credential, token, private key, and API key discovery in code and configuration",
        capabilities=DEFAULT_AGENT_CAPABILITIES["secrets"],
        system_prompt_snippet="You are the Secrets Intelligence Specialist. You inspect git commits, environment files, and configuration stores for leaked credentials.",
    ),
    "supply_chain": AgentRoleDefinition(
        role="supply_chain",
        display_name="Supply Chain Security Agent",
        primary_responsibility="Software Bill of Materials (SBOM), known CVE dependency checking, typosquatting",
        capabilities=DEFAULT_AGENT_CAPABILITIES["supply_chain"],
        system_prompt_snippet="You are the Supply Chain Specialist. You generate SBOM inventories and evaluate dependencies against known vulnerability databases.",
    ),
    "validation": AgentRoleDefinition(
        role="validation",
        display_name="Validation & Proof Agent",
        primary_responsibility="Reproduce and validate potential findings, collect empirical proof and screenshots",
        capabilities=DEFAULT_AGENT_CAPABILITIES["validation"],
        system_prompt_snippet="You are the Validation Specialist. You confirm suspected vulnerabilities with repeatable, minimal-impact Proof of Concept demonstrations.",
    ),
    "detection": AgentRoleDefinition(
        role="detection",
        display_name="Detection Engineering Agent",
        primary_responsibility="Purple-team detection validation, telemetry gap analysis, Sigma and Suricata rule generation",
        capabilities=DEFAULT_AGENT_CAPABILITIES["detection"],
        system_prompt_snippet="You are the Detection Engineer. You validate whether offensive actions trigger defensive telemetry and construct Sigma/YARA/Suricata detection rules.",
    ),
    "remediation": AgentRoleDefinition(
        role="remediation",
        display_name="Remediation & Patching Agent",
        primary_responsibility="Root-cause diagnosis, safe patch generation (unified diffs), and security regression tests",
        capabilities=DEFAULT_AGENT_CAPABILITIES["remediation"],
        system_prompt_snippet="You are the Remediation Specialist. You diagnose vulnerability root causes, formulate patch diffs for human review, and generate automated regression tests.",
    ),
}


def get_agent_definition(role: str) -> AgentRoleDefinition | None:
    return AGENT_MATRIX.get(role.lower().strip())
