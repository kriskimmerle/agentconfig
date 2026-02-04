#!/usr/bin/env python3
"""agentconfig — AI Agent Configuration Security Auditor.

Scans project-level agent configuration files for prompt injection,
credential theft, data exfiltration, and dangerous instructions.

Supported config files:
    .cursorrules, .cursor/rules/*        — Cursor AI
    CLAUDE.md, .claude/commands/*        — Claude Code
    AGENTS.md                            — Agent instructions
    .github/copilot-instructions.md      — GitHub Copilot
    .aider.conf.yml                      — Aider
    .continue/config.json                — Continue.dev
    mcp.json, .mcp/*.json                — MCP servers
    .windsurfrules                       — Windsurf/Codeium
    codex.md                             — OpenAI Codex CLI

Usage:
    agentconfig .                        # Scan current project
    agentconfig path/to/project/
    agentconfig --check path/to/project/ # CI mode
    agentconfig --json .                 # JSON output
    agentconfig file.md                  # Scan specific file

Informed by:
    - arxiv 2601.17548: "Prompt Injection Attacks on Agentic Coding Assistants"
    - NVIDIA AI Red Team sandbox security guidance (Jan 2026)
    - Flatt Security: "Pwning Claude Code in 8 Different Ways"
    - Lasso Security: "Detecting Indirect Prompt Injection in Claude Code"
    - ClawHavoc campaign (Jan 2026)
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

__version__ = "1.0.0"

# ── Check definitions ──────────────────────────────────────────────

CHECKS: dict[str, dict[str, str]] = {
    "AC01": {"name": "Prompt Injection", "severity": "CRITICAL",
             "desc": "Instructions to override system behavior or ignore safety rules"},
    "AC02": {"name": "Command Execution", "severity": "CRITICAL",
             "desc": "Instructions to run shell commands, scripts, or executables"},
    "AC03": {"name": "File Exfiltration", "severity": "CRITICAL",
             "desc": "Instructions to read or transmit sensitive files"},
    "AC04": {"name": "Credential Access", "severity": "CRITICAL",
             "desc": "Instructions to access API keys, tokens, or passwords"},
    "AC05": {"name": "Network Exfiltration", "severity": "CRITICAL",
             "desc": "Instructions to send data to external endpoints"},
    "AC06": {"name": "Permission Escalation", "severity": "HIGH",
             "desc": "Requesting elevated privileges or bypassing approvals"},
    "AC07": {"name": "Persistence", "severity": "HIGH",
             "desc": "Setting up persistent access via cron, hooks, or startup scripts"},
    "AC08": {"name": "Dangerous MCP Config", "severity": "HIGH",
             "desc": "MCP server with overly broad tool permissions"},
    "AC09": {"name": "Obfuscated Content", "severity": "HIGH",
             "desc": "Base64, unicode tricks, or hidden text in config files"},
    "AC10": {"name": "Approval Bypass", "severity": "HIGH",
             "desc": "Social engineering to skip review, auto-approve, or click yes"},
}

SEVERITY_WEIGHT = {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 1}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ── Config file discovery ───────────────────────────────────────────

AGENT_CONFIG_FILES = {
    # Cursor
    ".cursorrules",
    ".windsurfrules",
    # Claude Code
    "CLAUDE.md",
    "claude.md",
    "AGENTS.md",
    "agents.md",
    # Codex
    "codex.md",
    "CODEX.md",
    # Copilot
    ".github/copilot-instructions.md",
    # Aider
    ".aider.conf.yml",
    # MCP
    "mcp.json",
    ".mcp.json",
}

AGENT_CONFIG_DIRS = {
    ".cursor/rules": "*.md",
    ".claude/commands": "*.md",
    ".claude": "settings.json",
    ".mcp": "*.json",
    ".continue": "config.json",
    ".codex": "*.md",
}


# ── Pattern definitions ─────────────────────────────────────────────

# AC01: Prompt injection patterns
INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?', re.I),
     "Instruction override: ignore previous instructions"),
    (re.compile(r'disregard\s+(?:all\s+)?(?:previous|above|prior|your)\s+(?:instructions?|rules?|guidelines?)', re.I),
     "Instruction override: disregard rules"),
    (re.compile(r'forget\s+(?:all\s+)?(?:previous|your|everything)', re.I),
     "Instruction override: forget previous context"),
    (re.compile(r'you\s+are\s+now\s+(?:a|an)\s', re.I),
     "Role hijacking: 'you are now a...'"),
    (re.compile(r'your\s+new\s+(?:instructions?|role|purpose|task)\s+(?:is|are)', re.I),
     "Role hijacking: new instructions"),
    (re.compile(r'(?:system|SYSTEM)\s*(?:prompt|message|instruction)\s*:', re.I),
     "System prompt injection marker"),
    (re.compile(r'\[(?:SYSTEM|INST|SYS)\]', re.I),
     "System instruction tag injection"),
    (re.compile(r'<\|(?:im_start|system|endoftext)\|>', re.I),
     "Chat template injection token"),
    (re.compile(r'do\s+not\s+(?:follow|obey|listen\s+to)\s+(?:any|the)', re.I),
     "Instruction to disobey safety rules"),
    (re.compile(r'override\s+(?:safety|security|restrictions?|permissions?)', re.I),
     "Attempting to override safety restrictions"),
]

# AC02: Command execution patterns
COMMAND_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(?:run|execute|invoke)\s+(?:the\s+)?(?:command|script|shell|bash|sh)\s', re.I),
     "Instruction to execute shell commands"),
    (re.compile(r'(?:curl|wget|fetch)\s+(?:https?://|ftp://)', re.I),
     "External download command"),
    (re.compile(r'(?:source|\.)\s+(?:~/|\./|/)', re.I),
     "Source/dot command to load environment"),
    (re.compile(r'(?:pip|npm|yarn|cargo)\s+install\s+', re.I),
     "Package installation command"),
    (re.compile(r'(?:sudo|doas|su\s)', re.I),
     "Elevated privilege command"),
    (re.compile(r'chmod\s+(?:777|\+[xsXS]|u\+s)', re.I),
     "Dangerous permission change"),
    (re.compile(r'(?:rm\s+-rf|rm\s+--no-preserve-root)', re.I),
     "Destructive delete command"),
    (re.compile(r'(?:eval|exec)\s*\(', re.I),
     "Dynamic code execution"),
]

# AC03: File exfiltration patterns
EXFIL_FILE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(?:read|cat|open|load|include|source)\s+(?:.*?)\.env\b', re.I),
     "Reading .env file"),
    (re.compile(r'(?:read|cat|open|load)\s+(?:.*?)(?:\.ssh|id_rsa|id_ed25519)', re.I),
     "Reading SSH keys"),
    (re.compile(r'(?:read|cat|open|load)\s+(?:.*?)(?:\.aws|credentials|\.npmrc|\.pypirc|\.netrc)', re.I),
     "Reading credential files"),
    (re.compile(r'(?:read|cat|open|load)\s+(?:.*?)(?:\.git-credentials|\.gitconfig)', re.I),
     "Reading git credentials"),
    (re.compile(r'(?:read|cat|open|load)\s+(?:.*?)(?:keychain|keystore|wallet)', re.I),
     "Reading keychain/keystore"),
    (re.compile(r'(?:send|upload|post|transmit|exfiltrate)\s+(?:.*?)(?:file|data|content|secret)', re.I),
     "Instruction to send file data externally"),
]

# AC04: Credential access patterns
CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(?:extract|steal|capture|collect|harvest)\s+(?:.*?)(?:api[_\s]?key|token|secret|password|credential)', re.I),
     "Instruction to extract credentials"),
    (re.compile(r'(?:echo|print|output|display|log|write)\s+(?:.*?)(?:\$[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL))', re.I),
     "Instruction to output credential environment variables"),
    (re.compile(r'(?:include|embed|add)\s+(?:.*?)(?:api[_\s]?key|token|secret)\s+(?:in|to)\s+(?:the\s+)?(?:output|response|code|commit)', re.I),
     "Instruction to embed credentials in output"),
]

# AC05: Network exfiltration patterns
NETWORK_EXFIL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(?:webhook\.site|requestbin|hookbin|pipedream|beeceptor|requestcatcher)', re.I),
     "Known exfiltration endpoint"),
    (re.compile(r'(?:ngrok|serveo|localtunnel|cloudflared|bore)\.', re.I),
     "Tunnel service (potential exfiltration)"),
    (re.compile(r'(?:send|post|upload)\s+(?:.*?)(?:to|at)\s+https?://', re.I),
     "Instruction to send data to external URL"),
    (re.compile(r'(?:fetch|curl|wget)\s+(?:.*?)(?:\?|&)(?:data|content|secret|key|token)=', re.I),
     "Exfiltration via URL query parameters"),
    (re.compile(r'(?:encode|base64)\s+(?:.*?)(?:and|then)\s+(?:send|post|append|include)', re.I),
     "Encode-then-exfiltrate pattern"),
]

# AC06: Permission escalation patterns
PERMISSION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(?:always\s+)?(?:allow|approve|accept|permit)\s+(?:all|any|every)\s+(?:tool|action|command|operation)', re.I),
     "Blanket permission approval"),
    (re.compile(r'(?:skip|bypass|disable)\s+(?:the\s+)?(?:approval|confirmation|review|check|verification)', re.I),
     "Bypassing approval process"),
    (re.compile(r'(?:don.?t\s+ask|never\s+ask|no\s+need\s+to\s+(?:ask|confirm))', re.I),
     "Suppressing confirmation prompts"),
    (re.compile(r'auto[_\s-]?(?:approve|accept|allow|yes)', re.I),
     "Auto-approval setting"),
    (re.compile(r'(?:run|use)\s+(?:in\s+)?(?:yolo|autonomous|unattended|headless)\s+mode', re.I),
     "Unrestricted execution mode"),
    (re.compile(r'(?:allowed[_-]?tools|permissions?)\s*[=:]\s*\[\s*["\']?\*["\']?\s*\]', re.I),
     "Wildcard tool permissions"),
]

# AC07: Persistence patterns
PERSISTENCE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(?:crontab|systemctl\s+enable|launchctl\s+load|launchd)', re.I),
     "Scheduled task / persistence mechanism"),
    (re.compile(r'(?:\.bashrc|\.zshrc|\.profile|\.bash_profile|\.zprofile)', re.I),
     "Shell profile modification"),
    (re.compile(r'(?:pre-commit|post-commit|pre-push|post-checkout)\s+hook', re.I),
     "Git hook installation"),
    (re.compile(r'(?:startup|autostart|init\.d|rc\.local|LaunchAgents?|LaunchDaemons?)', re.I),
     "Startup persistence"),
    (re.compile(r'(?:modify|edit|append|write)\s+(?:.*?)(?:\.git/hooks|\.husky)', re.I),
     "Git hook modification"),
]

# AC09: Obfuscation patterns
OBFUSCATION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'[\u200b\u200c\u200d\u2060\ufeff]'),
     "Zero-width characters (hidden text)"),
    (re.compile(r'[\u0400-\u04ff].*[a-zA-Z]|[a-zA-Z].*[\u0400-\u04ff]'),
     "Mixed Cyrillic/Latin (homoglyph confusion)"),
    (re.compile(r'&#x[0-9a-fA-F]{2,4};'),
     "HTML entity encoding"),
    (re.compile(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}'),
     "Hex escape sequence"),
    (re.compile(r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}'),
     "Unicode escape sequence"),
]

# AC10: Social engineering / approval bypass
SOCIAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(?:just|simply|always)\s+(?:click|press|type|select)\s+(?:yes|y|allow|accept|approve)', re.I),
     "Social engineering to auto-approve"),
    (re.compile(r'(?:trust|safe|secure|verified|official)\s+(?:tool|server|source|command)', re.I),
     "False trust claim"),
    (re.compile(r'(?:don.?t\s+worry|no\s+risk|perfectly\s+safe|nothing\s+harmful)', re.I),
     "Safety reassurance (social engineering)"),
    (re.compile(r'(?:this\s+is\s+(?:normal|expected|standard|required))\s+(?:behavior|practice)', re.I),
     "Normalizing suspicious behavior"),
]


# ── Finding ─────────────────────────────────────────────────────────


class Finding:
    __slots__ = ("rule", "file", "line", "message", "severity", "fix", "snippet")

    def __init__(self, rule: str, file: str, line: int, message: str,
                 severity: str, fix: str = "", snippet: str = ""):
        self.rule = rule
        self.file = file
        self.line = line
        self.message = message
        self.severity = severity
        self.fix = fix
        self.snippet = snippet

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule": self.rule,
            "name": CHECKS[self.rule]["name"],
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
        }
        if self.fix:
            d["fix"] = self.fix
        if self.snippet:
            d["snippet"] = self.snippet
        return d


# ── Analyzer ────────────────────────────────────────────────────────


class AgentConfigAuditor:
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def audit_file(self, filepath: str, content: str, file_type: str = "text") -> None:
        """Audit a single configuration file."""
        if file_type == "json":
            self._check_mcp_config(filepath, content)
        
        # Text-based checks on all files
        self._check_injection(filepath, content)
        self._check_commands(filepath, content)
        self._check_file_exfil(filepath, content)
        self._check_credentials(filepath, content)
        self._check_network_exfil(filepath, content)
        self._check_permissions(filepath, content)
        self._check_persistence(filepath, content)
        self._check_obfuscation(filepath, content)
        self._check_social_engineering(filepath, content)
        self._check_base64_payloads(filepath, content)

    def _scan_patterns(self, fp: str, content: str, rule: str,
                        patterns: list[tuple[re.Pattern, str]],
                        severity: str, fix: str = "") -> None:
        """Generic pattern scanner."""
        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            for pattern, desc in patterns:
                match = pattern.search(stripped)
                if match:
                    snippet = stripped[:80] if len(stripped) > 80 else stripped
                    self.findings.append(Finding(
                        rule, fp, line_num, desc, severity, fix, snippet,
                    ))
                    break  # One finding per line per rule

    def _check_injection(self, fp: str, content: str) -> None:
        self._scan_patterns(fp, content, "AC01", INJECTION_PATTERNS, "CRITICAL",
                           "Remove prompt injection — these override agent safety rules")

    def _check_commands(self, fp: str, content: str) -> None:
        self._scan_patterns(fp, content, "AC02", COMMAND_PATTERNS, "CRITICAL",
                           "Remove or restrict command execution instructions")

    def _check_file_exfil(self, fp: str, content: str) -> None:
        self._scan_patterns(fp, content, "AC03", EXFIL_FILE_PATTERNS, "CRITICAL",
                           "Remove instructions to read sensitive files")

    def _check_credentials(self, fp: str, content: str) -> None:
        self._scan_patterns(fp, content, "AC04", CREDENTIAL_PATTERNS, "CRITICAL",
                           "Remove credential access instructions")

    def _check_network_exfil(self, fp: str, content: str) -> None:
        self._scan_patterns(fp, content, "AC05", NETWORK_EXFIL_PATTERNS, "CRITICAL",
                           "Remove external data transmission instructions")

    def _check_permissions(self, fp: str, content: str) -> None:
        self._scan_patterns(fp, content, "AC06", PERMISSION_PATTERNS, "HIGH",
                           "Don't auto-approve — require explicit user confirmation for each action")

    def _check_persistence(self, fp: str, content: str) -> None:
        self._scan_patterns(fp, content, "AC07", PERSISTENCE_PATTERNS, "HIGH",
                           "Remove persistence mechanism setup instructions")

    def _check_obfuscation(self, fp: str, content: str) -> None:
        self._scan_patterns(fp, content, "AC09", OBFUSCATION_PATTERNS, "HIGH",
                           "Remove obfuscated content — may hide malicious instructions")

    def _check_social_engineering(self, fp: str, content: str) -> None:
        self._scan_patterns(fp, content, "AC10", SOCIAL_PATTERNS, "HIGH",
                           "Remove social engineering patterns — users should review each action")

    def _check_base64_payloads(self, fp: str, content: str) -> None:
        """AC09: Detect base64-encoded payloads with suspicious decoded content."""
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
        suspicious_decoded = [
            "import os", "import subprocess", "eval(", "exec(",
            "os.system", "__import__", "curl ", "wget ",
            "#!/bin/", "/bin/sh", "/bin/bash",
            "ignore previous", "you are now",
        ]

        for line_num, line in enumerate(content.splitlines(), 1):
            for match in b64_pattern.finditer(line):
                try:
                    decoded = base64.b64decode(match.group(0)).decode("utf-8", errors="ignore")
                    if any(s in decoded.lower() for s in suspicious_decoded):
                        snippet = decoded[:60] + "..." if len(decoded) > 60 else decoded
                        self.findings.append(Finding(
                            "AC09", fp, line_num,
                            f"Base64 payload with suspicious content",
                            "HIGH",
                            "Remove encoded payloads — they hide malicious instructions",
                            snippet=snippet,
                        ))
                except Exception:
                    pass

    def _check_mcp_config(self, fp: str, content: str) -> None:
        """AC08: Audit MCP server configurations."""
        try:
            config = json.loads(content)
        except json.JSONDecodeError:
            return

        servers = {}
        # Handle both formats: {"mcpServers": {...}} and {"servers": {...}}
        if isinstance(config, dict):
            servers = config.get("mcpServers", config.get("servers", {}))
            if not isinstance(servers, dict):
                servers = {}

        for name, server in servers.items():
            if not isinstance(server, dict):
                continue

            # Check command
            cmd = server.get("command", "")
            args = server.get("args", [])
            full_cmd = f"{cmd} {' '.join(str(a) for a in args)}" if args else cmd

            # Dangerous commands
            if any(d in full_cmd.lower() for d in
                   ("npx", "uvx", "pip run", "bash", "sh ", "/bin/")):
                if any(d in full_cmd for d in
                       ("@", "http://", "https://", "github.com")):
                    self.findings.append(Finding(
                        "AC08", fp, 0,
                        f"MCP server '{name}' executes remote package: {full_cmd[:60]}",
                        "HIGH",
                        "Pin MCP server packages to specific versions from trusted sources",
                    ))

            # Check env for secrets being passed
            env = server.get("env", {})
            if isinstance(env, dict):
                for key, val in env.items():
                    if isinstance(val, str) and not val.startswith("${"):
                        key_upper = key.upper()
                        if any(s in key_upper for s in
                               ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")):
                            self.findings.append(Finding(
                                "AC08", fp, 0,
                                f"MCP server '{name}' has hardcoded credential in env: {key}",
                                "CRITICAL" if not val.startswith("env:") else "HIGH",
                                "Use environment variable references: ${ENV_VAR}",
                            ))

            # Check for overly permissive tool configs
            tools = server.get("tools", server.get("allowed_tools", []))
            if isinstance(tools, list) and "*" in tools:
                self.findings.append(Finding(
                    "AC08", fp, 0,
                    f"MCP server '{name}' has wildcard tool permissions",
                    "HIGH",
                    "Specify explicit tool allowlist instead of '*'",
                ))


# ── File Discovery ──────────────────────────────────────────────────


def discover_config_files(root: str) -> list[tuple[str, str]]:
    """Find agent configuration files in a project. Returns (path, type) pairs."""
    found: list[tuple[str, str]] = []
    root_path = Path(root)

    # Check known file names
    for fname in AGENT_CONFIG_FILES:
        fpath = root_path / fname
        if fpath.is_file():
            ftype = "json" if fname.endswith(".json") else "text"
            found.append((str(fpath), ftype))

    # Check known directories
    for dirname, pattern in AGENT_CONFIG_DIRS.items():
        dirpath = root_path / dirname
        if dirpath.is_dir():
            for fpath in dirpath.glob(pattern):
                if fpath.is_file():
                    ftype = "json" if fpath.suffix == ".json" else "text"
                    found.append((str(fpath), ftype))

    return found


def scan_path(path: str, auditor: AgentConfigAuditor) -> int:
    """Scan a path for agent configs. Returns number of files scanned."""
    p = Path(path)
    count = 0

    if p.is_file():
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
            ftype = "json" if p.suffix == ".json" else "text"
            auditor.audit_file(str(p), content, ftype)
            count = 1
        except OSError:
            pass
    elif p.is_dir():
        configs = discover_config_files(str(p))
        for fpath, ftype in configs:
            try:
                content = Path(fpath).read_text(encoding="utf-8", errors="ignore")
                auditor.audit_file(fpath, content, ftype)
                count += 1
            except OSError:
                pass
    return count


# ── Scoring and Output ──────────────────────────────────────────────


def compute_score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(SEVERITY_WEIGHT[f.severity] for f in findings))


def grade(score: int) -> str:
    if score >= 95: return "A+"
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


def severity_color(s: str) -> str:
    return {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m",
            "LOW": "\033[36m", "INFO": "\033[90m"}.get(s, "")


R = "\033[0m"
B = "\033[1m"
D = "\033[2m"


def print_results(auditor: AgentConfigAuditor, files_scanned: int,
                  verbose: bool = False, severity_filter: str | None = None,
                  ignore_rules: set[str] | None = None) -> tuple[int, str]:
    findings = auditor.findings
    if severity_filter:
        si = SEVERITY_ORDER.get(severity_filter.upper(), 99)
        findings = [f for f in findings if SEVERITY_ORDER[f.severity] <= si]
    if ignore_rules:
        findings = [f for f in findings if f.rule not in ignore_rules]

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))
    s = compute_score(findings)
    g = grade(s)

    print(f"\n{B}🤖 agentconfig{R} — Agent Configuration Security Audit")
    print(f"{D}{'─' * 60}{R}")
    print(f"  Config files scanned: {files_scanned}")
    print(f"  Findings: {len(findings)}")
    print(f"  Score: {B}{s}/100{R}  Grade: {B}{g}{R}")
    print(f"{D}{'─' * 60}{R}")

    if not findings:
        if files_scanned == 0:
            print(f"\n  {D}No agent configuration files found in this project.{R}\n")
        else:
            print(f"\n  {B}✅ No security issues found in agent configs.{R}\n")
        return s, g

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    print()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in by_sev:
            print(f"  {severity_color(sev)}{sev}{R}: {by_sev[sev]}")

    by_check: dict[str, int] = {}
    for f in findings:
        by_check[f.rule] = by_check.get(f.rule, 0) + 1
    print(f"\n{D}{'─' * 60}{R}")
    for rule in sorted(by_check.keys()):
        check = CHECKS[rule]
        c = severity_color(check["severity"])
        print(f"  {c}{rule}{R} {check['name']}: {by_check[rule]}")

    print(f"\n{D}{'─' * 60}{R}")
    current_file = ""
    for f in findings:
        if f.file != current_file:
            current_file = f.file
            print(f"\n  {B}{current_file}{R}")

        c = severity_color(f.severity)
        print(f"    {D}L{f.line:<4}{R} {c}{f.severity:<8}{R} {c}{f.rule}{R} {f.message}")
        if f.snippet:
            print(f"         {D}> {f.snippet}{R}")
        if verbose and f.fix:
            print(f"         {D}Fix: {f.fix}{R}")

    print()
    return s, g


def print_json(auditor: AgentConfigAuditor, files_scanned: int,
               severity_filter: str | None = None,
               ignore_rules: set[str] | None = None) -> tuple[int, str]:
    findings = auditor.findings
    if severity_filter:
        si = SEVERITY_ORDER.get(severity_filter.upper(), 99)
        findings = [f for f in findings if SEVERITY_ORDER[f.severity] <= si]
    if ignore_rules:
        findings = [f for f in findings if f.rule not in ignore_rules]

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))
    s = compute_score(findings)
    g = grade(s)

    result = {
        "tool": "agentconfig",
        "version": __version__,
        "files_scanned": files_scanned,
        "score": s,
        "grade": g,
        "summary": {sev: sum(1 for f in findings if f.severity == sev)
                     for sev in SEVERITY_ORDER if any(f.severity == sev for f in findings)},
        "findings": [f.to_dict() for f in findings],
    }
    print(json.dumps(result, indent=2))
    return s, g


# ── CLI ──────────────────────────────────────────────────────────────


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="agentconfig",
        description="🤖 AI Agent Configuration Security Auditor — scan .cursorrules, CLAUDE.md, MCP configs, and more",
    )
    parser.add_argument("paths", nargs="*", default=["."],
                        help="Project directories or config files to scan")
    parser.add_argument("--check", action="store_true",
                        help="CI mode: exit 1 if grade below threshold")
    parser.add_argument("--threshold", default="C",
                        help="Minimum passing grade for --check")
    parser.add_argument("--json", dest="json_output", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--severity",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to report")
    parser.add_argument("--ignore", action="append", default=[],
                        help="Rules to ignore")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show fix suggestions")
    parser.add_argument("--version", action="version",
                        version=f"agentconfig {__version__}")

    args = parser.parse_args()

    auditor = AgentConfigAuditor()
    total_files = 0
    ignore_rules = set(args.ignore)

    for path in args.paths:
        total_files += scan_path(path, auditor)

    if args.json_output:
        s, g = print_json(auditor, total_files, args.severity, ignore_rules)
    else:
        s, g = print_results(auditor, total_files, args.verbose,
                              args.severity, ignore_rules)

    if args.check:
        ts = {"A+": 95, "A": 90, "B": 80, "C": 70, "D": 60, "F": 0}
        if compute_score(auditor.findings) < ts.get(args.threshold.upper(), 70):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
