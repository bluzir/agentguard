import { type Decision, type GuardEvent, GuardPhase, type Severity } from "../types.js";
import { BaseModule } from "./base.js";

interface SkillScannerConfig {
  scanPaths?: string[];
  includeGlobs?: string[];
  maxFileBytes?: number;
  minEncodedLength?: number;
  entropyThreshold?: number;
  actionOnCritical?: "deny" | "challenge" | "alert";
  allowDomains?: string[];
  blockDomains?: string[];
  requireSignature?: boolean;
  requireSbom?: boolean;
  requirePinnedSource?: boolean;
  trustedSigners?: string[];
  enforceKinds?: Array<"skill" | "prompt" | "tool_metadata" | "config">;
  onProvenanceFailure?: "deny" | "challenge" | "alert";
}

export interface ScanFinding {
  ruleId: string;
  severity: Severity;
  confidence: "low" | "medium" | "high";
  location?: string;
  excerpt: string;
}

// Detection rules

const HTML_COMMENT = /<!--[\s\S]*?-->/g;
const ZERO_WIDTH_CHARS = /[\u200B\u200C\u200D\u200E\u200F\uFEFF\u2060\u2061\u2062\u2063\u2064]/g;
const BASE64_BLOB = /[A-Za-z0-9+/=]{80,}/g;
const DECODE_EXEC_PATTERNS = [
  /base64\s+-d/i,
  /atob\s*\(/i,
  /Buffer\.from\s*\([^)]*['"]base64['"]/i,
];
const EXFIL_PATTERNS = [
  /(?:\.env|\.ssh|\.aws|api[_-]?key|token|secret|password)[\s\S]{0,100}(?:curl|wget|fetch|http|webhook)/i,
  /(?:curl|wget|fetch|http|webhook)[\s\S]{0,100}(?:\.env|\.ssh|\.aws|api[_-]?key|token|secret|password)/i,
];
const SUSPICIOUS_URL_PATTERNS = [
  /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,  // raw IP URLs
  /https?:\/\/xn--/i,                                    // punycode
  /(?:bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd)\//i,         // URL shorteners
];
const INSTRUCTION_TAKEOVER = [
  /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i,
  /disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|rules)/i,
  /you\s+are\s+now\s+(?:a|an)\s+/i,
  /(?:reveal|show|output|print)\s+(?:your\s+)?(?:system|developer)\s+prompt/i,
];

/**
 * §9.10 skill_scanner — detect suspicious instructions in skills/prompts/tool metadata.
 * Phases: PRE_LOAD (primary), optional PRE_REQUEST
 */
export class SkillScannerModule extends BaseModule {
  name = "skill_scanner";
  phases = new Set([GuardPhase.PRE_LOAD, GuardPhase.PRE_REQUEST]);

  private actionOnCritical: "deny" | "challenge" | "alert" = "challenge";
  private minEncodedLength = 80;
  private entropyThreshold = 4.2;
  private blockDomains: string[] = [];
  private requireSignature = false;
  private requireSbom = false;
  private requirePinnedSource = false;
  private trustedSigners: string[] = [];
  private enforceKinds = new Set<"skill" | "prompt" | "tool_metadata" | "config">(["skill"]);
  private onProvenanceFailure: "deny" | "challenge" | "alert" = "deny";

  override configure(config: Record<string, unknown>): void {
    super.configure(config);
    const c = config as unknown as Partial<SkillScannerConfig>;
    this.actionOnCritical = c.actionOnCritical ?? "challenge";
    this.minEncodedLength = c.minEncodedLength ?? 80;
    this.entropyThreshold = c.entropyThreshold ?? 4.2;
    this.blockDomains = c.blockDomains ?? [];
    this.requireSignature = c.requireSignature ?? false;
    this.requireSbom = c.requireSbom ?? false;
    this.requirePinnedSource = c.requirePinnedSource ?? false;
    this.trustedSigners = c.trustedSigners ?? [];
    this.enforceKinds = new Set(c.enforceKinds ?? ["skill"]);
    this.onProvenanceFailure = c.onProvenanceFailure ?? "deny";
  }

  async evaluate(event: GuardEvent): Promise<Decision> {
    const provenanceFindings = this.scanProvenance(event);
    if (provenanceFindings.length > 0) {
      return this.applyFailurePolicy(
        provenanceFindings,
        this.onProvenanceFailure,
        "provenance findings",
      );
    }

    const content = this.getContent(event);
    if (!content) {
      return this.allow("no content to scan");
    }

    const findings = this.scan(content);
    if (findings.length === 0) {
      return this.allow("no suspicious patterns found");
    }

    const maxSeverity = this.getMaxSeverity(findings);
    const summary = findings.map((f) => `${f.ruleId}(${f.severity})`).join(", ");

    if (maxSeverity === "critical") {
      return this.applyFailurePolicy(
        findings,
        this.actionOnCritical,
        "critical findings",
      );
    }

    return this.alert(`findings: ${summary}`, maxSeverity);
  }

  scan(content: string): ScanFinding[] {
    const findings: ScanFinding[] = [];

    // Hidden instructions (HTML comments)
    for (const match of content.matchAll(HTML_COMMENT)) {
      findings.push({
        ruleId: "hidden_html_comment",
        severity: "high",
        confidence: "high",
        excerpt: match[0].slice(0, 80),
      });
    }

    // Zero-width chars
    if (ZERO_WIDTH_CHARS.test(content)) {
      findings.push({
        ruleId: "zero_width_chars",
        severity: "high",
        confidence: "medium",
        excerpt: "content contains zero-width/control characters",
      });
    }

    // Encoded payloads
    for (const match of content.matchAll(BASE64_BLOB)) {
      if (match[0].length >= this.minEncodedLength) {
        findings.push({
          ruleId: "encoded_blob",
          severity: "medium",
          confidence: "medium",
          excerpt: `base64 blob (${match[0].length} chars)`,
        });
      }
    }

    // Decode-and-execute
    for (const pattern of DECODE_EXEC_PATTERNS) {
      if (pattern.test(content)) {
        findings.push({
          ruleId: "decode_exec",
          severity: "critical",
          confidence: "high",
          excerpt: `decode-and-execute pattern: ${pattern.source}`,
        });
      }
    }

    // Exfiltration patterns
    for (const pattern of EXFIL_PATTERNS) {
      if (pattern.test(content)) {
        findings.push({
          ruleId: "exfil_pattern",
          severity: "critical",
          confidence: "medium",
          excerpt: "sensitive target + outbound action combination",
        });
      }
    }

    // Suspicious URLs
    for (const pattern of SUSPICIOUS_URL_PATTERNS) {
      const match = content.match(pattern);
      if (match) {
        findings.push({
          ruleId: "suspicious_url",
          severity: "high",
          confidence: "medium",
          excerpt: match[0].slice(0, 80),
        });
      }
    }

    // Blocked domains
    for (const domain of this.blockDomains) {
      if (content.includes(domain)) {
        findings.push({
          ruleId: "blocked_domain",
          severity: "high",
          confidence: "high",
          excerpt: `blocked domain: ${domain}`,
        });
      }
    }

    // Instruction takeover
    for (const pattern of INSTRUCTION_TAKEOVER) {
      if (pattern.test(content)) {
        findings.push({
          ruleId: "instruction_takeover",
          severity: "critical",
          confidence: "high",
          excerpt: `instruction override attempt: ${pattern.source}`,
        });
      }
    }

    return findings;
  }

  private getContent(event: GuardEvent): string | undefined {
    if (event.phase === GuardPhase.PRE_LOAD) {
      return event.artifact?.content;
    }
    if (event.phase === GuardPhase.PRE_REQUEST) {
      return event.requestText;
    }
    return undefined;
  }

  private getMaxSeverity(findings: ScanFinding[]): Severity {
    const order: Severity[] = ["info", "medium", "high", "critical"];
    let max: Severity = "info";
    for (const f of findings) {
      if (order.indexOf(f.severity) > order.indexOf(max)) {
        max = f.severity;
      }
    }
    return max;
  }

  private scanProvenance(event: GuardEvent): ScanFinding[] {
    if (event.phase !== GuardPhase.PRE_LOAD) {
      return [];
    }

    const artifact = event.artifact;
    if (!artifact) {
      return [];
    }

    if (!this.enforceKinds.has(artifact.kind)) {
      return [];
    }

    const findings: ScanFinding[] = [];

    if (this.requireSignature && artifact.signatureVerified !== true) {
      findings.push({
        ruleId: "missing_signature",
        severity: "critical",
        confidence: "high",
        excerpt: "artifact is not signature-verified",
      });
    }

    if (this.trustedSigners.length > 0) {
      const signer = (artifact.signer ?? "").trim();
      if (!signer) {
        findings.push({
          ruleId: "missing_signer_identity",
          severity: "high",
          confidence: "high",
          excerpt: "trusted signers are configured but signer is missing",
        });
      } else if (!this.trustedSigners.includes(signer)) {
        findings.push({
          ruleId: "untrusted_signer",
          severity: "critical",
          confidence: "high",
          excerpt: `signer "${signer}" is not in trustedSigners`,
        });
      }
    }

    if (this.requireSbom && !artifact.sbomUri) {
      findings.push({
        ruleId: "missing_sbom",
        severity: "high",
        confidence: "high",
        excerpt: "artifact missing sbomUri",
      });
    }

    if (this.requirePinnedSource && artifact.versionPinned !== true) {
      const source = artifact.sourceUri ?? "unknown-source";
      findings.push({
        ruleId: this.isLikelyFloatingReference(source)
          ? "floating_version_reference"
          : "unpinned_source",
        severity: "high",
        confidence: "medium",
        excerpt: `source is not pinned: ${source}`,
      });
    }

    return findings;
  }

  private isLikelyFloatingReference(sourceUri: string): boolean {
    return (
      /(?:^|[/:@])latest(?:$|[/?#])/i.test(sourceUri) ||
      /#(?:main|master|head)$/i.test(sourceUri) ||
      /:(?:main|master|head)$/i.test(sourceUri)
    );
  }

  private applyFailurePolicy(
    findings: ScanFinding[],
    policy: "deny" | "challenge" | "alert",
    label: string,
  ): Decision {
    const summary = findings.map((f) => `${f.ruleId}(${f.severity})`).join(", ");
    const maxSeverity = this.getMaxSeverity(findings);

    switch (policy) {
      case "deny":
        return this.deny(`${label}: ${summary}`, maxSeverity);
      case "challenge":
        return {
          action: "challenge" as Decision["action"],
          module: this.name,
          reason: `${label} require approval: ${summary}`,
          severity: maxSeverity,
          challenge: {
            channel: "orchestrator",
            prompt: `Suspicious content detected:\n${findings.map((f) => `- ${f.ruleId}: ${f.excerpt}`).join("\n")}\n\nAllow?`,
            timeoutSec: 300,
          },
        };
      case "alert":
        return this.alert(`${label}: ${summary}`, maxSeverity);
    }
  }
}
