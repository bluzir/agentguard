import fs from "node:fs";
import path from "node:path";
import { loadConfig } from "../config/index.js";
import { SkillScannerModule, type ScanFinding } from "../modules/skill-scanner.js";
import { GuardPhase } from "../types.js";

function parseArgs(): { configPath?: string } {
  const args = process.argv.slice(3);
  let configPath: string | undefined;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--config" || args[i] === "-c") {
      configPath = args[++i];
    }
  }

  return { configPath };
}

function globFiles(dir: string, patterns: string[]): string[] {
  // Simple recursive file walk (replace with proper glob lib later)
  const files: string[] = [];

  if (!fs.existsSync(dir)) return files;

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...globFiles(fullPath, patterns));
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      const matchesPattern = patterns.some((p) => {
        // Simple extension matching from globs like "**/*.md"
        const extMatch = p.match(/\*\.(\w+)$/);
        return extMatch && `.${extMatch[1]}` === ext;
      });
      if (matchesPattern) {
        files.push(fullPath);
      }
    }
  }

  return files;
}

export async function run(): Promise<void> {
  const { configPath } = parseArgs();
  const config = loadConfig(configPath);

  const scannerConfig = (config.moduleConfig.skill_scanner ?? {}) as Record<string, unknown>;
  const scanPaths = (scannerConfig.scanPaths as string[]) ?? [
    path.join(config.global.workspace, "skills"),
    path.join(config.global.workspace, "prompts"),
  ];
  const includeGlobs = (scannerConfig.includeGlobs as string[]) ?? [
    "**/*.md",
    "**/*.txt",
    "**/*.yaml",
    "**/*.json",
  ];
  const maxFileBytes = (scannerConfig.maxFileBytes as number) ?? 1048576;

  const scanner = new SkillScannerModule();
  scanner.configure(scannerConfig);

  let totalFiles = 0;
  let totalFindings = 0;
  const allFindings: Array<{ file: string; findings: ScanFinding[] }> = [];

  for (const scanPath of scanPaths) {
    const files = globFiles(scanPath, includeGlobs);

    for (const file of files) {
      const stat = fs.statSync(file);
      if (stat.size > maxFileBytes) {
        console.log(`  SKIP ${file} (${stat.size} bytes > max ${maxFileBytes})`);
        continue;
      }

      totalFiles++;
      const content = fs.readFileSync(file, "utf-8");
      const findings = scanner.scan(content);

      if (findings.length > 0) {
        totalFindings += findings.length;
        allFindings.push({ file, findings });
      }
    }
  }

  // Report
  console.log(`\nScan complete: ${totalFiles} files scanned\n`);

  if (allFindings.length === 0) {
    console.log("No suspicious patterns found.");
    return;
  }

  for (const { file, findings } of allFindings) {
    console.log(`${file}:`);
    for (const f of findings) {
      const badge =
        f.severity === "critical"
          ? "CRIT"
          : f.severity === "high"
            ? "HIGH"
            : f.severity === "medium"
              ? "MED "
              : "INFO";
      console.log(`  [${badge}] ${f.ruleId} — ${f.excerpt}`);
    }
    console.log();
  }

  console.log(`Total: ${totalFindings} finding(s) in ${allFindings.length} file(s)`);

  // Exit with error code if critical findings
  const hasCritical = allFindings.some((f) =>
    f.findings.some((ff) => ff.severity === "critical"),
  );
  if (hasCritical) {
    process.exit(1);
  }
}
