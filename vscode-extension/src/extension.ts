import * as vscode from "vscode";
import { execFile } from "child_process";
import * as path from "path";

/** Shape of a single finding from `agent-audit-kit scan --format json`. */
interface AuditFinding {
  ruleId: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  filePath: string;
  lineNumber: number | null;
  evidence: string;
  remediation: string;
  cveReferences: string[];
  owaspMcpReferences: string[];
  owaspAgenticReferences: string[];
  adversaReferences: string[];
}

/** Top-level JSON report structure. */
interface AuditReport {
  tool: string;
  version: string;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
    filesScanned: number;
    rulesEvaluated: number;
    scanDurationMs: number;
  };
  findings: AuditFinding[];
  score?: number;
  grade?: string;
}

const DIAGNOSTIC_SOURCE = "AgentAuditKit";

let diagnosticCollection: vscode.DiagnosticCollection;
let outputChannel: vscode.OutputChannel;
let onSaveDisposable: vscode.Disposable | undefined;

/**
 * Map a finding severity string to the corresponding VS Code DiagnosticSeverity.
 *
 * CRITICAL and HIGH map to Error, MEDIUM to Warning, LOW and INFO to Information.
 */
function toVscodeSeverity(
  severity: AuditFinding["severity"]
): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
    case "info":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

/**
 * Run the agent-audit-kit CLI and return parsed findings.
 */
function runScan(workspaceFolder: string, severity: string): Promise<AuditReport | null> {
  return new Promise((resolve) => {
    execFile(
      "agent-audit-kit",
      ["scan", workspaceFolder, "--format", "json", "--severity", severity],
      { timeout: 60_000, maxBuffer: 5 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (stderr) {
          outputChannel.appendLine(`[stderr] ${stderr}`);
        }

        // The CLI exits with code 1 when findings exceed --fail-on threshold,
        // which is not an error for our purposes. We only care about the JSON.
        if (error && !stdout.trim()) {
          outputChannel.appendLine(
            `Scan failed: ${error.message}`
          );
          resolve(null);
          return;
        }

        try {
          const report: AuditReport = JSON.parse(stdout);
          resolve(report);
        } catch (parseError) {
          outputChannel.appendLine(
            `Failed to parse scan output: ${String(parseError)}`
          );
          outputChannel.appendLine(`Raw output: ${stdout.slice(0, 500)}`);
          resolve(null);
        }
      }
    );
  });
}

/**
 * Convert scan findings into VS Code diagnostics grouped by file URI.
 */
function findingsToDiagnostics(
  findings: AuditFinding[],
  workspaceFolder: string
): Map<string, vscode.Diagnostic[]> {
  const diagnosticMap = new Map<string, vscode.Diagnostic[]>();

  for (const finding of findings) {
    const filePath = path.isAbsolute(finding.filePath)
      ? finding.filePath
      : path.join(workspaceFolder, finding.filePath);

    const line = finding.lineNumber ? finding.lineNumber - 1 : 0;
    const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);

    const message = `[${finding.ruleId}] ${finding.title}\n${finding.description}`;

    const diagnostic = new vscode.Diagnostic(
      range,
      message,
      toVscodeSeverity(finding.severity)
    );
    diagnostic.source = DIAGNOSTIC_SOURCE;
    diagnostic.code = finding.ruleId;

    // Attach remediation as related information if available
    if (finding.remediation) {
      diagnostic.relatedInformation = [
        new vscode.DiagnosticRelatedInformation(
          new vscode.Location(vscode.Uri.file(filePath), range),
          `Remediation: ${finding.remediation}`
        ),
      ];
    }

    const uri = vscode.Uri.file(filePath).toString();
    const existing = diagnosticMap.get(uri) ?? [];
    existing.push(diagnostic);
    diagnosticMap.set(uri, existing);
  }

  return diagnosticMap;
}

/**
 * Execute a full scan and publish diagnostics.
 */
async function scanAndPublishDiagnostics(
  workspaceFolder: string
): Promise<void> {
  const config = vscode.workspace.getConfiguration("agent-audit-kit");
  const enabled = config.get<boolean>("enable", true);

  if (!enabled) {
    diagnosticCollection.clear();
    return;
  }

  const severity = config.get<string>("severity", "low");
  outputChannel.appendLine(
    `Scanning ${workspaceFolder} (min severity: ${severity})...`
  );

  const report = await runScan(workspaceFolder, severity);

  if (!report) {
    return;
  }

  outputChannel.appendLine(
    `Scan complete: ${report.summary.total} finding(s) in ${report.summary.scanDurationMs}ms`
  );

  // Clear previous diagnostics before publishing new ones
  diagnosticCollection.clear();

  const diagnosticMap = findingsToDiagnostics(
    report.findings,
    workspaceFolder
  );

  for (const [uriString, diagnostics] of diagnosticMap) {
    diagnosticCollection.set(vscode.Uri.parse(uriString), diagnostics);
  }
}

/**
 * Code action provider that surfaces remediation suggestions as quick fixes.
 */
class AgentAuditCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== DIAGNOSTIC_SOURCE) {
        continue;
      }

      // Extract remediation from relatedInformation
      const remediation = diagnostic.relatedInformation?.[0]?.message;
      if (!remediation) {
        continue;
      }

      const action = new vscode.CodeAction(
        remediation,
        vscode.CodeActionKind.QuickFix
      );
      action.diagnostics = [diagnostic];
      action.isPreferred = false;

      // Open the AgentAuditKit output channel so the user can see full details
      action.command = {
        title: "Show AgentAuditKit Output",
        command: "agent-audit-kit.showOutput",
      };

      actions.push(action);
    }

    return actions;
  }
}

/**
 * Extension entry point.
 */
export function activate(context: vscode.ExtensionContext): void {
  outputChannel = vscode.window.createOutputChannel("AgentAuditKit");
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("agent-audit-kit");

  context.subscriptions.push(outputChannel);
  context.subscriptions.push(diagnosticCollection);

  // Register the command to show the output channel
  const showOutputCommand = vscode.commands.registerCommand(
    "agent-audit-kit.showOutput",
    () => {
      outputChannel.show(true);
    }
  );
  context.subscriptions.push(showOutputCommand);

  // Register code action provider for all supported languages
  const codeActionProvider = vscode.languages.registerCodeActionsProvider(
    [
      { language: "json", scheme: "file" },
      { language: "yaml", scheme: "file" },
      { language: "jsonc", scheme: "file" },
    ],
    new AgentAuditCodeActionProvider(),
    {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }
  );
  context.subscriptions.push(codeActionProvider);

  // Register manual scan command
  const scanCommand = vscode.commands.registerCommand(
    "agent-audit-kit.scan",
    async () => {
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder) {
        vscode.window.showWarningMessage(
          "AgentAuditKit: No workspace folder open."
        );
        return;
      }
      await scanAndPublishDiagnostics(folder.uri.fsPath);
    }
  );
  context.subscriptions.push(scanCommand);

  // Auto-scan on file save
  onSaveDisposable = vscode.workspace.onDidSaveTextDocument(
    async (document: vscode.TextDocument) => {
      const config = vscode.workspace.getConfiguration("agent-audit-kit");
      const autoScan = config.get<boolean>("autoScanOnSave", true);

      if (!autoScan) {
        return;
      }

      const supportedLanguages = ["json", "yaml", "jsonc"];
      if (!supportedLanguages.includes(document.languageId)) {
        return;
      }

      const folder = vscode.workspace.getWorkspaceFolder(document.uri);
      if (!folder) {
        return;
      }

      await scanAndPublishDiagnostics(folder.uri.fsPath);
    }
  );
  context.subscriptions.push(onSaveDisposable);

  // Run initial scan if a workspace is open
  const initialFolder = vscode.workspace.workspaceFolders?.[0];
  if (initialFolder) {
    scanAndPublishDiagnostics(initialFolder.uri.fsPath);
  }

  outputChannel.appendLine("AgentAuditKit extension activated.");
}

/**
 * Extension teardown.
 */
export function deactivate(): void {
  diagnosticCollection?.clear();
  diagnosticCollection?.dispose();
  onSaveDisposable?.dispose();
  outputChannel?.dispose();
}
