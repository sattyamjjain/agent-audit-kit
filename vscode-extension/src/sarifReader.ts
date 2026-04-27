/**
 * SARIF reader — surfaces inline diagnostics + rule-doc hovers from the
 * SARIF file the AAK CLI / GitHub Action writes. Pairs with extension.ts
 * (which already runs the JSON scan on save) so users can either:
 *
 *   - Edit a config file (extension runs scan on save → diagnostics)
 *   - Open a SARIF file (this reader surfaces the same diagnostics)
 *
 * Scaffolded for v0.3.8. Full marketplace publish queues for v0.4.0.
 */

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";

interface SarifResult {
  ruleId: string;
  message: { text?: string };
  level?: "error" | "warning" | "note" | "none";
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri?: string };
      region?: { startLine?: number; startColumn?: number };
    };
  }>;
  properties?: { aak_diff_state?: string; "security-severity"?: string };
}

interface SarifRun {
  results?: SarifResult[];
  tool?: { driver?: { rules?: Array<{ id: string; shortDescription?: { text?: string }; help?: { text?: string; markdown?: string } }> } };
}

interface Sarif {
  runs?: SarifRun[];
}

const DIAG_COLLECTION_NAME = "agent-audit-kit-sarif";

function severityFromResult(result: SarifResult): vscode.DiagnosticSeverity {
  const sev = result.properties?.["security-severity"];
  if (sev) {
    const score = parseFloat(sev);
    if (score >= 9.0) return vscode.DiagnosticSeverity.Error;
    if (score >= 7.0) return vscode.DiagnosticSeverity.Warning;
    if (score >= 4.0) return vscode.DiagnosticSeverity.Information;
    return vscode.DiagnosticSeverity.Hint;
  }
  switch (result.level) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "warning":
      return vscode.DiagnosticSeverity.Warning;
    case "note":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
}

export function loadSarif(sarifPath: string): Sarif {
  const text = fs.readFileSync(sarifPath, "utf-8");
  return JSON.parse(text) as Sarif;
}

export function applySarifToDiagnostics(
  sarif: Sarif,
  workspaceRoot: string,
  collection: vscode.DiagnosticCollection,
): void {
  collection.clear();
  const byUri = new Map<string, vscode.Diagnostic[]>();
  for (const run of sarif.runs ?? []) {
    for (const result of run.results ?? []) {
      const loc = result.locations?.[0]?.physicalLocation;
      if (!loc?.artifactLocation?.uri) continue;
      const fileUri = path.isAbsolute(loc.artifactLocation.uri)
        ? loc.artifactLocation.uri
        : path.join(workspaceRoot, loc.artifactLocation.uri);
      const startLine = (loc.region?.startLine ?? 1) - 1;
      const startCol = (loc.region?.startColumn ?? 1) - 1;
      const range = new vscode.Range(startLine, startCol, startLine, startCol + 80);
      const message = `[${result.ruleId}] ${result.message?.text ?? ""}`;
      const diag = new vscode.Diagnostic(range, message, severityFromResult(result));
      diag.code = result.ruleId;
      diag.source = "agent-audit-kit";
      const list = byUri.get(fileUri) ?? [];
      list.push(diag);
      byUri.set(fileUri, list);
    }
  }
  for (const [uri, diags] of byUri) {
    collection.set(vscode.Uri.file(uri), diags);
  }
}

export function registerSarifCommands(context: vscode.ExtensionContext): void {
  const collection = vscode.languages.createDiagnosticCollection(DIAG_COLLECTION_NAME);
  context.subscriptions.push(collection);

  context.subscriptions.push(
    vscode.commands.registerCommand("agent-audit-kit.loadSarif", async () => {
      const picked = await vscode.window.showOpenDialog({
        canSelectMany: false,
        filters: { SARIF: ["sarif", "json"] },
      });
      if (!picked || picked.length === 0) return;
      const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "";
      try {
        const sarif = loadSarif(picked[0].fsPath);
        applySarifToDiagnostics(sarif, root, collection);
        vscode.window.showInformationMessage(
          `agent-audit-kit: loaded SARIF, surfaced ${countResults(sarif)} finding(s).`,
        );
      } catch (e) {
        vscode.window.showErrorMessage(`agent-audit-kit: failed to load SARIF — ${(e as Error).message}`);
      }
    }),
  );
}

function countResults(sarif: Sarif): number {
  let n = 0;
  for (const run of sarif.runs ?? []) n += (run.results ?? []).length;
  return n;
}
