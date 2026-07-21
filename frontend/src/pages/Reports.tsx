import { useState } from "react";
import { Download, FileText, FileDown } from "lucide-react";
import { AppShell } from "../components/layout/AppShell";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { downloadIncidentsPdf, fetchIncidentStats, fetchIncidents } from "../lib/api";

function toCsv(rows: Record<string, unknown>[]): string {
  if (rows.length === 0) return "";
  const headers = Object.keys(rows[0]);
  const escape = (v: unknown) => {
    const s = v === null || v === undefined ? "" : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [headers.join(","), ...rows.map((r) => headers.map((h) => escape(r[h])).join(","))];
  return lines.join("\n");
}

function downloadFile(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export default function Reports() {
  const [exporting, setExporting] = useState<string | null>(null);

  async function exportIncidentsCsv() {
    setExporting("csv");
    try {
      const incidents = await fetchIncidents({ limit: 1000 });
      const rows = incidents.map((i) => ({
        id: i.id,
        timestamp: new Date(i.timestamp * 1000).toISOString(),
        attack_type: i.attack_type,
        category: i.category,
        severity: i.severity,
        confidence: i.confidence,
        source_ip: i.source_ip,
        destination_ip: i.destination_ip ?? "",
        destination_port: i.destination_port ?? "",
        risk_score: i.risk_score,
        status: i.status,
        mitre_technique_id: i.mitre_technique_id ?? "",
        explanation: i.explanation,
      }));
      downloadFile(toCsv(rows), `alertiq-incidents-${Date.now()}.csv`, "text/csv");
    } finally {
      setExporting(null);
    }
  }

  async function exportSummaryJson() {
    setExporting("summary");
    try {
      const stats = await fetchIncidentStats(2592000);
      downloadFile(JSON.stringify(stats, null, 2), `alertiq-summary-${Date.now()}.json`, "application/json");
    } finally {
      setExporting(null);
    }
  }

  async function exportPdf() {
    setExporting("pdf");
    try {
      await downloadIncidentsPdf(2592000);
    } finally {
      setExporting(null);
    }
  }

  return (
    <AppShell title="Reports">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Incident Export (CSV)</CardTitle>
          </CardHeader>
          <CardBody>
            <p className="mb-4 text-sm text-ink-500">
              Export up to the last 1000 incidents with full details for spreadsheet analysis or compliance
              records.
            </p>
            <Button onClick={exportIncidentsCsv} disabled={exporting === "csv"}>
              <Download size={14} /> {exporting === "csv" ? "Exporting…" : "Export Incidents CSV"}
            </Button>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>30-Day Summary (JSON)</CardTitle>
          </CardHeader>
          <CardBody>
            <p className="mb-4 text-sm text-ink-500">
              Export the aggregated incident summary (by category, severity, and top attackers) for the last 30
              days.
            </p>
            <Button onClick={exportSummaryJson} disabled={exporting === "summary"} variant="secondary">
              <Download size={14} /> {exporting === "summary" ? "Exporting…" : "Export Summary JSON"}
            </Button>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Branded Incident Report (PDF)</CardTitle>
          </CardHeader>
          <CardBody>
            <p className="mb-4 text-sm text-ink-500">
              Generate a print-ready PDF covering the last 30 days: summary counts, category/severity breakdown,
              top attackers, and the full incident table.
            </p>
            <Button onClick={exportPdf} disabled={exporting === "pdf"} variant="secondary">
              <FileDown size={14} /> {exporting === "pdf" ? "Generating…" : "Export PDF Report"}
            </Button>
          </CardBody>
        </Card>

        <Card className="md:col-span-2">
          <CardBody className="flex items-center gap-4">
            <div className="rounded-lg bg-base-700/60 p-2.5 text-ink-500">
              <FileText size={18} strokeWidth={1.75} />
            </div>
            <div>
              <p className="text-sm font-medium text-ink-100">Automated report delivery</p>
              <p className="text-xs text-ink-500">
                Scheduled/automatic report emailing is not yet built. Configure SMTP settings on the backend
                (see README) to enable per-incident email notifications today.
              </p>
            </div>
          </CardBody>
        </Card>
      </div>
    </AppShell>
  );
}
