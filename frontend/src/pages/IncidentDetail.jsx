import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  downloadReport,
  getEvidence,
  getIncident,
  getReportDataIfAvailable,
  runInvestigation,
} from "../api.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import EvidenceList from "../components/EvidenceList.jsx";
import IndicatorGrid from "../components/IndicatorGrid.jsx";
import Timeline from "../components/Timeline.jsx";
import MitreTable from "../components/MitreTable.jsx";
import RagSourcesList from "../components/RagSourcesList.jsx";
import RecommendedActionsList from "../components/RecommendedActionsList.jsx";
import GeneratedByBadge from "../components/GeneratedByBadge.jsx";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorBanner from "../components/ErrorBanner.jsx";
import InfoBanner from "../components/InfoBanner.jsx";

function fmtTime(iso) {
  if (!iso) return "-";
  return iso.replace("T", " ").slice(0, 19);
}

export default function IncidentDetail() {
  const { uploadId, incidentId } = useParams();

  const [incident, setIncident] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const [reportData, setReportData] = useState(null);
  const [loadError, setLoadError] = useState(null);

  const [investigating, setInvestigating] = useState(false);
  const [investigateError, setInvestigateError] = useState(null);

  const [downloadingReport, setDownloadingReport] = useState(false);
  const [reportError, setReportError] = useState(null);

  function load() {
    setLoadError(null);
    setIncident(null);
    setEvidence(null);
    setReportData(null);
    Promise.all([
      getIncident(uploadId, incidentId),
      getEvidence(uploadId, incidentId),
      getReportDataIfAvailable(uploadId, incidentId),
    ])
      .then(([incidentInfo, evidenceInfo, report]) => {
        setIncident(incidentInfo);
        setEvidence(evidenceInfo);
        setReportData(report);
      })
      .catch((err) => setLoadError(err.message));
  }

  useEffect(() => {
    load();
  }, [uploadId, incidentId]);

  async function handleInvestigate(refresh) {
    setInvestigating(true);
    setInvestigateError(null);
    try {
      await runInvestigation(uploadId, incidentId, refresh);
      const report = await getReportDataIfAvailable(uploadId, incidentId);
      setReportData(report);
    } catch (err) {
      setInvestigateError(err.message);
    } finally {
      setInvestigating(false);
    }
  }

  async function handleDownloadReport() {
    setDownloadingReport(true);
    setReportError(null);
    try {
      await downloadReport(uploadId, incidentId);
    } catch (err) {
      setReportError(err.message);
    } finally {
      setDownloadingReport(false);
    }
  }

  if (loadError) {
    return (
      <div className="container">
        <ErrorBanner message={loadError} onRetry={load} />
      </div>
    );
  }

  if (!incident || !evidence) {
    return <LoadingSpinner label="Loading incident..." />;
  }

  return (
    <div className="container">
      <div className="flex-between">
        <div>
          <h1 className="page-title">
            {incident.incident_id} — {incident.title}
          </h1>
          <p className="page-subtitle mb-0">
            Detected {fmtTime(incident.first_seen)} · Last activity {fmtTime(incident.last_seen)}
          </p>
        </div>
        <SeverityBadge severity={incident.severity} />
      </div>

      <div className="section panel">
        <div className="indicator-grid">
          <dt>Status</dt>
          <dd style={{ fontFamily: "inherit", fontSize: 13 }}>{incident.status}</dd>
          <dt>Username(s)</dt>
          <dd>{incident.usernames.join(", ") || "n/a"}</dd>
          <dt>Hostname(s)</dt>
          <dd>{incident.hostnames.join(", ") || "n/a"}</dd>
          <dt>Source IP(s)</dt>
          <dd>{incident.source_ips.join(", ") || "n/a"}</dd>
          <dt>Destination IP(s)</dt>
          <dd>{incident.destination_ips.join(", ") || "n/a"}</dd>
          <dt>Rules fired</dt>
          <dd style={{ fontFamily: "inherit", fontSize: 13 }}>{incident.rules.join(", ")}</dd>
          <dt>Event count</dt>
          <dd style={{ fontFamily: "inherit", fontSize: 13 }}>{incident.event_count}</dd>
        </div>
      </div>

      <div className="section">
        <h2 className="section-title">Evidence</h2>
        <div className="panel">
          <EvidenceList items={evidence.evidence_items} />
        </div>
        <div className="panel" style={{ marginTop: 12 }}>
          <h3 style={{ fontSize: 13, marginTop: 0 }}>Indicators of Compromise</h3>
          <IndicatorGrid indicators={evidence.indicators} />
        </div>
      </div>

      <div className="section">
        <div className="flex-between">
          <h2 className="section-title" style={{ flex: 1 }}>
            AI Investigation
          </h2>
          {reportData && (
            <button
              className="btn btn-small"
              disabled={investigating}
              onClick={() => handleInvestigate(true)}
            >
              {investigating ? <span className="spinner" /> : "↻"} Re-run
            </button>
          )}
        </div>

        <ErrorBanner message={investigateError} />

        {!reportData && !investigating && (
          <div className="panel" style={{ textAlign: "center", padding: "32px 20px" }}>
            <p className="text-dim">
              This incident has not been investigated yet. Running the multi-agent
              workflow will analyze the evidence, retrieve relevant MITRE ATT&amp;CK
              techniques, and build an attack timeline.
            </p>
            <button className="btn btn-primary" onClick={() => handleInvestigate(false)}>
              ▶ Investigate
            </button>
          </div>
        )}

        {investigating && <LoadingSpinner label="Running multi-agent investigation..." />}

        {reportData && !investigating && (
          <>
            <div className="panel">
              <div className="narrative-label">Executive summary</div>
              <p className="narrative-block">{reportData.executive_summary}</p>

              <div className="narrative-label">Initial hypothesis</div>
              <p className="narrative-block">
                {reportData.initial_hypothesis}{" "}
                <span className="text-faint">
                  (confidence: {reportData.detection_confidence})
                </span>
              </p>

              <div className="narrative-label">Recommended priority</div>
              <SeverityBadge severity={reportData.recommended_priority?.toUpperCase()} />
            </div>

            <div className="panel" style={{ marginTop: 16 }}>
              <h3 style={{ fontSize: 13, marginTop: 0 }}>Incident Timeline</h3>
              <Timeline steps={reportData.timeline} />
            </div>

            <div className="panel" style={{ marginTop: 16 }}>
              <div className="narrative-label" style={{ marginTop: 0 }}>Attack sequence</div>
              <p className="narrative-block">{reportData.attack_sequence_narrative}</p>
              <div className="narrative-label">Affected scope</div>
              <p className="narrative-block">{reportData.affected_scope}</p>
              <div className="narrative-label">Gaps and uncertainty</div>
              <p className="narrative-block">{reportData.gaps_and_uncertainty}</p>
            </div>

            <div style={{ marginTop: 16 }}>
              <h3 style={{ fontSize: 13 }}>MITRE ATT&amp;CK Mapping</h3>
              <MitreTable techniques={reportData.mitre_techniques} />
            </div>

            <div className="panel" style={{ marginTop: 16 }}>
              <h3 style={{ fontSize: 13, marginTop: 0 }}>RAG Sources</h3>
              <RagSourcesList sources={reportData.rag_sources} />
            </div>

            <div className="panel" style={{ marginTop: 16 }}>
              <h3 style={{ fontSize: 13, marginTop: 0 }}>Recommended Actions</h3>
              <RecommendedActionsList actions={reportData.recommended_actions} />
            </div>

            <div className="trace-strip">
              {reportData.agent_trace.map((t) => (
                <GeneratedByBadge key={t.agent} generatedBy={t.generated_by} />
              ))}
              <span className="text-faint" style={{ fontSize: 11, marginLeft: 6 }}>
                provider: {reportData.llm_provider} · graph: {reportData.graph_backend}
              </span>
            </div>
          </>
        )}
      </div>

      <div className="section">
        <h2 className="section-title">Report</h2>
        <ErrorBanner message={reportError} />
        {!reportData ? (
          <InfoBanner>Run the investigation above before generating a report.</InfoBanner>
        ) : (
          <button
            className="btn btn-primary"
            disabled={downloadingReport}
            onClick={handleDownloadReport}
          >
            {downloadingReport ? <span className="spinner" /> : "⬇"} Generate Report (PDF)
          </button>
        )}
      </div>
    </div>
  );
}
