import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { getStats, getUpload, listIncidents } from "../api.js";
import StatCard from "../components/StatCard.jsx";
import SeverityChart from "../components/SeverityChart.jsx";
import IncidentTable from "../components/IncidentTable.jsx";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorBanner from "../components/ErrorBanner.jsx";

export default function Dashboard() {
  const { uploadId } = useParams();
  const [upload, setUpload] = useState(null);
  const [stats, setStats] = useState(null);
  const [incidents, setIncidents] = useState(null);
  const [error, setError] = useState(null);

  function load() {
    setError(null);
    setStats(null);
    setIncidents(null);
    Promise.all([getUpload(uploadId), getStats(uploadId), listIncidents(uploadId)])
      .then(([uploadInfo, statsInfo, incidentList]) => {
        setUpload(uploadInfo);
        setStats(statsInfo);
        setIncidents(incidentList);
      })
      .catch((err) => setError(err.message));
  }

  useEffect(() => {
    load();
  }, [uploadId]);

  if (error) {
    return (
      <div className="container">
        <ErrorBanner message={error} onRetry={load} />
      </div>
    );
  }

  if (!stats || !incidents) {
    return <LoadingSpinner label="Loading dashboard..." />;
  }

  return (
    <div className="container">
      <h1 className="page-title">Dashboard</h1>
      <p className="page-subtitle">
        {upload?.filename} · {upload?.event_count} events · uploaded{" "}
        {upload?.uploaded_at.replace("T", " ").slice(0, 19)}
      </p>

      <div className="stat-grid">
        <StatCard value={stats.total_events} label="Total events" />
        <StatCard value={stats.suspicious_events} label="Suspicious events" />
        <StatCard value={stats.active_incidents} label="Active incidents" />
        <StatCard
          value={stats.high_severity_incidents}
          label="High / critical incidents"
          accent={stats.high_severity_incidents > 0 ? "high" : undefined}
        />
      </div>

      <div className="section">
        <h2 className="section-title">Severity distribution</h2>
        <div className="panel">
          <SeverityChart severityCounts={stats.severity_counts} />
        </div>
      </div>

      <div className="section">
        <h2 className="section-title">Incidents</h2>
        <IncidentTable incidents={incidents} />
      </div>
    </div>
  );
}
