import { useNavigate, useParams } from "react-router-dom";
import SeverityBadge from "./SeverityBadge.jsx";

function fmtTime(iso) {
  if (!iso) return "-";
  return iso.replace("T", " ").slice(0, 19);
}

export default function IncidentTable({ incidents }) {
  const navigate = useNavigate();
  const { uploadId } = useParams();

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Incident</th>
            <th>Type</th>
            <th>Severity</th>
            <th>Source IP</th>
            <th>Host</th>
            <th>Detected</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {incidents.length === 0 && (
            <tr className="empty-row">
              <td colSpan={7}>No incidents detected in this dataset.</td>
            </tr>
          )}
          {incidents.map((inc) => (
            <tr
              key={inc.incident_id}
              className="clickable"
              onClick={() => navigate(`/uploads/${uploadId}/incidents/${inc.incident_id}`)}
            >
              <td className="mono">{inc.incident_id}</td>
              <td>{inc.title}</td>
              <td>
                <SeverityBadge severity={inc.severity} />
              </td>
              <td className="mono">{inc.source_ips.join(", ") || "-"}</td>
              <td>{inc.hostnames.join(", ") || "-"}</td>
              <td className="text-dim">{fmtTime(inc.first_seen)}</td>
              <td className="text-dim">{inc.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
