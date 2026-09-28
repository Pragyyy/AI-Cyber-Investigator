import VerdictBadge from "./VerdictBadge.jsx";

export default function MitreTable({ techniques }) {
  if (!techniques || techniques.length === 0) {
    return (
      <p className="text-faint">
        No MITRE ATT&amp;CK techniques met the retrieval confidence threshold for this incident.
      </p>
    );
  }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Technique</th>
            <th>Verdict</th>
            <th>Justification</th>
          </tr>
        </thead>
        <tbody>
          {techniques.map((t) => (
            <tr key={t.technique_id}>
              <td>
                <span className="mono" style={{ fontWeight: 700 }}>
                  {t.technique_id}
                </span>
                <div className="text-dim" style={{ fontSize: 12 }}>
                  {t.technique_name}
                </div>
              </td>
              <td>
                <VerdictBadge verdict={t.verdict} />
              </td>
              <td className="text-dim" style={{ fontSize: 12.5 }}>
                {t.justification}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
