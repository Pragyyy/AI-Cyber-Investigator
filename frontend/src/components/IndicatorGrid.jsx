const LABELS = {
  source_ips: "Source IP(s)",
  destination_ips: "Destination IP(s)",
  usernames: "Username(s)",
  hostnames: "Hostname(s)",
  processes: "Process(es)",
  file_hashes: "File hash(es)",
  destination_ports: "Destination port(s)",
};

export default function IndicatorGrid({ indicators }) {
  return (
    <dl className="indicator-grid">
      {Object.entries(LABELS).map(([key, label]) => {
        const values = indicators[key] || [];
        return (
          <div key={key} style={{ display: "contents" }}>
            <dt>{label}</dt>
            <dd>{values.length > 0 ? values.join(", ") : "none observed"}</dd>
          </div>
        );
      })}
    </dl>
  );
}
