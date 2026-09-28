export default function StatCard({ value, label, accent }) {
  return (
    <div className={`stat-card${accent ? ` accent-${accent}` : ""}`}>
      <div className="value">{value}</div>
      <div className="label">{label}</div>
    </div>
  );
}
