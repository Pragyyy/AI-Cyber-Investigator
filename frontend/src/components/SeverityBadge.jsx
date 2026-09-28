export default function SeverityBadge({ severity }) {
  if (!severity) return null;
  return <span className={`badge badge-${severity}`}>{severity}</span>;
}
