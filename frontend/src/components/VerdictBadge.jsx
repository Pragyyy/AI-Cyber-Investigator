const LABELS = {
  supported: "Supported",
  potential: "Potential",
  weak: "Weak",
};

export default function VerdictBadge({ verdict }) {
  if (!verdict) return null;
  return (
    <span className={`badge-verdict badge-verdict-${verdict}`}>
      {LABELS[verdict] || verdict}
    </span>
  );
}
