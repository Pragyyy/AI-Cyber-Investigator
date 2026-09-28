export default function EvidenceList({ items }) {
  if (!items || items.length === 0) {
    return <p className="text-faint">No evidence items were extracted for this incident.</p>;
  }
  return (
    <div>
      {items.map((item) => (
        <div className="evidence-item" key={item.evidence_id}>
          <span className="evidence-id">{item.evidence_id}</span>
          <span>
            <span className="evidence-category">[{item.category}]</span>
            {item.statement}
          </span>
        </div>
      ))}
    </div>
  );
}
