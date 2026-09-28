export default function RecommendedActionsList({ actions }) {
  if (!actions || actions.length === 0) return null;
  return (
    <ol className="actions-list">
      {actions.map((a, i) => (
        <li key={i}>{a}</li>
      ))}
    </ol>
  );
}
