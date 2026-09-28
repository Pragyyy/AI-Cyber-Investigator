export default function RagSourcesList({ sources }) {
  if (!sources || sources.length === 0) {
    return <p className="text-faint">No knowledge-base sources were retrieved.</p>;
  }
  return (
    <ul className="source-list">
      {sources.map((s, i) => (
        <li key={i}>
          {s.title}
          <div className="source-file">{s.source}</div>
        </li>
      ))}
    </ul>
  );
}
