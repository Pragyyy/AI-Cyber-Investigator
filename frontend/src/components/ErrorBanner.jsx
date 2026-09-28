export default function ErrorBanner({ message, onRetry }) {
  if (!message) return null;
  return (
    <div className="error-banner">
      <span>⚠</span>
      <div style={{ flex: 1 }}>
        <div>{message}</div>
        {onRetry && (
          <button className="btn btn-small" style={{ marginTop: 8 }} onClick={onRetry}>
            Retry
          </button>
        )}
      </div>
    </div>
  );
}
