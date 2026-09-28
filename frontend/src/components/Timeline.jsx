function fmtTimeRange(range) {
  // report/data gives "YYYY-MM-DD HH:MM:SS - YYYY-MM-DD HH:MM:SS"; show just the
  // times if both sides share the same date, to keep it compact.
  const [start, end] = range.split(" - ");
  if (!end) return start;
  const [startDate, startTime] = start.split(" ");
  const [endDate, endTime] = end.split(" ");
  if (startDate === endDate) return `${startTime} - ${endTime}`;
  return `${start} → ${end}`;
}

export default function Timeline({ steps }) {
  if (!steps || steps.length === 0) {
    return <p className="text-faint">No timeline available.</p>;
  }

  return (
    <div className="timeline">
      {steps.map((step, i) => (
        <div className="timeline-step" key={step.step}>
          <div className="timeline-marker">
            <div className="timeline-dot" />
            {i < steps.length - 1 && <div className="timeline-line" />}
          </div>
          <div className="timeline-content">
            <div className="timeline-phase">
              Step {step.step}: {step.phase}
            </div>
            <div className="timeline-time">{fmtTimeRange(step.time_range)}</div>
            <div className="timeline-desc">{step.description}</div>
            {step.gap_note && <div className="timeline-gap">⚠ {step.gap_note}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}
