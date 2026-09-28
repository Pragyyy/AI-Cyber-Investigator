import { useEffect, useState } from "react";
import { listSamples, loadSample, uploadLogs } from "../api.js";
import ErrorBanner from "./ErrorBanner.jsx";
import LoadingSpinner from "./LoadingSpinner.jsx";

export default function UploadPanel({ onUploaded }) {
  const [samples, setSamples] = useState([]);
  const [selectedSample, setSelectedSample] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    listSamples()
      .then((list) => {
        setSamples(list);
        if (list.length > 0) setSelectedSample(list[0].name);
      })
      .catch((err) => setError(`Could not load sample list: ${err.message}`));
  }, []);

  async function handleFileChange(e) {
    const file = e.target.files?.[0];
    e.target.value = ""; // allow re-selecting the same file later
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const upload = await uploadLogs(file);
      onUploaded(upload);
    } catch (err) {
      setError(`Upload failed: ${err.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function handleLoadSample() {
    if (!selectedSample) return;
    setBusy(true);
    setError(null);
    try {
      const upload = await loadSample(selectedSample);
      onUploaded(upload);
    } catch (err) {
      setError(`Could not load sample: ${err.message}`);
    } finally {
      setBusy(false);
    }
  }

  if (busy) return <LoadingSpinner label="Processing logs..." />;

  return (
    <div>
      <ErrorBanner message={error} />
      <div className="upload-panel">
        <label className="file-input-label">
          <input type="file" accept=".csv,.json,.jsonl,.ndjson" onChange={handleFileChange} />
          📁 Upload security_logs.csv / .json
        </label>

        {samples.length > 0 && (
          <>
            <span className="divider-or">or</span>
            <select value={selectedSample} onChange={(e) => setSelectedSample(e.target.value)}>
              {samples.map((s) => (
                <option key={s.name} value={s.name}>
                  {s.name}
                </option>
              ))}
            </select>
            <button className="btn" onClick={handleLoadSample}>
              Load sample dataset
            </button>
          </>
        )}
      </div>
    </div>
  );
}
