import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import UploadPanel from "../components/UploadPanel.jsx";
import InfoBanner from "../components/InfoBanner.jsx";
import { getRagStatus } from "../api.js";

export default function Landing() {
  const navigate = useNavigate();
  const [ragWarning, setRagWarning] = useState(null);

  useEffect(() => {
    getRagStatus()
      .then((status) => {
        if (!status.built) {
          setRagWarning(
            "The knowledge base index hasn't been built yet. You can still upload " +
            "logs and browse incidents, but running Investigate will fail until the " +
            "backend builds it (this normally happens automatically on startup - " +
            "see the backend README if it doesn't)."
          );
        }
      })
      .catch(() => {
        // Backend may not be reachable yet - the upload attempt below will surface
        // that error more usefully than a preflight check failure would here.
      });
  }, []);

  return (
    <div className="container landing">
      <div className="landing-card">
        <h1>AI Cybersecurity Investigator</h1>
        <p>
          Upload security logs (CSV/JSON) or load one of the bundled sample scenarios
          to start an automated investigation.
        </p>
        {ragWarning && <InfoBanner>{ragWarning}</InfoBanner>}
        <UploadPanel onUploaded={(upload) => navigate(`/uploads/${upload.upload_id}`)} />
      </div>
    </div>
  );
}
