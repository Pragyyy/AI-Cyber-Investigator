import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { deleteUpload, listUploads } from "../api.js";

export default function Header() {
  const navigate = useNavigate();
  const { uploadId } = useParams();
  const [uploads, setUploads] = useState([]);
  const [menuOpen, setMenuOpen] = useState(false);

  function refreshUploads() {
    listUploads()
      .then(setUploads)
      .catch(() => {
        // Header shouldn't block the page over this - the switcher just stays empty.
      });
  }

  useEffect(refreshUploads, [uploadId]);

  async function handleDelete(e, targetId) {
    e.stopPropagation(); // don't also trigger the row's navigate-to-dataset click
    if (!window.confirm("Delete this dataset and all its incidents? This cannot be undone.")) {
      return;
    }
    try {
      await deleteUpload(targetId);
      refreshUploads();
      if (targetId === uploadId) navigate("/");
    } catch (err) {
      window.alert(`Could not delete dataset: ${err.message}`);
    }
  }

  return (
    <header className="app-header">
      <div className="brand" onClick={() => navigate("/")} style={{ cursor: "pointer" }}>
        <span className="dot" />
        AI CYBERSECURITY INVESTIGATOR
      </div>
      <div className="header-actions">
        {uploads.length > 0 && (
          <div style={{ position: "relative" }}>
            <button
              className="btn btn-small"
              onClick={() => setMenuOpen((open) => !open)}
            >
              Switch dataset ▾
            </button>
            {menuOpen && (
              <div
                className="panel"
                style={{
                  position: "absolute",
                  right: 0,
                  top: "calc(100% + 6px)",
                  minWidth: 280,
                  maxHeight: 320,
                  overflowY: "auto",
                  zIndex: 20,
                  padding: 6,
                }}
              >
                {uploads.map((u) => (
                  <div
                    key={u.upload_id}
                    onClick={() => {
                      setMenuOpen(false);
                      navigate(`/uploads/${u.upload_id}`);
                    }}
                    className="switcher-item"
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 8,
                      padding: "8px 10px",
                      borderRadius: 6,
                      cursor: "pointer",
                      background:
                        u.upload_id === uploadId ? "var(--bg-panel-alt)" : "transparent",
                    }}
                  >
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 600 }}>{u.filename}</div>
                      <div className="text-faint" style={{ fontSize: 11 }}>
                        {u.event_count} events · {u.uploaded_at.replace("T", " ").slice(0, 19)}
                      </div>
                    </div>
                    <button
                      className="btn btn-small"
                      title="Delete this dataset"
                      onClick={(e) => handleDelete(e, u.upload_id)}
                      style={{ padding: "3px 8px", flexShrink: 0 }}
                    >
                      ✕
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
        <button className="btn btn-primary btn-small" onClick={() => navigate("/")}>
          + Upload logs
        </button>
      </div>
    </header>
  );
}
