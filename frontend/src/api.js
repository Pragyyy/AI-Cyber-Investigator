// Thin wrapper around the backend API. Every function returns parsed JSON (or, for
// the PDF download, a Blob) and throws an Error with a readable message on failure -
// components catch that and show it via <ErrorBanner />.

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

async function request(path, options = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      ...(options.body && !(options.body instanceof FormData)
        ? { "Content-Type": "application/json" }
        : {}),
      ...options.headers,
    },
  });

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {
      // response wasn't JSON - keep the status text
    }
    const error = new Error(detail);
    error.status = res.status;
    throw error;
  }

  if (res.status === 204) return null;
  return res.json();
}

// ---- Uploads ---------------------------------------------------------------
export function listUploads() {
  return request("/api/uploads");
}

export function getUpload(uploadId) {
  return request(`/api/uploads/${uploadId}`);
}

export function uploadLogs(file) {
  const form = new FormData();
  form.append("file", file);
  return request("/api/uploads", { method: "POST", body: form });
}

export function deleteUpload(uploadId) {
  return request(`/api/uploads/${uploadId}`, { method: "DELETE" });
}

// ---- Sample datasets ---------------------------------------------------------
export function listSamples() {
  return request("/api/samples");
}

export function loadSample(name) {
  return request(`/api/samples/${encodeURIComponent(name)}/load`, { method: "POST" });
}

// ---- Dashboard stats & incidents ---------------------------------------------
export function getStats(uploadId) {
  return request(`/api/uploads/${uploadId}/stats`);
}

export function listIncidents(uploadId) {
  return request(`/api/uploads/${uploadId}/incidents`);
}

export function getIncident(uploadId, incidentId) {
  return request(`/api/uploads/${uploadId}/incidents/${incidentId}`);
}

export function getEvents(uploadId, params = {}) {
  const query = new URLSearchParams(params).toString();
  return request(`/api/uploads/${uploadId}/events${query ? `?${query}` : ""}`);
}

// ---- Evidence, RAG, investigation ---------------------------------------------
export function getEvidence(uploadId, incidentId) {
  return request(`/api/uploads/${uploadId}/incidents/${incidentId}/evidence`);
}

export function runInvestigation(uploadId, incidentId, refresh = false) {
  const query = refresh ? "?refresh=true" : "";
  return request(`/api/uploads/${uploadId}/incidents/${incidentId}/investigate${query}`, {
    method: "POST",
  });
}

// Fetches the normalized report data (same structure the PDF is built from - see
// backend/app/report/builder.py) without generating a PDF. Returns null (not an
// error) if no investigation has been run yet, so callers can render an "Investigate"
// call-to-action instead of an error banner.
export async function getReportDataIfAvailable(uploadId, incidentId) {
  try {
    return await request(`/api/uploads/${uploadId}/incidents/${incidentId}/report/data`);
  } catch (err) {
    if (err.status === 409) return null;
    throw err;
  }
}

// ---- Report --------------------------------------------------------------------
export async function downloadReport(uploadId, incidentId) {
  const res = await fetch(
    `${BASE_URL}/api/uploads/${uploadId}/incidents/${incidentId}/report`,
    { method: "POST" }
  );
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {
      // not JSON
    }
    const error = new Error(detail);
    error.status = res.status;
    throw error;
  }
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${incidentId}_report.pdf`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

// ---- RAG status (used to show a helpful message if the index isn't built yet) ----
export function getRagStatus() {
  return request("/api/rag/status");
}
