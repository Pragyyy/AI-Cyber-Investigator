import { Routes, Route, Link, useNavigate } from "react-router-dom";
import Header from "./components/Header.jsx";
import Landing from "./pages/Landing.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import IncidentDetail from "./pages/IncidentDetail.jsx";

export default function App() {
  const navigate = useNavigate();

  return (
    <>
      <Header onSwitchDataset={() => navigate("/")} />
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/uploads/:uploadId" element={<Dashboard />} />
        <Route
          path="/uploads/:uploadId/incidents/:incidentId"
          element={<IncidentDetail />}
        />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </>
  );
}

function NotFound() {
  return (
    <div className="container">
      <div className="panel">
        <p>Page not found. <Link to="/">Go home</Link>.</p>
      </div>
    </div>
  );
}
