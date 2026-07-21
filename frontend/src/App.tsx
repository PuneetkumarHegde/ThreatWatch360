import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import { ProtectedRoute } from "./components/layout/ProtectedRoute";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import LiveMonitor from "./pages/LiveMonitor";
import Devices from "./pages/Devices";
import DeviceProfile from "./pages/DeviceProfile";
import Threats from "./pages/Threats";
import ThreatMap from "./pages/ThreatMap";
import Investigation from "./pages/Investigation";
import Analytics from "./pages/Analytics";
import Reports from "./pages/Reports";
import SettingsPage from "./pages/Settings";

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/live-monitor" element={<ProtectedRoute><LiveMonitor /></ProtectedRoute>} />
          <Route path="/devices" element={<ProtectedRoute><Devices /></ProtectedRoute>} />
          <Route path="/devices/:mac" element={<ProtectedRoute><DeviceProfile /></ProtectedRoute>} />
          <Route path="/threats" element={<ProtectedRoute><Threats /></ProtectedRoute>} />
          <Route path="/threat-map" element={<ProtectedRoute><ThreatMap /></ProtectedRoute>} />
          <Route path="/threats/:id" element={<ProtectedRoute><Investigation /></ProtectedRoute>} />
          <Route path="/analytics" element={<ProtectedRoute><Analytics /></ProtectedRoute>} />
          <Route path="/reports" element={<ProtectedRoute><Reports /></ProtectedRoute>} />
          <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
