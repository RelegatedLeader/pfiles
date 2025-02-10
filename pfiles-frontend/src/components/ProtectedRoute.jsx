import { Navigate } from "react-router-dom";

function ProtectedRoute({ children }) {
  const token = localStorage.getItem("jwt");

  console.log("🔒 Checking Token for Protected Route:", token);

  return token ? children : <Navigate to="/login" />;
}

export default ProtectedRoute;
