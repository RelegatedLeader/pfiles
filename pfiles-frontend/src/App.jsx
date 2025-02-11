import { useEffect } from "react";
import "./App.css";
import AppRoutes from "./routes/routes.jsx";

function App() {
  useEffect(() => {
    console.log("✅ App Component Loaded!");
  }, []);

  return (
    <div>
      <AppRoutes />
    </div>
  );
}

export default App;
