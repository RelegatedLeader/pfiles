import { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";

function Login() {
  const [hash, setHash] = useState("");
  const navigate = useNavigate();
  const handleLogin = async () => {
    try {
      console.log("🔑 Attempting Login with Hash:", hash);

      const response = await axios.post(
        "https://pfiles.onrender.com/login",
        { hash_code: hash },
        {
          headers: { "Content-Type": "application/json" },
          withCredentials: true, // REQUIRED for CORS & authentication
        }
      );

      console.log("✅ Server Response:", response.data);

      const { accessToken } = response.data;
      if (!accessToken) {
        alert("Login failed. No token received.");
        return;
      }

      localStorage.setItem("jwt", accessToken);
      alert("Login successful! Redirecting...");
      navigate("/dashboard");
    } catch (error) {
      console.error("❌ Login Error:", error.response?.data || error.message);
      alert("Login failed. Check your hash.");
    }
  };

  return (
    <div>
      <h2>Login</h2>
      <input
        type="text"
        placeholder="Enter your authentication hash"
        value={hash}
        onChange={(e) => setHash(e.target.value)}
      />
      <button onClick={handleLogin}>Login</button>
    </div>
  );
}

export default Login;
