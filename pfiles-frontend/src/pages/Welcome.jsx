import { Link } from "react-router-dom";

function Welcome() {
  return (
    <div style={{ textAlign: "center", marginTop: "50px" }}>
      <h1>Welcome to PFiles</h1>
      <p>Your file management system.</p>
      <Link to="/login">
        <button style={{ padding: "10px 20px", fontSize: "16px" }}>
          Go to Login
        </button>
      </Link>
    </div>
  );
}

export default Welcome;
