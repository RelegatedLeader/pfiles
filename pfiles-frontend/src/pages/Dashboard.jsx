import { useEffect, useState } from "react";
import axios from "axios";

function Dashboard() {
  const [files, setFiles] = useState([]);

  useEffect(() => {
    const fetchFiles = async () => {
      try {
        const token = localStorage.getItem("jwt"); // Get JWT from local storage
        const response = await axios.get("https://pfiles.onrender.com/files", {
          headers: { Authorization: `Bearer ${token}` }, // Send JWT in request
        });

        setFiles(response.data); // Store retrieved files in state
      } catch (error) {
        console.error("Error fetching files:", error);
      }
    };

    fetchFiles(); // Call function when component mounts
  }, []);

  return (
    <div>
      <h2>Dashboard</h2>
      <h3>Your Files:</h3>
      <ul>
        {files.map((file) => (
          <li key={file.id}>{file.name}</li>
        ))}
      </ul>
    </div>
  );
}

export default Dashboard;

//not being used as of right now and asked to be deleted but i am not sure if to
//delete it or not
