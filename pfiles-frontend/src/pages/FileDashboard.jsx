import { useEffect, useState } from "react";
import axios from "axios";

function FileDashboard() {
  const [files, setFiles] = useState([]);
  const [file, setFile] = useState(null);

  // Fetch files from backend
  useEffect(() => {
    const fetchFiles = async () => {
      try {
        const token = localStorage.getItem("jwt");
        const response = await axios.get("https://pfiles.onrender.com/files", {
          headers: { Authorization: `Bearer ${token}` },
        });

        setFiles(response.data);
      } catch (error) {
        console.error("Error fetching files:", error);
      }
    };

    fetchFiles();
  }, []);

  // Upload a file
  const handleUpload = async () => {
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    try {
      const token = localStorage.getItem("jwt");
      await axios.post("https://pfiles.onrender.com/upload", formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "multipart/form-data",
        },
      });

      alert("File uploaded successfully!");
      window.location.reload(); // Refresh files list
    } catch (error) {
      console.error("File upload failed:", error);
    }
  };

  return (
    <div>
      <h2>File Dashboard</h2>

      {/* File Upload */}
      <input type="file" onChange={(e) => setFile(e.target.files[0])} />
      <button onClick={handleUpload}>Upload File</button>

      {/* List of Files */}
      <h3>Uploaded Files:</h3>
      <ul>
        {files.map((file) => (
          <li key={file.id}>
            {file.name} - <button>Download</button> <button>Delete</button>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default FileDashboard;

/** Explanation
✅ Fetches files from /files and displays them.
✅ Allows users to select & upload files to /upload.
✅ Shows uploaded files & buttons for future actions (Download, Delete).
✅ Refreshes page after upload. */
