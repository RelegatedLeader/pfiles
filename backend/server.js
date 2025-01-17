const express = require("express");
const { Pool } = require("pg");
const dotenv = require("dotenv");

const crypto = require("crypto"); //hashes it
const nodemailer = require("nodemailer"); //send emails
const jwt = require("jsonwebtoken"); // generates jwt token which is more secure and scalable
const cron = require("node-cron"); // to delete expired tokens on the daily basis
const rateLimit = require("express-rate-limit"); // this is to prvent brute force attacks (e.g repeated login attempts)
const cors = require("cors"); // used to prevent cross-origin attacks where a malicious site tries to access your api
const helmet = require("helmet"); //prevents clickjacking, MIME sniffing , and other attacks
const { body, validationResult } = require("express-validator"); //prevents SQL injection and XXS by cleaning incoming data
const multer = require("multer"); //to upload files securely
const path = require("path"); ///was added with the multer above
const fs = require("fs"); // File system module for deletion

//Clickjacking is a malicious technique where an attacker tricks a user into clicking on something
//  different from what they perceive, potentially
//  revealing confidential information or allowing the attacker to take control of their computer.
//MIME sniffing is a technique used by web browsers to determine the file format of a
//  resource when the MIME type is not explicitly specified or is incorrect, by analyzing the content of the resource.

dotenv.config(); //load environment variables

console.log(process.env);
//console.log("Loaded DB_USER:", process.env.DB_USER);

const app = express();

const port = process.env.PORT || 3000;

//postgreSQL connection setup

app.use(express.json()); // Middleware to parse JSON bodies

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

//lets log them at the start to see if they work
//make sure to leave a placeholder for the refresh token and then replace it with the real one
//after login in
console.log(
  "Loaded JWT_SECRET:",
  process.env.JWT_SECRET ? "✔️ Loaded" : "❌ Missing"
);
console.log(
  "Loaded JWT_REFRESH_SECRET:",
  process.env.JWT_REFRESH_SECRET ? "✔️ Loaded" : "❌ Missing"
);

// Log incoming requests before defining routes
app.use((req, res, next) => {
  console.log(`Received request: ${req.method} ${req.url}`);
  next();
});

app.get("/", (req, res) => {
  res.send("PFiles Backend is running!");
});

app.get("/users", async (req, res) => {
  try {
    const result = await pool.query("Select * from users");
    res.json(result.rows);
    // Sends the rows returned by the database query as a JSON response
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

//req is needed simply because it is part of the signature of the whole function
//it can be used as incoming req from the client (such as the browser, post man etc)
app.get("/hashes", async (req, res) => {
  try {
    const result = await pool.query("Select * from hashes");
    res.json(result.rows);
    // Sends the rows returned by the database query as a JSON response
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

app.get("/ideas", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM ideas WHERE user_id = $1", [
      req.user.user_id,
    ]);
    res.json(result.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

//now to inserting

app.post("/users", async (req, res) => {
  const { email } = req.body; //extract email from the request body

  try {
    const result = await pool.query(
      "INSERT INTO users (email) VALUES ($1) RETURNING *",
      //$1 in the Query: Placeholder for dynamic values (to prevent SQL injection).

      [email]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: err.message }); // Now correctly sends the error message
  }
});

app.post("/hashes", async (req, res) => {
  const { user_id, hash_code } = req.body; // extract data from the request body

  try {
    const result = await pool.query(
      "INSERT INTO hashes (user_id, hash_code) VALUES ($1, $2) RETURNING *",
      [user_id, hash_code] // Fixed: correctly passing values as an array
    );

    res.json(result.rows[0]); // Respond with the newly created hash
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: err.message }); // Send error message in response
  }
});

app.post("/ideas", async (req, res) => {
  const { user_id, title, content, file_path } = req.body; //extract data from the request body

  try {
    const result = await pool.query(
      "INSERT INTO ideas (user_id, title, content, file_path) VALUES ($1, $2,$3, $4) RETURNING *",
      [user_id, title, content, file_path]
    );

    res.json(result.rows[0]); // Respond with the newly created idea
  } catch (err) {
    console.log(err.message);
    res.status(500).send("Server Error");
  }
});

///testing database connection before any routes
pool.query("select now()", (err, res) => {
  if (err) {
    console.error("Database connection error", err.stack);
  } else {
    console.log("Database connected successfully", res.rows[0]);
  }
});

//using the crypto library
async function generateMonthlyHash(user_id) {
  console.log("Inside generateMonthlyHash for user:", user_id); // Debugging
  const hash_code = crypto.randomBytes(16).toString("hex"); // Generate a random 32-character hash

  try {
    console.log("Deleting old expired hashes..."); // Debugging
    await pool.query(
      "DELETE FROM hashes WHERE user_id = $1 AND expires_at < NOW()",
      [user_id]
    );

    console.log("Inserting new hash into database..."); // Debugging
    const result = await pool.query(
      "INSERT INTO hashes (user_id, hash_code, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 month') RETURNING *",
      [user_id, hash_code]
    );

    console.log("New hash stored in database:", result.rows[0]); // Debugging
    return result.rows[0];
  } catch (err) {
    console.error("Error generating hash:", err.message);
    throw err;
  }
}

//email sending function using nodemailer
async function sendHashByEmail(email, hash_code) {
  console.log("Preparing to send email to:", email); // Debugging

  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.error("Missing email credentials in .env file!");
    return;
  }

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your monthly Pfiles Login Hash",
    text: `Your login hash for this month: ${hash_code}\n\nThis hash will expire in one month.`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Hash sent to ${email}`);
  } catch (err) {
    console.error("Error sending email to", email, err);
  }
}

//this is a route to trigger hash generation (it can be autmate it with a cron job later on)
app.post("/generate-hash", async (req, res) => {
  const user_id = 1; // Since there's only one user (you)
  console.log("Generate Hash Route Hit"); // Debugging

  try {
    console.log("Generating new hash for user:", user_id); // Debugging
    const newHash = await generateMonthlyHash(user_id);
    console.log("Generated Hash:", newHash.hash_code); // Debugging

    await sendHashByEmail("frankalfaro105@gmail.com", newHash.hash_code);
    console.log("Email sent successfully"); // Debugging

    return res.json({
      message: "New monthly hash generated and sent to email!",
      hash: newHash,
    });
  } catch (err) {
    console.error("Error in /generate-hash:", err.message); // Debugging
    res.status(500).json({ error: err.message });
  }
});

//this limits request to 100 per 15 minsutes per ip
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, //15 minutes
  max: 5, //limit each ip to 5 login attempts
  message: "Too many login attempts, Please try again later",
  headers: true,
});

// this is the login verification - the user (me) will submit the hash for verification and chekc if its valid
//it is modified to be able to refresh tokens to avoid using frequent logins!
app.post(
  "/login",
  loginLimiter,
  [
    //this is from the express-validator
    body("hash_code")
      .isLength({ min: 32, max: 32 })
      .withMessage("Invalid hash format"),
  ],
  async (req, res) => {
    console.log("Login route hit!"); // Debugging
    console.log("Received hash_code:", req.body.hash_code); // Debugging

    //from express-validator that is used to prevent xxs and SQL injection attacks
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    } //now  requests with invalid hash_code formats will be rejected before reaching the database.

    const { hash_code } = req.body; //gets hash from user input

    try {
      const result = await pool.query(
        "SELECT * FROM hashes WHERE hash_code = $1 AND expires_at > NOW()",
        [hash_code]
      );

      if (result.rows.length === 0) {
        return res.status(401).json({ error: "Invalid or expired hash." });
      }

      const user_id = result.rows[0].user_id;

      // Generate Access Token (Short-lived)
      const accessToken = jwt.sign({ user_id }, process.env.JWT_SECRET, {
        expiresIn: "30d",
      });

      // Generate Refresh Token (Longer-lived)
      const refreshToken = jwt.sign(
        { user_id },
        process.env.JWT_REFRESH_SECRET,
        {
          expiresIn: "60d",
        }
      );

      //users now receive a refresh token that allows them to get a new access token without logging in again

      // Store refresh token in DB
      await pool.query(
        "INSERT INTO refresh_tokens (user_id, token) VALUES ($1, $2)",
        [user_id, refreshToken]
      );

      res.json({ accessToken, refreshToken });
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ error: "Server Error" });
    }
  }
);

//now that we can authenticate a user ^ ... lets ensure that only logged-in users can access certain endpoints
//basically securing protected routes

//was replaced with authenticateToken

/**function authenticateUser(req, res, next) {
  const { hash_code } = req.headers; //read hash from request headers
  if (!hash_code) {
    return res.status(401).json({ error: "Access Denied. No hash Provided" });
  }

  pool
    .query("SELECT * FROM hashes WHERE hash_code = $1 AND expires_at > NOW()", [
      hash_code,
    ])
    .then((result) => {
if (result.rows.length === 0) {
        return res.status(401).json({ error: "Invalid or expired hash" });
      }
      next(); //proceed if valid
    })
    .catch((err) => {
      console.error(err.message);
      res.status(500).json({ error: "Server Error" });
    });
} */

//this is a jwt authentication middleware
// when you log out, the token is revoked and becomes unusable. (the token gets revoked! )

async function authenticateToken(req, res, next) {
  //verifies token first , it prevents unnecessary lookups for valid tokens
  //only queries revoked_tokens if JWT is valid → Faster and more efficient.

  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ error: "Access denied. No token provided." });

  const token = authHeader.split(" ")[1];

  try {
    // Verify JWT first
    //  //this is using the jwt to keep it more secured, it is generated after the confirmation of
    //the email sent hash (double security!) --> this one simply just authenticates the one being used
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Now check if the token is revoked
    const revoked = await pool.query(
      "SELECT * FROM revoked_tokens WHERE token = $1",
      [token]
    );
    if (revoked.rows.length > 0)
      return res.status(403).json({ error: "Token has been revoked." });

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid or expired token." });
  }
}

//blacklisting(implementing token revocation), it fixes the idea of taking the ability of someone being able
//to use a token that has been stolen as they have a time limit , but it rejects them
//database itself will be modified where a new table called revoked_tokens will have those tokens:
/*CREATE TABLE revoked_tokens (
    id SERIAL PRIMARY KEY,
    token TEXT NOT NULL,
    revoked_at TIMESTAMP DEFAULT NOW()
);
 */

//new post method logout to revoke the tokens
app.post("/logout", authenticateToken, async (req, res) => {
  const token = req.headers.authorization.split(" ")[1]; // correct as it needs the spacing - basically extracts
  // Bearer <token> where the space is after Bearer
  try {
    await pool.query("INSERT INTO revoked_tokens (token) VALUES ($1)", [token]);
    res.json({ message: "Logged out successfully." }); //token is revoked
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

//this is for the refresh-token route - creates A refresh token that allows user to stay logged in
//without storing long lived acess tokens that could be stolen! -> they last longer (60 days)
// and if the access token is stolen, the attacker cannot refresh it, making it useless after expiration
// they are stored securely in a database and can be revoked if compromiseed.
//when a user log ins , they get the access token and teh refresh token, when the access token expires,
//the client sends the refresh token to get new access token without logging in again

app.post("/refresh-token", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken)
    return res.status(401).json({ error: "Refresh token required." });

  try {
    const result = await pool.query(
      "SELECT * FROM refresh_tokens WHERE token = $1",
      [refreshToken]
    );
    if (result.rows.length === 0)
      return res.status(403).json({ error: "Invalid refresh token." });

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    // Generate new access token
    const newAccessToken = jwt.sign(
      { user_id: decoded.user_id },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Server Error" });
  }
});
//users can now refresh their access tokens instead of logging in every time!

//since refresh tokens expire in 60 days, lets remove old tokens automatically
async function cleanupExpiredTokens() {
  //ensures expired tokens are actually deleted.

  await pool.query("DELETE FROM refresh_tokens WHERE expires_at < NOW()");
}

cleanupExpiredTokens(); //we need to to do it all around!

//node cron to delete expired tokens on the daily
//designed to run automatically at set intervals (e.g every midnght)
// in our case, it cleans up expired refresh tokens on the daily
cron.schedule("0 0 * * *", async () => {
  console.log("Cleaning up expired tokens...");
  await pool.query("DELETE FROM refresh_tokens WHERE expires_at < NOW()");
});

/**🔒 Security Enhancements Plan
//this will be applied all around the code to ensure that they are relative and used within
Rate Limiting	Prevents brute-force attacks
CORS Configuration	Protects against cross-origin attacks
Helmet (HTTP Security Headers)	Adds extra security layers
Input Validation & Sanitization	Prevents SQL injection & XSS
HSTS (Strict Transport Security)	Forces HTTPS for added security */

// Restrict API access to specific origins
const corsOptions = {
  origin: ["http://localhost:3000"], // Update this to your frontend URL when deployed
  methods: "GET,POST,PUT,DELETE",
  allowedHeaders: "Content-Type,Authorization",
};
//now only the frontend can access the API, blocking external malicious requests.

app.use(cors(corsOptions));

// Apply security headers
app.use(helmet()); // now the API has additional protection against common attacks
app.use(
  helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }) //now the browser will always use HTTPS if available.
);

//set up storage engine (files will be stored in 'uploads' folder)
const storage = multer.diskStorage({
  destination: "uploads/", //save files to 'uploads' folder
  filename: (req, file, cb) => {
    //cb = callback function : cb is used to provide the result of the operation to Multer
    cb(null, `${Date.now()}-${file.originalname}`); // Unique filename)
  },
});

//configure multer with file size limit (5 mb max)
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, //5mb limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "image/jpeg",
      "image/png",
      "application/pdf",
      "audio/mpeg",
      "video/mp4",
      "video/x-msvideo",
      "video/quicktime", // MP4, AVI, MOV
    ];

    if (!allowedTypes.includes(file.mimetype)) {
      return cb(
        new Error("Invalid file type. Only JPG, PNG, PDF, and MP3 allowed.")
      );
    }
    cb(null, true);
  },
});

//// File upload endpoint (Authenticated users only)

//to get the files via /uploads/ {filename}
app.use("/uploads", express.static("uploads"));

app.post(
  "/upload",
  authenticateToken,
  upload.single("file"),
  async (req, res) => {
    try {
      console.log("FIle Upload: ", req.file); //log in just in case errors arise

      const filePath = req.file.path; //path where the file is stored
      const user_id = req.user.user_id; //get user ID from token

      //save file reference in the database
      const result = await pool.query(
        "INSERT INTO ideas (user_id, title, file_path) VALUES ($1,$2,$3) RETURNING *",
        [user_id, req.file.originalname, filePath]
      );

      res.json({
        message: "File uploaded successfully!",
        file: result.rows[0],
      });
    } catch (err) {
      console.error("Upload Error:", err.message);
      res.status(500).json({ error: "File upload failed." });
    }
  }
);

//gets the files within the database
app.get("/files/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`Fetching file with ID: ${id}`); // Debugging

    const result = await pool.query("SELECT * FROM ideas WHERE id = $1", [id]);

    if (result.rows.length === 0) {
      console.log("❌ No file found for this ID."); // Debugging
      return res.status(404).json({ error: "File not found" });
    }

    const file = result.rows[0];
    console.log("✅ File Retrieved:", file); // Debugging

    // Convert Windows-style backslashes to forward slashes
    const correctedPath = file.file_path.replace(/\\/g, "/");
    const fileUrl = `http://localhost:3000/${correctedPath}`;
    console.log("✅ Corrected File URL:", fileUrl); // Debugging

    res.json({ file_url: fileUrl });
  } catch (err) {
    console.error("❌ File Retrieval Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// Serve static files from the uploads directory
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.post("/cleanup-missing-files", async (req, res) => {
  try {
    console.log("Checking for missing files...");

    const result = await pool.query("SELECT id, file_path FROM ideas");

    let deletedCount = 0;
    for (const row of result.rows) {
      if (!fs.existsSync(row.file_path)) {
        await pool.query("DELETE FROM ideas WHERE id = $1", [row.id]);
        deletedCount++;
      }
    }

    res.json({ message: `Deleted ${deletedCount} orphaned records.` });
  } catch (err) {
    console.error("Cleanup Error:", err.message);
    res.status(500).json({ error: "Cleanup failed." });
  }
});

// DELETE endpoint to remove a file
app.delete("/files/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const user_id = req.user.user_id;

    console.log(`Received DELETE request for file ID: ${id}`); // Debugging

    // Retrieve file info from the database
    const result = await pool.query(
      "SELECT * FROM ideas WHERE id = $1 AND user_id = $2",
      [id, user_id]
    );

    if (result.rows.length === 0) {
      console.log("Unauthorized deletion attempt or file not found.");
      return res.status(404).json({ error: "File not found or unauthorized" });
    }

    const filePath = result.rows[0].file_path;

    // Delete the file from the server storage
    fs.unlink(filePath, async (err) => {
      if (err) {
        console.error("File deletion error:", err.message);
        return res.status(500).json({ error: "File deletion failed" });
      }

      // Remove file reference from the database
      await pool.query("DELETE FROM ideas WHERE id = $1", [id]);

      console.log(`File deleted successfully: ${filePath}`);
      res.json({ message: "File deleted successfully" });
    });
  } catch (err) {
    console.error("File Deletion Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

//automatic cleanup function to remove database entries for missing files

async function cleanupOrphanedFiles() {
  console.log("Checking for orphaned file records...");

  const result = await pool.query("SELECT id, file_path FROM ideas");

  for (let row of result.rows) {
    if (!fs.existsSync(row.file_path)) {
      console.log(`Removing orphaned entry: ${row.file_path}`);
      await pool.query("DELETE FROM ideas WHERE id = $1", [row.id]);
    }
  }
}

// Run the cleanup function every 24 hours (Optional), runs every night to remove broken file records!
cron.schedule("0 0 * * *", cleanupOrphanedFiles);

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
