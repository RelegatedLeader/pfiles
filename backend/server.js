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
const archiver = require("archiver"); //returns archive for download
const clamd = require("clamdjs");
const net = require("net"); // For ClamAV TCP scanning
const logger = require("./utils/logger"); // this is a robust error logger located in utils folder
const { swaggerUi, specs } = require("./utils/swaggerConfig"); //helps with api configuration with swagger

//added at bottom
const { encryptFile } = require("../backend/utils/encryption");
const { decryptFile } = require("../backend/utils/encryption");

//these two are for adding a thumnail for images and videos after uploading them, they will be applied
// to the /upload route
const sharp = require("sharp"); //size and format < -- can be used to compress images
const ffmpeg = require("fluent-ffmpeg"); // (for duration, resolution, and format) <-- can be used to compress videos

//pdf-lib is used for adding metadata to PDF files
const { PDFDocument } = require("pdf-lib"); // For PDF metadata

//Clickjacking is a malicious technique where an attacker tricks a user into clicking on something
//  different from what they perceive, potentially
//  revealing confidential information or allowing the attacker to take control of their computer.
//MIME sniffing is a technique used by web browsers to determine the file format of a
//  resource when the MIME type is not explicitly specified or is incorrect, by analyzing the content of the resource.

dotenv.config(); //load environment variables

console.log(process.env);
//console.log("Loaded DB_USER:", process.env.DB_USER);

const app = express();

const port = process.env.PORT || 10000; // Ensure it uses Render's assigned port
// ✅ Apply Helmet security headers early in the middleware stack
app.use(
  helmet({
    contentSecurityPolicy: false, // Optional: Disable CSP if causing issues
    frameguard: { action: "deny" }, // Prevent clickjacking
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }, // Enforce HTTPS
    referrerPolicy: { policy: "no-referrer" }, // Hide referrer information
    xssFilter: true, // Mitigate XSS attacks
    noSniff: true, // Prevent MIME-type sniffing
  })
);
app.use(express.json()); // Middleware to parse JSON bodies , should be placed before all routes.

///adds swagger middleware.
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs));
console.log("Swagger Docs available at: http://localhost:3000/api-docs");
// ✅ CORS Configuration (Keep it after Helmet)
const corsOptions = {
  origin: "*",
  // origin: ["http://localhost:3000"], // Update for production
  methods: "GET,POST,PUT,DELETE",
  allowedHeaders: "Content-Type,Authorization",
};
app.use(cors(corsOptions));
//postgreSQL connection setup

//this is the middleware for swagger  - the api configuration
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs));
console.log("Swagger Docs available at: http://localhost:3000/api-docs");

//this is the middle ware to log all incoming requests from the logger.js in utilitie folder
//placing this right here ensures that every request is logged before reaching
//your API endpoints
app.use((req, res, next) => {
  logger.info(`🚀 Incoming Request: ${req.method} ${req.url}`);
  next();
});

//before and after
/**const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
}); */

//now removed??
/**const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // Required for Render PostgreSQL
  },
}); */

const isRender = process.env.RENDER === "true"; // Check if running on Render

const pool = new Pool({
  user: process.env.DB_USER,
  host: isRender ? process.env.DB_HOST : "localhost", // Use localhost if not on Render
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432, // Default to local PostgreSQL port
  ssl: isRender ? { rejectUnauthorized: false } : false, // Only use SSL on Render
});

//try

console.log("DB Password:", typeof process.env.DB_PASSWORD);

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

app.use((req, res, next) => {
  logger.info(`📩 [GET] ${req.originalUrl} - Incoming Request`);
  logger.info(`🔍 Request Params: ${JSON.stringify(req.params)}`);
  logger.info(`📝 Request Query: ${JSON.stringify(req.query)}`);

  next();
});

// Log incoming requests before defining routes
app.use((req, res, next) => {
  console.log(
    `🚀 [${req.method}] ${req.url} -> Matched route: ${
      req.route ? req.route.path : "None"
    }`
  );
  next();
});

/**
 * @swagger
 * /:
 *   get:
 *     summary: Check if the backend is running
 *     description: Returns a simple message to confirm the server is online.
 *     responses:
 *       200:
 *         description: Server is running.
 */
app.get("/", (req, res) => {
  res.send("PFiles Backend is running!");
});

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Fetch all users
 *     description: Retrieves all users from the database.
 *     responses:
 *       200:
 *         description: A list of users.
 *       500:
 *         description: Server error.
 */
app.get("/users", async (req, res) => {
  try {
    const result = await pool.query("Select * from users");
    res.json(result.rows);
    logger.info(`📩 [GET] /users - Fetching all users`);

    // Sends the rows returned by the database query as a JSON response
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

//req is needed simply because it is part of the signature of the whole function
//it can be used as incoming req from the client (such as the browser, post man etc)

/**
 * @swagger
 * /hashes:
 *   get:
 *     summary: Fetch all authentication hashes
 *     description: Retrieves all stored authentication hashes.
 *     responses:
 *       200:
 *         description: A list of authentication hashes.
 *       500:
 *         description: Server error.
 */
app.get("/hashes", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM hashes");
    res.json(result.rows);
    logger.info(`📩 [GET] /hashes - Fetching all hashes`);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

app.get("/hashes", async (req, res) => {
  try {
    const result = await pool.query("Select * from hashes");
    res.json(result.rows);
    logger.info(`📩 [GET] /hashes - Fetching all hashes`);

    // Sends the rows returned by the database query as a JSON response
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});
/**
 * @swagger
 * /ideas:
 *   get:
 *     summary: Fetch all files (ideas) for the authenticated user
 *     description: Retrieves all files uploaded by the user.
 *     responses:
 *       200:
 *         description: A list of files.
 *       500:
 *         description: Server error.
 */

app.get("/ideas", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM ideas WHERE user_id = $1", [
      req.user.user_id,
    ]);
    res.json(result.rows);
    logger.info(
      `📩 [GET] /ideas - Fetching ideas for user ID: ${req.user.user_id}`
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

//now to inserting
//now with protections against Cross Siet Scripting and SQL IJECTION

/**
 * @swagger
 * /users:
 *   post:
 *     summary: Create a new user
 *     description: Adds a new user to the database.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The user's email address.
 *     responses:
 *       200:
 *         description: User created successfully.
 *       400:
 *         description: Invalid email format.
 *       500:
 *         description: Server error.
 */
app.post(
  "/users",
  [
    //prevents invalid emails and makes sure they are formatted correctly
    //helps from xxs cross script attacks and sql injection
    body("email")
      .trim()
      .isEmail()
      .normalizeEmail()
      .withMessage("Invalid email format"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;

    try {
      const result = await pool.query(
        "INSERT INTO users (email) VALUES ($1) RETURNING *",
        [email]
      );
      res.json(result.rows[0]);
    } catch (err) {
      if (err.code === "23505") {
        return res.status(400).json({ error: "Email already exists." });
      }
      console.error("Database Error:", err.message);
      res.status(500).json({ error: "An unexpected error occurred." });
    }
  }
);

/**
 * @swagger
 * /hashes:
 *   post:
 *     summary: Store a new authentication hash
 *     description: Adds a new hash code for authentication purposes.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - user_id
 *               - hash_code
 *             properties:
 *               user_id:
 *                 type: integer
 *                 description: The ID of the user.
 *               hash_code:
 *                 type: string
 *                 description: The generated authentication hash.
 *     responses:
 *       200:
 *         description: Hash stored successfully.
 *       500:
 *         description: Server error.
 */
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

/**
 * @swagger
 * /ideas:
 *   post:
 *     summary: Create a new file record
 *     description: Stores metadata for a newly uploaded file.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - user_id
 *               - title
 *               - file_path
 *             properties:
 *               user_id:
 *                 type: integer
 *                 description: ID of the user.
 *               title:
 *                 type: string
 *                 description: Title of the file.
 *               file_path:
 *                 type: string
 *                 description: Path to the stored file.
 *     responses:
 *       200:
 *         description: File metadata stored successfully.
 *       500:
 *         description: Server error.
 */
app.post(
  "/ideas",
  // Sanitizes title and content to prevent malicious scripts from being stored.
  // Ensures file_path is a valid string.
  [
    body("title")
      .trim()
      .escape()
      .isLength({ min: 1 })
      .withMessage("Title is required."),
    body("content").optional().trim().escape(),
    body("file_path").isString().withMessage("Invalid file path."),
  ],

  async (req, res) => {
    //see if errors are found
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { user_id, title, content, file_path } = req.body;

    try {
      const result = await pool.query(
        "INSERT INTO ideas (user_id, title, content, file_path) VALUES ($1, $2, $3, $4) RETURNING *",
        [user_id, title, content, file_path]
      );

      res.json(result.rows[0]);
    } catch (err) {
      console.log(err.message);
      res.status(500).send("Server Error");
    }
  }
);

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

/**
 * @swagger
 * /generate-hash:
 *   post:
 *     summary: Generate and send monthly authentication hash
 *     description: Generates a new authentication hash and emails it to the user.
 *     responses:
 *       200:
 *         description: Hash generated and sent successfully.
 *       500:
 *         description: Server error.
 */
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

/**
 * @swagger
 * /login:
 *   post:
 *     summary: User login with authentication hash
 *     description: Authenticates the user using a one-time hash code and returns access & refresh tokens.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - hash_code
 *             properties:
 *               hash_code:
 *                 type: string
 *                 description: The user's authentication hash.
 *     responses:
 *       200:
 *         description: Login successful, tokens issued.
 *       400:
 *         description: Invalid hash format.
 *       401:
 *         description: Invalid or expired hash.
 *       500:
 *         description: Server error.
 */
app.post(
  "/login",
  loginLimiter, // Limits login attempts to prevent brute force attacks, this isthe rate limit from express
  [
    body("hash_code")
      .trim() // Removes whitespace from start and end to avoid issues with input
      .isLength({ min: 32, max: 32 }) // Ensures the hash is exactly 32 characters long (avoiding SQL injection attempts)
      .matches(/^[a-fA-F0-9]+$/) // Only allows valid hexadecimal characters (prevents malicious injections)
      .withMessage("Invalid hash format"), // If the hash is incorrect, return an error message
  ],
  async (req, res) => {
    console.log("🔑 Login route hit!"); // Debugging: Log that the login route is accessed
    console.log("Received hash_code:", req.body.hash_code); // Debugging: Check the provided hash

    //from express-validator that is used to prevent XSS and SQL injection attacks
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log("❌ Validation Errors:", errors.array()); // Log validation errors
      return res.status(400).json({ errors: errors.array() });
    }

    const { hash_code } = req.body; // Extracts hash from user input

    try {
      console.log("🔍 Checking hash validity in database...");
      const result = await pool.query(
        "SELECT * FROM hashes WHERE hash_code = $1 AND expires_at > NOW()",
        [hash_code]
      );

      if (result.rows.length === 0) {
        console.log("❌ Invalid or expired hash provided.");
        return res.status(401).json({ error: "Invalid or expired hash." });
      }

      const user_id = result.rows[0].user_id; // Retrieve the user ID linked to the hash

      console.log("✅ Hash verified, generating tokens...");

      // Generate Access Token (Short-lived, used for authentication)
      const accessToken = jwt.sign({ user_id }, process.env.JWT_SECRET, {
        expiresIn: "30d", // Token is valid for 30 days
      });

      // Generate Refresh Token (Longer-lived, used to renew access tokens)
      const refreshToken = jwt.sign(
        { user_id },
        process.env.JWT_REFRESH_SECRET,
        {
          expiresIn: "60d", // Refresh token lasts for 60 days
        }
      );

      console.log("💾 Storing refresh token in database...");
      // Store refresh token in DB (allows revocation if needed)
      await pool.query(
        "INSERT INTO refresh_tokens (user_id, token) VALUES ($1, $2)",
        [user_id, refreshToken]
      );

      console.log("🎉 Login successful! Tokens issued.");
      res.json({ accessToken, refreshToken }); // Return tokens to the user
    } catch (err) {
      console.error("🔥 Server Error:", err.message);
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

    // Attach user_id to req for later use
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

/**
 * @swagger
 * /logout:
 *   post:
 *     summary: User logout (revoke token)
 *     description: Revokes the user's current access token.
 *     responses:
 *       200:
 *         description: Logout successful, token revoked.
 *       500:
 *         description: Server error.
 */
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

/**
 * @swagger
 * /refresh-token:
 *   post:
 *     summary: Refresh access token
 *     description: Generates a new access token using a refresh token.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 description: The user's refresh token.
 *     responses:
 *       200:
 *         description: New access token issued.
 *       401:
 *         description: Refresh token required.
 *       403:
 *         description: Invalid refresh token.
 *       500:
 *         description: Server error.
 */
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

//now only the frontend can access the API, blocking external malicious requests.

//set up storage engine (files will be stored in 'uploads' folder)
// Configure multer storage to save files in user-specific directories

app.use("/uploads", express.static("uploads"));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadFolder = path.join(__dirname, "uploads");
    if (!fs.existsSync(uploadFolder)) {
      fs.mkdirSync(uploadFolder, { recursive: true });
    }
    cb(null, uploadFolder);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

//now user_id is correctly extracted
// from the JWT token, and the folder is created before storage.

//configure multer with file size limit (5 mb max)
const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 }, //50mb limit (because of the possible add on of videos)
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
        new Error(
          "Invalid file type. Only JPG, PNG, PDF, MP3, MP4, AVI, and MOV allowed."
        )
      );
    }

    // 🔹 Custom file size check per type
    if (
      (file.mimetype.startsWith("image/") && file.size > 10 * 1024 * 1024) || // 10MB for images
      (file.mimetype.startsWith("video/") && file.size > 50 * 1024 * 1024) // 50MB for videos
    ) {
      return cb(new Error("❌ File too large. Max size exceeded!"));
    } // now, files over the size limit will be rejected immediately -> this is for storare safety

    cb(null, true);
  },
});

//// File upload endpoint (Authenticated users only)

//to get the files via /uploads/ {filename}
//app.use("/uploads", express.static(path.resolve(__dirname, "uploads")));
const thumbnailDir = path.join(__dirname, "uploads/thumbnails");
if (!fs.existsSync(thumbnailDir)) {
  fs.mkdirSync(thumbnailDir, { recursive: true });
}

// Modify /upload to handle compression & thumbnails
// Modify /upload to handle file versioning

//to make sure we dont get affected by XSS attacks
const sanitizeFilename = (filename) => {
  return filename
    .replace(/[^a-zA-Z0-9_.-]/g, "") // Keep only safe characters
    .replace(/\.\./g, "") // Remove directory traversal attempts
    .replace(/^\.+/, ""); // Remove leading dots
};

//
const verifyFileIntegrity = (filePath) => {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);

    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", (err) => reject(err));
  });
};

//scam for viruses with clamav
// Function to scan files using ClamAV via TCP
const scanFileForViruses = async (filePath) => {
  try {
    const scanner = clamd.createScanner("127.0.0.1", 3310); // Connect to ClamAV daemon
    const result = await scanner.scanFile(filePath);

    if (result.includes("OK")) {
      return true; // File is clean
    } else {
      return false; // Virus detected
    }
  } catch (err) {
    console.error("❌ ClamAV Scan Error:", err.message);
    return false; // Treat errors as a potential virus detection
  }
};

/**
 * @swagger
 * /upload:
 *   post:
 *     summary: Upload a file
 *     description: Uploads a file and stores it in the database.
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required:
 *               - file
 *             properties:
 *               file:
 *                 type: string
 *                 format: binary
 *                 description: The file to upload.
 *     responses:
 *       200:
 *         description: File uploaded successfully.
 *       400:
 *         description: Invalid file type or size.
 *       500:
 *         description: File upload failed.
 */
app.post(
  "/upload",
  authenticateToken,
  (req, res, next) => {
    console.log("🔥 Upload route hit!");

    upload.single("file")(req, res, (err) => {
      if (err) {
        console.error("🚨 Multer Upload Error:", err.message);
        return res.status(400).json({ error: err.message });
      }
      console.log("✅ Multer processed the file.");
      next();
    });
  },
  async (req, res) => {
    console.log("🔍 Checking request...");
    try {
      if (!req.file) {
        console.error("❌ No file uploaded!");
        return res.status(400).json({ error: "No file uploaded." });
      }

      console.log("✅ File uploaded:", req.file.path);

      const sanitizedFilename = sanitizeFilename(req.file.originalname);
      const filePath = `uploads/${Date.now()}-${sanitizedFilename}`;
      const encryptedFilePath = `uploads/encrypted_${Date.now()}_${sanitizedFilename}`;
      const user_id = req.user.user_id;
      const tags = req.body.tags ? JSON.parse(req.body.tags) : [];
      const fileExt = path.extname(req.file.filename).toLowerCase();
      let thumbnailPath = null;
      let metadata = {};
      let compressedFilePath = filePath;

      fs.renameSync(req.file.path, filePath); // Rename the file properly

      // 🔐 Encrypt the file before storing
      await encryptFile(filePath, encryptedFilePath);
      fs.unlinkSync(filePath); // Remove the unencrypted file after encryption

      // 🔍 **Verify File Integrity (Check Hash)**
      const fileHash = await verifyFileIntegrity(encryptedFilePath);

      // 🔄 **Prevent Duplicate File Uploads**
      const existingFile = await pool.query(
        "SELECT * FROM file_hashes WHERE hash = $1 AND user_id = $2",
        [fileHash, user_id]
      );

      if (existingFile.rows.length > 0) {
        fs.unlinkSync(encryptedFilePath); // Delete duplicate file
        console.warn(`⚠️ Duplicate file upload detected: ${filePath}`);
        return res.status(400).json({ error: "Duplicate file detected." });
      }

      // 🦠 **Scan File for Viruses**
      const isSafe = await scanFileForViruses(encryptedFilePath);
      if (!isSafe) {
        fs.unlinkSync(encryptedFilePath); // Delete infected file
        console.error("🚨 Virus detected! File deleted.");

        // Log failed upload attempt
        await pool.query(
          "INSERT INTO upload_logs (user_id, file_path, error_message) VALUES ($1, $2, $3)",
          [user_id, encryptedFilePath, "Virus detected - File rejected"]
        );

        return res.status(400).json({ error: "File contains a virus!" });
      }

      /** 🖼️ Process Image Metadata & Compression */
      const imageTypes = [".jpg", ".jpeg", ".png"];
      const videoTypes = [".mp4", ".avi", ".mov"];

      if (imageTypes.includes(fileExt)) {
        const imageMetadata = await sharp(filePath).metadata();
        metadata = {
          width: imageMetadata.width,
          height: imageMetadata.height,
          format: imageMetadata.format,
          size: req.file.size,
        };

        // Generate Thumbnail
        const thumbnailFilename = `thumb-${Date.now()}-${req.file.filename}`;
        thumbnailPath = `uploads/thumbnails/${thumbnailFilename}`;

        await sharp(filePath)
          .resize(200, 200)
          .toFile(path.join(__dirname, thumbnailPath));

        console.log("🖼️ Image thumbnail created:", thumbnailPath);

        // Compress Image
        compressedFilePath = `uploads/compressed-${req.file.filename}`;
        await sharp(filePath)
          .resize(1024)
          .jpeg({ quality: 70 })
          .toFile(path.join(__dirname, compressedFilePath));

        console.log("🖼️ Image compressed:", compressedFilePath);
      } else if (videoTypes.includes(fileExt)) {
        metadata = await new Promise((resolve, reject) => {
          ffmpeg.ffprobe(filePath, (err, metadata) => {
            if (err) return reject(err);
            resolve({
              format: metadata.format.format_name,
              duration: metadata.format.duration,
              width: metadata.streams[0]?.width || null,
              height: metadata.streams[0]?.height || null,
              size: req.file.size,
            });
          });
        });

        // Generate Thumbnail
        const thumbnailFilename = `thumb-${Date.now()}.jpg`;
        thumbnailPath = `uploads/thumbnails/${thumbnailFilename}`;

        await new Promise((resolve, reject) => {
          ffmpeg(filePath)
            .screenshots({
              timestamps: ["00:00:01"],
              filename: thumbnailFilename,
              folder: path.join(__dirname, "uploads/thumbnails"),
              size: "200x200",
            })
            .on("end", () => resolve())
            .on("error", reject);
        });

        console.log("🎥 Video thumbnail created:", thumbnailPath);
      }

      /** 🔄 Store Previous Version Before Overwriting */
      const oldFileResult = await pool.query(
        "SELECT * FROM ideas WHERE title = $1 AND user_id = $2",
        [req.file.originalname, user_id]
      );

      if (oldFileResult.rows.length > 0) {
        const oldFile = oldFileResult.rows[0];

        await pool.query(
          "INSERT INTO file_versions (file_id, user_id, title, file_path, compressed_file_path, metadata) VALUES ($1, $2, $3, $4, $5, $6)",
          [
            oldFile.id,
            user_id,
            oldFile.title,
            oldFile.file_path,
            oldFile.compressed_file_path,
            oldFile.metadata,
          ]
        );
      }

      /** 💾 Store File Data in Database */
      const result = await pool.query(
        "INSERT INTO ideas (user_id, title, file_path, thumbnail_path, compressed_file_path, metadata, tags) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        [
          user_id,
          req.file.originalname,
          encryptedFilePath,
          thumbnailPath,
          compressedFilePath,
          JSON.stringify(metadata),
          JSON.stringify(tags),
        ]
      );

      // Store file hash in DB
      await pool.query(
        "INSERT INTO file_hashes (file_path, hash, user_id) VALUES ($1, $2, $3)",
        [encryptedFilePath, fileHash, user_id]
      );

      console.log("💾 Saved to Database:", result.rows[0]);

      res.json({
        message: "File uploaded, encrypted & verified successfully!",
        file: result.rows[0],
      });
    } catch (err) {
      console.error("🔥 Upload Error:", err.message);

      // Log failed uploads
      await pool.query(
        "INSERT INTO upload_logs (user_id, file_path, error_message) VALUES ($1, $2, $3)",
        [req.user.user_id, req.file ? req.file.path : "N/A", err.message]
      );

      res.status(500).json({ error: "File upload failed." });
    }
  }
);

// i also added indexes on the database , ex: CREATE INDEX idx_ideas_user_id ON ideas(user_id);
//to make searching faster

//gets the files within the database
//  Define /files/searching first (before /files/:id)

/**
 * @swagger
 * /files/searching:
 *   get:
 *     summary: Search files by tag
 *     description: Returns files that contain a specific tag.
 *     parameters:
 *       - in: query
 *         name: tag
 *         required: true
 *         description: Tag to search for.
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Files found with the given tag.
 *       400:
 *         description: Tag is required.
 *       500:
 *         description: Server error.
 */
app.get("/files/searching", authenticateToken, async (req, res) => {
  console.log("🚀 Route /files/searching is being executed...");

  try {
    const { tag } = req.query;
    const user_id = req.user.user_id;

    if (!tag) {
      console.log("❌ Missing tag in request");
      return res.status(400).json({ error: "Tag is required for search" });
    }

    console.log(`🔍 Searching for files with tag: ${tag} for user: ${user_id}`);

    const query = `
      SELECT * FROM ideas
      WHERE user_id = $1
        AND tags IS NOT NULL
        AND tags @> $2::jsonb
    `;
    const params = [user_id, JSON.stringify([tag])];

    console.log("🛠️ Executing Query:", query);
    console.log("📌 Query Parameters:", params);

    const result = await pool.query(query, params);

    logger.info(`📩 [GET] /files/searching - Searching for files`);
    logger.info(`🔍 Search Query: ${JSON.stringify(req.query)}`);

    return res.json({ files: result.rows });
  } catch (err) {
    console.error("🔥 Search Error:", err.stack);
    return res
      .status(500)
      .json({ error: "Server Error", details: err.message });
  }
});

//  Place this route BEFORE /files/:id to avoid conflicts
//express routes are sequential
////get all the files in the group

/**
 * @swagger
 * /files/group/{groupName}:
 *   get:
 *     summary: Fetch all files in a group
 *     description: Retrieves all files belonging to a specific group.
 *     parameters:
 *       - in: path
 *         name: groupName
 *         required: true
 *         description: Name of the group.
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of files in the group.
 *       500:
 *         description: Server error.
 */
app.get("/files/group/:groupName", authenticateToken, async (req, res) => {
  const { groupName } = req.params;

  try {
    console.log(`🔍 Searching for group: ${groupName}`);

    const result = await pool.query(
      `SELECT ideas.* FROM ideas
       JOIN groups ON ideas.group_id = groups.id
       WHERE LOWER(groups.name) = LOWER($1)`,
      [groupName]
    );
    logger.info(
      `📩 [GET] /files/group/${req.params.groupName} - Fetching files in group`
    );

    res.json({ group: groupName, files: result.rows });
  } catch (err) {
    console.error("🔥 Server Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

//this route is different, it is for general search, sorting and filtering,
//this is for the mere idea of optimization of searching
///has to be implemented before /file/:id

//example to test: GET /files/search?query=report&type=pdf&sort=name&order=asc
//basically we are building a SQL query here!
// 🔹 In-memory cache to store search results for faster retrieval
const cache = new Map();

/**
 * @swagger
 * /files/search:
 *   get:
 *     summary: Search files with filters and sorting
 *     description: Allows searching, filtering, and sorting files based on name, type, category, and metadata.
 *     parameters:
 *       - in: query
 *         name: query
 *         required: false
 *         description: Search term (file title).
 *         schema:
 *           type: string
 *       - in: query
 *         name: type
 *         required: false
 *         description: File type extension (e.g., pdf, jpg).
 *         schema:
 *           type: string
 *       - in: query
 *         name: category
 *         required: false
 *         description: File category (image, video, pdf).
 *         schema:
 *           type: string
 *       - in: query
 *         name: sort
 *         required: false
 *         description: Sorting criteria (name, date, size, type).
 *         schema:
 *           type: string
 *       - in: query
 *         name: order
 *         required: false
 *         description: Sorting order (asc or desc).
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Files matching the search criteria.
 *       500:
 *         description: Search failed.
 */
app.get("/files/search", authenticateToken, async (req, res) => {
  try {
    // Extract query parameters from the request
    const { query, type, category, sort, order } = req.query;
    const user_id = req.user.user_id; // Get user ID from the authenticated token

    // Generate a unique cache key based on search filters
    const cacheKey = `${user_id}-${query}-${type}-${category}-${sort}-${order}`;

    // 🚀 Check if result exists in cache, return it instantly
    if (cache.has(cacheKey)) {
      console.log("⚡ Serving from Cache!");
      return res.json({ files: cache.get(cacheKey) });
    }

    // Initialize the SQL query to select all files for the authenticated user
    let sql = `SELECT * FROM ideas WHERE user_id = $1`;
    let params = [user_id]; // First parameter is always the user ID

    // 🔍 Filter by search query (title matching)
    if (query) {
      sql += ` AND LOWER(title) LIKE LOWER($2)`; // Case-insensitive search
      params.push(`%${query}%`); // Use wildcard (%) for partial matching
    }

    // 📂 Filter by file extension type (e.g., ".jpg", ".pdf")
    if (type) {
      sql += ` AND LOWER(file_path) LIKE LOWER($3)`;
      params.push(`%.${type}`);
    }

    // 🏷️ **NEW**: Filtering by category (image, video, pdf)
    if (category) {
      const categories = {
        image: ["jpg", "jpeg", "png"],
        video: ["mp4", "avi", "mov"],
        pdf: ["pdf"],
      };

      if (categories[category]) {
        const extensions = categories[category]
          .map((ext) => `'%.${ext}'`) // Convert to SQL LIKE pattern
          .join(", ");
        sql += ` AND LOWER(file_path) LIKE ANY (ARRAY[${extensions}])`;
      }
    }

    // 📌 Sorting logic (Sort by name, date, size, or type)
    if (sort) {
      const validSorts = {
        name: "title", // Sort by file title
        date: "created_at", // Sort by creation date
        size: "metadata->>'size'", // Sort by file size stored in metadata JSON
        type: "file_path", // Sort by file type
      };

      if (validSorts[sort]) {
        const orderBy = order === "desc" ? "DESC" : "ASC";
        sql += ` ORDER BY ${validSorts[sort]} ${orderBy}`;
      }
    }

    // 🚀 Speed Optimization: Use database indexing for faster queries
    console.log("🔹 Optimizing Query with Indexes...");
    await pool.query("SET enable_seqscan = OFF"); // Force index usage for faster search

    // 🛠️ Debugging logs to see generated query
    logger.info(`📩 [GET] /files/search - Executing file search`);
    logger.info(`🔍 Query Parameters: ${JSON.stringify(req.query)}`);

    // Execute the optimized query with PostgreSQL
    const result = await pool.query(sql, params);

    // 🔹 Store result in cache (expires in 5 minutes)
    cache.set(cacheKey, result.rows);
    setTimeout(() => cache.delete(cacheKey), 5 * 60 * 1000); // Auto-clear cache after 5 minutes

    // ✅ Return filtered & sorted results
    res.json({ files: result.rows });
  } catch (err) {
    console.error("🔥 Search Error:", err.message);
    res.status(500).json({ error: "Search failed." });
  }
});

//^
/**Extracts search filters (query, type, sort, order) from the request.
Starts with a base SQL query that fetches files belonging to the logged-in user.
Adds search conditions dynamically:
If a search term (query) is provided, it filters files whose title matches.
If a file type (type) is provided, it filters files by file extension.
Handles sorting based on name, date, size, or type.
Logs the final SQL query for debugging.
Executes the query and returns the matching files. */

//this is to retrieve and restore previous versions

/**
 * @swagger
 * /files/{id}/versions:
 *   get:
 *     summary: Fetch file versions
 *     description: Retrieves all previous versions of a file.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: File ID.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: File versions retrieved.
 *       500:
 *         description: Server error.
 */
app.get("/files/:id/versions", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const user_id = req.user.user_id;

    logger.info(
      `📩 [GET] /files/${req.params.id}/versions - Fetching file versions`
    );

    const result = await pool.query(
      "SELECT * FROM file_versions WHERE file_id = $1 AND user_id = $2 ORDER BY created_at DESC",
      [id, user_id]
    );

    res.json({ versions: result.rows });
    logger.info(
      `📩 [GET] /files/${req.params.id}/versions - Fetching file versions`
    );
  } catch (err) {
    console.error("🔥 Version Fetch Error:", err.message);
    res.status(500).json({ error: "Failed to fetch file versions." });
  }
});

///this is to rollback to previous versions - ex -> an image, there may be two types of it,
//and we can always roll back to a previous version of the same file, this helps delete
//the need to restore things if you really think about it, makes it all look clean!

/**
 * @swagger
 * /files/{id}/rollback/{versionId}:
 *   put:
 *     summary: Rollback a file to a previous version
 *     description: Restores a file to a specified previous version.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the file to rollback.
 *         schema:
 *           type: integer
 *       - in: path
 *         name: versionId
 *         required: true
 *         description: ID of the version to restore.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: File rolled back successfully.
 *       404:
 *         description: Version not found.
 *       500:
 *         description: Rollback failed.
 */
app.put(
  "/files/:id/rollback/:versionId",
  authenticateToken,
  async (req, res) => {
    try {
      const { id, versionId } = req.params;
      const user_id = req.user.user_id;

      console.log(`🔄 Restoring version ${versionId} for file ID: ${id}`);

      const versionResult = await pool.query(
        "SELECT * FROM file_versions WHERE id = $1 AND user_id = $2",
        [versionId, user_id]
      );

      if (versionResult.rows.length === 0) {
        return res.status(404).json({ error: "Version not found." });
      }

      const version = versionResult.rows[0];

      await pool.query(
        "UPDATE ideas SET file_path = $1, compressed_file_path = $2, metadata = $3 WHERE id = $4",
        [version.file_path, version.compressed_file_path, version.metadata, id]
      );

      res.json({ message: "File rolled back successfully!" });
    } catch (err) {
      console.error("🔥 Rollback Error:", err.message);
      res.status(500).json({ error: "Rollback failed." });
    }
  }
);

// ✅ Then place the /files/:id route AFTER /files/searching

/**
 * @swagger
 * /files/{id}:
 *   get:
 *     summary: Fetch a specific file by ID
 *     description: Retrieves the details of a file based on its ID.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the file.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: File details returned.
 *       404:
 *         description: File not found.
 *       500:
 *         description: Server error.
 */
app.get("/files/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;

  // 🔹 Ensure ID is a valid number before querying the database
  if (!/^\d+$/.test(id)) {
    console.log(`❌ Invalid ID received: ${id}`);
    return res.status(400).json({ error: "Invalid file ID format" });
  }

  console.log(`Fetching file with ID: ${id}`);

  try {
    const result = await pool.query(
      "SELECT * FROM ideas WHERE id = $1 AND user_id = $2",
      [id, req.user.user_id]
    );

    if (result.rows.length === 0) {
      console.log("🚫 File not found or unauthorized.");
      return res.status(404).json({ error: "File not found" });
    }

    const file = result.rows[0];
    const fileURL = `http://localhost:3000/uploads/${path.basename(
      file.file_path
    )}`;

    console.log("✅ File URL:", fileURL);
    res.json({ file_url: fileURL });
  } catch (err) {
    console.error("🔥 File Retrieval Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

//now we are working on grouping , so we will add a put
//add remove tags for a file
/**
 * @swagger
 * /files/{id}/tags:
 *   put:
 *     summary: Update file tags
 *     description: Adds or removes tags for a file.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the file to update tags.
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - tags
 *             properties:
 *               tags:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: List of tags to assign.
 *     responses:
 *       200:
 *         description: Tags updated successfully.
 *       400:
 *         description: Invalid input.
 *       404:
 *         description: File not found.
 *       500:
 *         description: Server error.
 */
app.put("/files/:id/tags", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { tags } = req.body;
    const user_id = req.user.user_id;

    if (!Array.isArray(tags)) {
      //lowercase array is not a valid js object
      return res.status(400).json({ error: "Tags must be an array" });
    }

    //fetch the file
    const result = await pool.query(
      "SELECT * FROM ideas WHERE id = $1 AND user_id = $2",
      [id, user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "File not found or unauthorized" });
    }

    //update the tags in the database
    await pool.query("UPDATE ideas SET tags = $1 WHERE id = $2", [
      JSON.stringify(tags),
      id,
    ]);
    res.json({ message: "Tags updated successfully!" });
  } catch (err) {
    console.error("�� Tag Update Errorr:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// BULK TAGGING

/**
 * @swagger
 * /files/bulk-tags:
 *   put:
 *     summary: Bulk update file tags
 *     description: Adds or updates tags for multiple files at once.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - file_ids
 *               - tags
 *             properties:
 *               file_ids:
 *                 type: array
 *                 items:
 *                   type: integer
 *                 description: List of file IDs to update.
 *               tags:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: List of tags to apply.
 *     responses:
 *       200:
 *         description: Tags updated for multiple files.
 *       400:
 *         description: Invalid input.
 *       500:
 *         description: Server error.
 */
app.put("/files/bulk-tags", authenticateToken, async (req, res) => {
  try {
    const { file_ids, tags } = req.body;
    const user_id = req.user.user_id;

    if (!Array.isArray(file_ids) || !Array.isArray(tags)) {
      return res.status(400).json({ error: "Invalid input format" });
    }

    let updateCount = 0;

    for (const id of file_ids) {
      const result = await pool.query(
        "SELECT * FROM ideas WHERE id = $1 AND user_id = $2",
        [id, user_id]
      );
      if (result.rows.length > 0) {
        await pool.query("UPDATE ideas SET tags = $1 WHERE id = $2", [
          JSON.stringify(tags),
          id,
        ]);
        updateCount++;
      }
    }
    res.json({ message: `Tags updated for ${updateCount} files.` });
  } catch (err) {
    console.error("Bulk Tagging Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

//delete in bulk based on id- > deletes files from both the database and the storage
// skips any missing files and logs them

/**
 * @swagger
 * /files/bulk-delete:
 *   delete:
 *     summary: Bulk delete files
 *     description: Deletes multiple files from the filesystem and database.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - file_ids
 *             properties:
 *               file_ids:
 *                 type: array
 *                 items:
 *                   type: integer
 *                 description: List of file IDs to delete.
 *     responses:
 *       200:
 *         description: Files deleted successfully.
 *       400:
 *         description: Invalid input.
 *       500:
 *         description: Server error.
 */
app.delete("/files/bulk-delete", authenticateToken, async (req, res) => {
  try {
    const { file_ids } = req.body;
    const user_id = req.user.user_id;

    if (!Array.isArray(file_ids) || file_ids.length === 0) {
      return res.status(400).json({ error: "Invalid file list provided." });
    }

    let deletedCount = 0;
    let missingFiles = [];

    for (const id of file_ids) {
      const result = await pool.query(
        "SELECT * FROM ideas WHERE id = $1 AND user_id = $2",
        [id, user_id]
      );

      if (result.rows.length === 0) {
        missingFiles.push(id);
        continue;
      }

      const file = result.rows[0];
      const filePath = path.join(__dirname, file.file_path);

      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath); // Delete the actual file
      }

      await pool.query("DELETE FROM ideas WHERE id = $1", [id]);
      deletedCount++;
    }

    res.json({
      message: `Deleted ${deletedCount} files.`,
      missing: missingFiles.length ? missingFiles : "None",
    });
  } catch (err) {
    console.error("🔥 Bulk Deletion Error:", err.message);
    res.status(500).json({ error: "Bulk file deletion failed." });
  }
});

//rename in bulk based on an arrya that has the id and the new name , it is object based
//it renames the files in both the dababase and filesystem .

/**
 * @swagger
 * /files/bulk-rename:
 *   put:
 *     summary: Bulk rename files
 *     description: Renames multiple files in both the filesystem and database.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - files
 *             properties:
 *               files:
 *                 type: array
 *                 items:
 *                   type: object
 *                   required:
 *                     - id
 *                     - newName
 *                   properties:
 *                     id:
 *                       type: integer
 *                       description: ID of the file to rename.
 *                     newName:
 *                       type: string
 *                       description: The new name for the file.
 *     responses:
 *       200:
 *         description: Files renamed successfully.
 *       400:
 *         description: Invalid input.
 *       500:
 *         description: Bulk rename failed.
 */
app.put("/files/bulk-rename", authenticateToken, async (req, res) => {
  try {
    const { files } = req.body;
    const user_id = req.user.user_id;

    if (!Array.isArray(files) || files.length === 0) {
      return res.status(400).json({ error: "Invalid file list provided." });
    }

    let renamedCount = 0;
    let failedRenames = [];

    for (const { id, newName } of files) {
      const result = await pool.query(
        "SELECT * FROM ideas WHERE id = $1 AND user_id = $2",
        [id, user_id]
      );

      if (result.rows.length === 0) {
        failedRenames.push({ id, reason: "File not found or unauthorized" });
        continue;
      }

      const file = result.rows[0];
      const oldPath = path.join(__dirname, file.file_path);
      const fileExt = path.extname(file.file_path);
      const newFilePath = path.join(
        __dirname,
        "uploads",
        `${newName}${fileExt}`
      );

      if (fs.existsSync(oldPath)) {
        fs.renameSync(oldPath, newFilePath); // Rename file in filesystem
        await pool.query("UPDATE ideas SET file_path = $1 WHERE id = $2", [
          `uploads/${newName}${fileExt}`,
          id,
        ]);
        renamedCount++;
      } else {
        failedRenames.push({ id, reason: "File missing from storage" });
      }
    }

    res.json({
      message: `Renamed ${renamedCount} files.`,
      failed: failedRenames.length ? failedRenames : "None",
    });
  } catch (err) {
    console.error("🔥 Bulk Rename Error:", err.message);
    res.status(500).json({ error: "Bulk file renaming failed." });
  }
});

//to download in bulk:

/**
 * @swagger
 * /files/bulk-download:
 *   post:
 *     summary: Bulk download files as ZIP
 *     description: Downloads multiple files in a ZIP archive.
 *     responses:
 *       200:
 *         description: ZIP file created successfully.
 *       500:
 *         description: ZIP file generation failed.
 */
app.post("/files/bulk-download", authenticateToken, async (req, res) => {
  // This route handler listens for POST requests to '/files/bulk-download' and requires authentication
  try {
    // Destructuring assignment to get 'file_ids' from the request body
    const { file_ids } = req.body;
    // Extracting the user_id from the authenticated user object
    const user_id = req.user.user_id;

    // Check if file_ids is an array and not empty
    if (!Array.isArray(file_ids) || file_ids.length === 0) {
      return res.status(400).json({ error: "Invalid file list provided." });
    }

    // Create a new archive object for creating a zip file with maximum compression
    const archive = archiver("zip", { zlib: { level: 9 } });
    // Set the response's Content-Disposition to 'attachment' to prompt a download with name 'files.zip'
    res.attachment("files.zip");

    // Pipe the archive to the response, meaning the zip data will be streamed directly to the response
    archive.pipe(res);

    // Loop through each file ID provided in the request
    for (const id of file_ids) {
      // Query the database for the file with the given id, ensuring it belongs to the user
      const result = await pool.query(
        "SELECT * FROM ideas WHERE id = $1 AND user_id = $2",
        [id, user_id]
      );

      // If no file matches the query, skip to the next iteration
      if (result.rows.length === 0) {
        console.warn(`Skipping file ID ${id}: Not found.`);
        continue;
      }

      // Extract the first (and only) row from the query result
      const file = result.rows[0];
      // Construct the full path to the file on the server
      const filePath = path.join(__dirname, file.file_path);

      // Check if the file exists at the specified path
      if (fs.existsSync(filePath)) {
        // If the file exists, add it to the zip archive, using only the filename for the zip entry
        archive.file(filePath, { name: path.basename(filePath) });
      } else {
        // Log a warning if the file does not exist
        console.warn(`Skipping file ${filePath}: Does not exist.`);
      }
    }

    // Finalize the archive, which writes all buffered data and closes the archive
    archive.finalize();
  } catch (err) {
    // Log any errors that occur during the process
    console.error("🔥 ZIP Download Error:", err.message);
    // Send an error response if something went wrong during zip creation
    res.status(500).json({ error: "ZIP file generation failed." });
  }
});

// example of what is received ^
/**{
  "files": [
    { "id": 1, "newName": "document_renamed" },
    { "id": 2, "newName": "image_updated" }
  ]
} */

/** keeping it jsut in case it is needed 
 * app.get("/files/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`Fetching file with ID: ${id}`); // Debugging

    const result = await pool.query(
      "SELECT * FROM ideas WHERE id = $1 AND user_id = $2",
      [id, req.user.user_id]
    );

    if (result.rows.length === 0) {
      console.log("Unauthorized or missing file."); // Debugging
      return res.status(404).json({ error: "File not found" });
    }

    const file = result.rows[0];
    const fileURL = `http://localhost:3000/uploads/${path.basename(
      file.file_path
    )}`;
    //This ensures Windows-style paths are correctly converted.

    console.log("Generated File URL:", fileURL); // Debugging

    res.json({ file_url: fileURL });
  } catch (err) {
    console.error("File Retrieval Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

 */
// Serve static files from the uploads directory
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

//app.use("/uploads", express.static(path.join(__dirname, "uploads")));

/**
 * @swagger
 * /cleanup-missing-files:
 *   post:
 *     summary: Cleanup missing files
 *     description: Deletes orphaned database records for files that no longer exist in storage.
 *     responses:
 *       200:
 *         description: Missing files removed successfully.
 *       500:
 *         description: Cleanup failed.
 */
app.delete("/cleanup-missing-files", async (req, res) => {
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
    logger.info(
      `📩 [DELETE] /cleanup-missing-files - Deleted ${deletedCount} orphaned records`
    );

    res.json({ message: `Deleted ${deletedCount} orphaned records.` });
  } catch (err) {
    console.error("Cleanup Error:", err.message);
    res.status(500).json({ error: "Cleanup failed." });
  }
});
//just in case it was meant to be a POST ^
/**app.post("/cleanup-missing-files", async (req, res) => {
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
    logger.info(`📩 [GET] /cleanup-missing-files - Checking for missing files`);

    res.json({ message: `Deleted ${deletedCount} orphaned records.` });
  } catch (err) {
    console.error("Cleanup Error:", err.message);
    res.status(500).json({ error: "Cleanup failed." });
  }
}); */

// to download the decrypted file

/**
 * @swagger
 * /files/{id}/download:
 *   get:
 *     summary: Download a decrypted file
 *     description: Retrieves and decrypts a file before sending it for download.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the file to download.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: File downloaded successfully.
 *       404:
 *         description: File not found.
 *       500:
 *         description: Failed to download file.
 */
app.get("/files/:id/download", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      "SELECT * FROM ideas WHERE id = $1 AND user_id = $2",
      [id, req.user.user_id]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ error: "File not found" });

    const encryptedFilePath = result.rows[0].file_path;
    const decryptedFilePath = `temp/decrypted_${Date.now()}_${path.basename(
      encryptedFilePath
    )}`;

    await decryptFile(encryptedFilePath, decryptedFilePath);
    logger.info(
      `📩 [GET] /files/${req.params.id}/download - Download request received`
    );

    res.download(decryptedFilePath, (err) => {
      if (err) console.error("🔥 Download Error:", err.message);
      fs.unlinkSync(decryptedFilePath); // Cleanup temp decrypted file
    });
  } catch (err) {
    console.error("🔥 File Download Error:", err.message);
    res.status(500).json({ error: "Failed to download file" });
  }
});

// DELETE endpoint to remove a file

/**
 * @swagger
 * /files/{id}:
 *   delete:
 *     summary: Delete a file
 *     description: Deletes a file from both the filesystem and database.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the file to delete.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: File deleted successfully.
 *       404:
 *         description: File not found.
 *       500:
 *         description: Server error.
 */
app.delete("/files/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const user_id = req.user.user_id;

    console.log(`Received DELETE request for file ID: ${id}`);

    // Retrieve file info from the database
    const result = await pool.query(
      "SELECT * FROM ideas WHERE id = $1 AND user_id = $2",
      [id, user_id]
    );

    if (result.rows.length === 0) {
      console.log("Unauthorized deletion attempt or file not found.");
      return res.status(404).json({ error: "File not found or unauthorized" });
    }

    const encryptedFilePath = path.join(__dirname, result.rows[0].file_path);
    const decryptedFilePath = encryptedFilePath.replace(
      "encrypted_",
      "decrypted_"
    );

    console.log(`Attempting to decrypt and delete file: ${encryptedFilePath}`);

    // Check if the encrypted file exists before trying to decrypt & delete it
    if (!fs.existsSync(encryptedFilePath)) {
      console.warn(
        `File does not exist: ${encryptedFilePath}, deleting from DB only.`
      );

      // Remove file reference from the database even if the file is missing
      await pool.query("DELETE FROM ideas WHERE id = $1", [id]);
      return res.json({
        message: "File entry removed from database (file was already missing).",
      });
    }

    // 🔓 Decrypt the file before deletion (Optional for Audit Logs)
    await decryptFile(encryptedFilePath, decryptedFilePath);

    // Delete both encrypted and decrypted files
    fs.unlink(encryptedFilePath, async (err) => {
      if (err) {
        console.error("File deletion error:", err.message);
        return res.status(500).json({ error: "File deletion failed" });
      }

      if (fs.existsSync(decryptedFilePath)) {
        fs.unlinkSync(decryptedFilePath); // Delete decrypted version too
      }

      // Remove file reference from the database
      await pool.query("DELETE FROM ideas WHERE id = $1", [id]);

      console.log(`File deleted successfully: ${encryptedFilePath}`);
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

//log the routes being used to check they are being recoginzed ...

console.log(
  "Registered Routes:",
  app._router.stack
    .filter((r) => r.route) // Only routes, not middleware
    .map((r) => r.route.path)
);

//this route is to rename the file  in the file systme

/**
 * @swagger
 * /files/{id}/rename:
 *   put:
 *     summary: Rename a file
 *     description: Renames a file in the system and updates the database.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the file to rename.
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - newName
 *             properties:
 *               newName:
 *                 type: string
 *                 description: The new name for the file.
 *     responses:
 *       200:
 *         description: File renamed successfully.
 *       400:
 *         description: Invalid input.
 *       404:
 *         description: File not found.
 *       500:
 *         description: Server error.
 */
app.put("/files/:id/rename", authenticateToken, async (req, res) => {
  try {
    console.log("🔹 Received Rename Request:", req.body);

    //js destructuring
    const { id } = req.params; //Extracted from the URL path parameter (e.g., /files/:id/rename where :id is dynamic).
    const { newName } = req.body; //Extracted from the request body (sent as JSON in a PUT request).
    const user_id = req.user.user_id; //Comes from the authenticated JWT token (attached to req.user by authenticateToken).
    /**How this works:

The id (10) is taken from the URL.
The newName (new_image_name) is taken from the body.
The user_id is extracted from the JWT token that was verified. */
    if (!newName || newName.trim() === "") {
      console.error("❌ Invalid newName received:", newName);
      return res.status(400).json({ error: "New file name is required." });
    }

    console.log(`🔍 Renaming file ID ${id} to ${newName}`);

    // Fetch the file record from the database
    const result = await pool.query(
      "SELECT * FROM ideas WHERE id = $1 AND user_id = $2",
      [id, user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "File not found or unauthorized." });
    }

    const file = result.rows[0]; //remember that this is basically an object
    let oldPath = path.join(__dirname, file.file_path); // Ensure absolute path
    //__dirname is a Node.js environment variable that provides the absolute path
    //  to the directory containing the currently executing JavaScript file

    console.log(`🔍 Checking if file exists: ${oldPath}`);
    if (!fs.existsSync(oldPath)) {
      console.error(`🚨 File not found: ${oldPath}`);
      return res
        .status(404)
        .json({ error: "File not found in the filesystem." });
    }

    const fileExt = path.extname(oldPath); // Get file extension
    const newFilePath = path.join(__dirname, "uploads", `${newName}${fileExt}`);

    console.log(`🔄 Renaming: ${oldPath} ➝ ${newFilePath}`);

    // Rename the file in the filesystem
    fs.rename(oldPath, newFilePath, async (err) => {
      if (err) {
        console.error("⚠️ Error renaming file:", err.message);
        return res.status(500).json({ error: "File renaming failed." });
      }

      // Update the database with the new file path (stored as relative path)
      const relativeNewPath = `uploads/${newName}${fileExt}`;
      await pool.query("UPDATE ideas SET file_path = $1 WHERE id = $2", [
        relativeNewPath,
        id,
      ]);

      console.log("✅ Rename successful!");
      res.json({ message: "File renamed successfully!", newFilePath });
    });
  } catch (err) {
    console.error("🔥 File Renaming Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

/**Fetches the file info from the database
Renames the file in the filesystem
Updates the database with the new file name
Returns a success response */

//a new table for groups was create with the ideao f normalization of the database by creating a new table for
//the "groups" of different types of data

//to create a new group

/**
 * @swagger
 * /groups:
 *   post:
 *     summary: Create a new group
 *     description: Creates a new file group.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *             properties:
 *               name:
 *                 type: string
 *                 description: The name of the group.
 *     responses:
 *       200:
 *         description: Group created successfully.
 *       400:
 *         description: Group name is required.
 *       500:
 *         description: Server error.
 */
app.post("/groups", authenticateToken, async (req, res) => {
  const { name } = req.body;

  if (!name) return res.status(400).json({ error: "Group name is required!" });
  try {
    const result = await pool.query(
      "INSERT INTO groups (name) VALUES ($1) RETURNING *",
      [name]
    );
    logger.info(`📩 [GET] /groups - Fetching all groups`);

    res.json({ message: "Group created!", group: result.rows[0] });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

//assign a file to a group

/**
 * @swagger
 * /files/{id}/group:
 *   put:
 *     summary: Assign a file to a group
 *     description: Assigns a file to a specified group.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the file to assign.
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - groupName
 *             properties:
 *               groupName:
 *                 type: string
 *                 description: Name of the group to assign the file to.
 *     responses:
 *       200:
 *         description: File assigned to group successfully.
 *       400:
 *         description: Invalid input.
 *       500:
 *         description: Server error.
 */
app.put("/files/:id/group", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { groupName } = req.body;

  if (!groupName) {
    return res.status(400).json({ error: "Group name is required!" });
  }

  try {
    const groupResult = await pool.query(
      "INSERT INTO groups (name) VALUES ($1) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
      [groupName]
    );
    console.log("🚀 Group Insert Result:", groupResult.rows); // Add this for debugging
    const groupId = groupResult.rows[0].id;

    // Assign the file to the group
    await pool.query("UPDATE ideas SET group_id = $1 WHERE id = $2", [
      groupId,
      id,
    ]);
    res.json({ message: `File assigned to group: ${groupName}` });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

//these are to capture unhandled errors
//you are to replace most console.log() with either logger.info() or logger.error()

process.on("uncaughtException", (err) => {
  logger.error(`🔥 Uncaught Exception: ${err.message}`);
});

process.on("unhandledRejection", (err) => {
  logger.error(`⚠️ Unhandled Rejection: ${err.message}`);
});

console.log("Registered Routes:");
app._router.stack.forEach((middleware) => {
  if (middleware.route) {
    console.log(
      `🔹 ${Object.keys(middleware.route.methods).join(", ").toUpperCase()} ${
        middleware.route.path
      }`
    );
  }
});

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
