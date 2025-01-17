const express = require("express");
const { Pool } = require("pg");
const dotenv = require("dotenv");

const crypto = require("crypto"); //hashes it
const nodemailer = require("nodemailer"); //send emails
const jwt = require("jsonwebtoken"); // generates jwt token which is more secure and scalable

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
  const hash_code = crypto.randomBytes(16).toString("hex"); // Generate a random 32-character hash

  try {
    // Invalidate previous hashes for this user
    await pool.query(
      "DELETE FROM hashes WHERE user_id = $1 AND expires_at < NOW()",
      [user_id]
    );

    // Insert new hash valid for one month
    const result = await pool.query(
      "INSERT INTO hashes (user_id, hash_code, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 month') RETURNING *",
      [user_id, hash_code]
    );

    return result.rows[0]; // Return the newly created hash
  } catch (err) {
    console.error("Error generating hash:", err.message);
    throw err;
  }
}

//email sending function using nodemailer
async function sendHashByEmail(email, hash_code) {
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
    console.error("Error sending email " + email, err);
  }
}

//this is a route to trigger hash generation (it can be autmate it with a cron job later on)
app.post("/generate-hash", async (req, res) => {
  const user_id = 1; // Since there's only one user (you)
  try {
    const newHash = await generateMonthlyHash(user_id);
    await sendHashByEmail("frankalfaro105@gmail.com", newHash.hash_code);
    return res.json({
      message: "New monthly hash generated and sent to email!",
      hash: newHash,
    }); // Added return
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// this is the login verification - the user (me) will submit the hash for verification and chekc if its valid
app.post("/login", async (req, res) => {
  const { hash_code } = req.body; //get hash from user input

  try {
    const result = await pool.query(
      "SELECT * FROM hashes WHERE hash_code = $1 AND expires_at > NOW()",
      [hash_code]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid or expired hash." });
    }

    //generate a JWT token
    const token = jwt.sign(
      { user_id: result.rows[0].user_id },
      process.env.JWT_SECRET, // Ensure this matches your .env file
      { expiresIn: process.env.JWT_EXPIRATION }
    );

    //else confirm that it was a sucessful login
    res.json({ message: "Login successful!", token }); //gives jwt token that will be used
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Server Errors" });
  }
});

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

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  console.log("Auth Header:", authHeader); // Debugging

  if (!authHeader) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  const token = authHeader.split(" ")[1]; // Extract token after "Bearer"
  console.log("Extracted Token:", token); // Debugging

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token." });
    }

    req.user = decoded; // Attach decoded user info
    next();
  });
}

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
