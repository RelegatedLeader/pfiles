const express = require("express");
const { Pool } = require("pg");
const dotenv = require("dotenv");

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

app.get("/ideas", async (req, res) => {
  try {
    const result = await pool.query("Select * from ideas");
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
app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
