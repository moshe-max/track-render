import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import { Pool } from "pg";

dotenv.config();

const app = express();
app.use(express.json());

// PNG 1x1 transparent pixel
const PIXEL = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII=",
  "base64"
);

const HMAC_SECRET = process.env.HMAC_SECRET || "dev-secret";
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// HMAC signature helper
function sign(...parts) {
  const h = crypto.createHmac("sha256", HMAC_SECRET);
  h.update(parts.join("|"));
  return h.digest("hex");
}

// Pixel endpoint
app.get("/s/pixel", async (req, res) => {
  const { tid, mid, sig } = req.query;
  if (!tid || !mid || !sig) return res.status(400).send("Missing parameters");
  const expectedSig = sign(tid, mid);
  if (sig !== expectedSig) return res.status(400).send("Invalid signature");

  await pool.query(
    "INSERT INTO events(type, tid, mid, ip) VALUES($1,$2,$3,$4)",
    ["OPEN", tid, mid, req.ip]
  );

  res.set({
    "Content-Type": "image/png",
    "Content-Length": PIXEL.length,
    "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
    Pragma: "no-cache",
    Expires: "0",
  });
  res.send(PIXEL);
});

// Redirect endpoint
app.get("/r/:token", async (req, res) => {
  const token = req.params.token;
  const result = await pool.query("SELECT url FROM redirects WHERE token=$1", [token]);
  if (!result.rows[0]) return res.status(404).send("Unknown link");

  await pool.query(
    "INSERT INTO events(type, token, url, ip) VALUES($1,$2,$3,$4)",
    ["CLICK", token, result.rows[0].url, req.ip]
  );

  res.redirect(302, result.rows[0].url);
});

// Create tokenized redirect
app.post("/api/createLink", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).send("Missing url");
  const token = crypto.randomBytes(4).toString("hex");
  await pool.query("INSERT INTO redirects(token, url) VALUES($1,$2)", [token, url]);
  res.json({ token });
});

// Stats for a specific tid
app.get("/api/stats/:tid", async (req, res) => {
  const { tid } = req.params;
  const result = await pool.query(
    "SELECT type, COUNT(*) as count FROM events WHERE tid=$1 GROUP BY type",
    [tid]
  );
  const stats = {};
  result.rows.forEach(r => stats[r.type] = parseInt(r.count));
  res.json({ tid, stats });
});

// Dashboard
app.get("/dashboard", async (req, res) => {
  const result = await pool.query("SELECT * FROM events ORDER BY created_at DESC LIMIT 100");
  let html = `<html><head><title>Dashboard</title>
    <style>
      body { font-family: Arial; margin: 20px; }
      table { border-collapse: collapse; width: 100%; }
      th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
      th { background-color: #eee; }
    </style></head><body>`;
  html += "<h1>Email Tracker Dashboard</h1>";
  html += "<table><tr><th>Type</th><th>tid/mid</th><th>Token</th><th>URL</th><th>Timestamp</th><th>IP</th></tr>";
  result.rows.forEach(ev => {
    html += `<tr>
      <td>${ev.type}</td>
      <td>${ev.tid || ev.mid || ""}</td>
      <td>${ev.token || ""}</td>
      <td>${ev.url || ""}</td>
      <td>${new Date(ev.created_at).toLocaleString()}</td>
      <td>${ev.ip}</td>
    </tr>`;
  });
  html += "</table></body></html>";
  res.send(html);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server listening on ${port}`));
