import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

// Transparent 1x1 pixel
const PIXEL = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII=",
  "base64"
);

const HMAC_SECRET = "dev-secret"; // optional: replace with env variable

// In-memory storage
const redirectMap = new Map(); // token -> URL
const events = []; // stores last events

// HMAC helper
function sign(...parts) {
  const h = crypto.createHmac("sha256", HMAC_SECRET);
  h.update(parts.join("|"));
  return h.digest("hex");
}

// Pixel tracking endpoint
app.get("/s/pixel", (req, res) => {
  const { tid, mid, sig } = req.query;
  if (!tid || !mid || !sig) return res.status(400).send("Missing parameters");

  if (sig !== sign(tid, mid)) return res.status(400).send("Invalid signature");

  events.push({
    type: "OPEN",
    tid,
    mid,
    ip: req.ip,
    timestamp: new Date()
  });

  res.set({
    "Content-Type": "image/png",
    "Content-Length": PIXEL.length,
    "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
    Pragma: "no-cache",
    Expires: "0",
  });
  res.send(PIXEL);
});

// Redirect endpoint (fixed to include tid/mid)
app.get("/r/:token", (req, res) => {
  const token = req.params.token;
  const url = redirectMap.get(token);
  if (!url) return res.status(404).send("Unknown link");

  const { tid, mid } = req.query; // include tid/mid from tracked link

  events.push({
    type: "CLICK",
    token,
    url,
    tid: tid || null,
    mid: mid || null,
    ip: req.ip,
    timestamp: new Date()
  });

  res.redirect(302, url);
});

// Create tokenized redirect
app.post("/api/createLink", (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).send("Missing url");

  const token = crypto.randomBytes(4).toString("hex");
  redirectMap.set(token, url);
  res.json({ token });
});

// Stats endpoint
app.get("/api/stats/:tid", (req, res) => {
  const { tid } = req.params;
  const filtered = events.filter(ev => ev.tid === tid);
  const stats = { OPEN: 0, CLICK: 0 };
  filtered.forEach(ev => { stats[ev.type] = (stats[ev.type] || 0) + 1 });
  res.json({ tid, stats });
});

// Dashboard
app.get("/dashboard", (req, res) => {
  let html = `<html><head><title>Dashboard</title>
    <style>
      body { font-family: Arial; margin: 20px; }
      table { border-collapse: collapse; width: 100%; }
      th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
      th { background-color: #eee; }
    </style></head><body>`;
  html += "<h1>Email Tracker Dashboard</h1>";
  html += "<table><tr><th>Type</th><th>tid</th><th>mid</th><th>Token</th><th>URL</th><th>Timestamp</th><th>IP</th></tr>";
  events.slice(-100).forEach(ev => {
    html += `<tr>
      <td>${ev.type}</td>
      <td>${ev.tid || ""}</td>
      <td>${ev.mid || ""}</td>
      <td>${ev.token || ""}</td>
      <td>${ev.url || ""}</td>
      <td>${ev.timestamp.toLocaleString()}</td>
      <td>${ev.ip}</td>
    </tr>`;
  });
  html += "</table></body></html>";
  res.send(html);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server listening on port ${port}`));
