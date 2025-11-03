import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

// 1x1 transparent PNG
const PIXEL = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII=",
  "base64"
);

const HMAC_SECRET = process.env.HMAC_SECRET || "dev-secret";

// In-memory map for link redirects
const redirectMap = new Map();

// HMAC signing helper
function sign(...parts) {
  const h = crypto.createHmac("sha256", HMAC_SECRET);
  h.update(parts.join("|"));
  return h.digest("hex");
}

// Pixel endpoint
app.get("/s/pixel", (req, res) => {
  const { tid, mid, sig } = req.query;
  if (!tid || !mid || !sig) return res.status(400).send("Missing parameters");

  const expectedSig = sign(tid, mid);
  if (sig !== expectedSig) return res.status(400).send("Invalid signature");

  console.log("OPEN:", { tid, mid, ip: req.ip, ua: req.get("User-Agent") });

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
app.get("/r/:token", (req, res) => {
  const token = req.params.token;
  const url = redirectMap.get(token);
  if (!url) return res.status(404).send("Unknown link");

  console.log("CLICK:", { token, ip: req.ip, ua: req.get("User-Agent") });
  res.redirect(302, url);
});

// API to create redirect links
app.post("/api/createLink", (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).send("Missing url");
  const token = crypto.randomBytes(4).toString("hex");
  redirectMap.set(token, url);
  res.json({ token });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server listening on ${port}`));
