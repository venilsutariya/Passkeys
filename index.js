// Express server setup for understanding passkeys
// This example is intentionally simplified and focuses on managing user registration with passkeys

const express = require("express");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const crypto = require("node:crypto");

if (!globalThis.crypto) {
  globalThis.crypto = crypto;
}

const PORT = 5555;
const app = express();

app.use(express.static("./public"));
app.use(express.json());

// In-memory user and challenge store (for demonstration purposes, not for production)
const userStore = {};
const challengeStore = {};

// User registration endpoint
app.use("/register", (req, res) => {
  const { username, password } = req.body;

  // Generate a unique ID for the user (using timestamp as a simple method)
  const id = `user_${Date.now()}`;

  const user = {
    id,
    username,
    password, // In a real application, you'd hash the password before storing it
  };

  userStore[id] = user;

  return res.json({ id });
});

// User register-challenge endpoint
app.post("/register-challenge", async (req, res) => {
  const { userId } = req.body;

  if (!userStore[userId]) {
    return res.status(404).json({ error: "user not found!" });
  }

  const challengePayload = await generateRegistrationOptions({
    rpID: "localhost",
    rpName: "passkey application",
    userName: userStore[userId].username,
  });

  challengeStore[userId] = challengePayload.challenge;

  return res.json({ options: challengePayload });
});

// User register-verify endpoint
app.post("/register-verify", async (req, res) => {
  const { userId, cred } = req.body;

  if (!userStore[userId]) {
    return res.status(404).json({ error: "user not found!" });
  }

  const user = userStore[userId];
  const challenge = challengeStore[userId];

  const verificationResult = await verifyRegistrationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:5555",
    expectedRPID: "localhost",
    response: cred,
  });

  if (!verificationResult.verified)
    return res.json({ error: "could not verify" });
  userStore[userId].passkey = verificationResult.registrationInfo;

  return res.json({ verified: true });
});

// User login-challenge endpoint
app.post("/login-challenge", async (req, res) => {
  const { userId } = req.body;

  if (!userStore[userId]) {
    return res.status(404).json({ error: "user not found!" });
  }

  const opts = await generateAuthenticationOptions({
    rpID: "localhost",
  });

  challengeStore[userId] = opts.challenge;

  return res.json({ options: opts });
});

// User register-verify endpoint
app.post("/login-verify", async (req, res) => {
  const { userId, cred } = req.body;

  if (!userStore[userId]) {
    return res.status(404).json({ error: "user not found!" });
  }

  const user = userStore[userId];
  const challenge = challengeStore[userId];

  const result = await verifyAuthenticationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:5555",
    expectedRPID: "localhost",
    response: cred,
    authenticator: user.passkey,
  });

  if (!result.verified) return res.json({ error: "could not verify" });

  //   Login the user
  return res.json({ success: true, userId });
});

// Start the server
app.listen(PORT, () =>
  console.log(`Server is running at http://localhost:${PORT}`)
);
