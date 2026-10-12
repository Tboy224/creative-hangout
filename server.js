const crypto = require("crypto");
const fsSync = require("fs");
const fs = require("fs/promises");
const http = require("http");
const path = require("path");
const tls = require("tls");

function loadEnvFile() {
  const envPath = path.join(__dirname, ".env");

  if (!fsSync.existsSync(envPath)) return;

  const text = fsSync.readFileSync(envPath, "utf8");

  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith("#")) continue;

    const separatorIndex = trimmed.indexOf("=");

    if (separatorIndex === -1) continue;

    const key = trimmed.slice(0, separatorIndex).trim();
    const value = trimmed.slice(separatorIndex + 1).trim();

    if (key && process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

loadEnvFile();

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, "data");
const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(ROOT, "uploads");
const DB_PATH = path.join(DATA_DIR, "registrations.json");
const MAX_BODY_SIZE = 8 * 1024 * 1024;
const EVENT_NAME = process.env.EVENT_NAME || "The Creative Hangout";
const EVENT_FEE_NAIRA = Number(process.env.EVENT_FEE_NAIRA || 2000);
const BANK_NAME = process.env.BANK_NAME || "Bank name";
const BANK_ACCOUNT_NAME = process.env.BANK_ACCOUNT_NAME || "Account name";
const BANK_ACCOUNT_NUMBER = process.env.BANK_ACCOUNT_NUMBER || "0000000000";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "creativehangout2026";
const ADMIN_SESSION_SECRET = process.env.ADMIN_SESSION_SECRET || "change-this-admin-session-secret";
const SESSION_COOKIE_NAME = "creative_hangout_admin";
const SMTP_HOST = process.env.SMTP_HOST || "";
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const EMAIL_FROM = process.env.EMAIL_FROM || SMTP_USER;
const SMTP_ALLOW_INSECURE_TLS = process.env.SMTP_ALLOW_INSECURE_TLS === "true";

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".pdf": "application/pdf"
};
async function ensureStorage() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.mkdir(UPLOADS_DIR, { recursive: true });

  try {
    await fs.access(DB_PATH);
  } catch {
    await fs.writeFile(DB_PATH, "[]\n", "utf8");
  }
}

async function readRegistrations() {
  await ensureStorage();
  const text = await fs.readFile(DB_PATH, "utf8");
  return JSON.parse(text || "[]");
}

async function writeRegistrations(registrations) {
  const tempPath = `${DB_PATH}.tmp`;
  await fs.writeFile(tempPath, `${JSON.stringify(registrations, null, 2)}\n`, "utf8");
  await fs.rename(tempPath, DB_PATH);
}

function sendJson(res, status, data) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(data));
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

function safeCompare(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function parseCookies(req) {
  const cookies = {};
  const header = req.headers.cookie || "";

  for (const part of header.split(";")) {
    const separatorIndex = part.indexOf("=");

    if (separatorIndex === -1) continue;

    const key = part.slice(0, separatorIndex).trim();
    const value = part.slice(separatorIndex + 1).trim();
    cookies[key] = decodeURIComponent(value);
  }

  return cookies;
}

function createSessionToken() {
  const issuedAt = Date.now().toString();
  const signature = crypto
    .createHmac("sha256", ADMIN_SESSION_SECRET)
    .update(`${ADMIN_USERNAME}:${issuedAt}`)
    .digest("hex");

  return `${issuedAt}.${signature}`;
}

function verifySessionToken(token) {
  if (!token || !token.includes(".")) {
    return false;
  }

  const [issuedAt, signature] = token.split(".");
  const age = Date.now() - Number(issuedAt);
  const maxAge = 24 * 60 * 60 * 1000;

  if (!Number.isFinite(age) || age < 0 || age > maxAge) {
    return false;
  }

  const expectedSignature = crypto
    .createHmac("sha256", ADMIN_SESSION_SECRET)
    .update(`${ADMIN_USERNAME}:${issuedAt}`)
    .digest("hex");

  return safeCompare(signature, expectedSignature);
}

function isAdminRequest(req) {
  const cookies = parseCookies(req);
  return verifySessionToken(cookies[SESSION_COOKIE_NAME]);
}

function requireAdmin(req, res) {
  if (isAdminRequest(req)) {
    return true;
  }

  const acceptsHtml = (req.headers.accept || "").includes("text/html");

  if (acceptsHtml) {
    redirect(res, "/admin-login.html");
    return false;
  }

  sendJson(res, 401, { error: "Admin login required." });
  return false;
}

async function handleAdminLogin(req, res) {
  try {
    const body = await readBody(req);
    const data = JSON.parse(body || "{}");
    const usernameMatches = safeCompare(data.username || "", ADMIN_USERNAME);
    const passwordMatches = safeCompare(data.password || "", ADMIN_PASSWORD);

    if (!usernameMatches || !passwordMatches) {
      sendJson(res, 401, { error: "Invalid username or password." });
      return;
    }

    const token = createSessionToken();
    res.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
      "Set-Cookie": `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`
    });
    res.end(JSON.stringify({ ok: true }));
  } catch (error) {
    sendJson(res, 500, { error: error.message || "Login failed." });
  }
}

function handleAdminLogout(res) {
  res.writeHead(302, {
    Location: "/admin-login.html",
    "Set-Cookie": `${SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`
  });
  res.end();
}

function smtpRequest(socket, command, expectedCodes) {
  return new Promise((resolve, reject) => {
    let response = "";
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error("SMTP request timed out."));
    }, 30000);

    function cleanup() {
      clearTimeout(timeout);
      socket.off("data", handleData);
      socket.off("error", handleError);
    }

    function handleError(error) {
      cleanup();
      reject(error);
    }

    function handleData(chunk) {
      response += chunk.toString("utf8");
      const lines = response.trimEnd().split(/\r?\n/);
      const lastLine = lines[lines.length - 1] || "";
      const code = Number(lastLine.slice(0, 3));
      const pendingMoreLines = /^\d{3}-/.test(lastLine);

      if (!pendingMoreLines && expectedCodes.includes(code)) {
        cleanup();
        resolve(response);
        return;
      }

      if (!pendingMoreLines && Number.isInteger(code) && !expectedCodes.includes(code)) {
        cleanup();
        reject(new Error(`SMTP error: ${response.trim()}`));
      }
    }

    socket.on("data", handleData);
    socket.on("error", handleError);

    if (command) {
      socket.write(`${command}\r\n`);
    }
  });
}

function encodeEmailSubject(subject) {
  return `=?UTF-8?B?${Buffer.from(subject, "utf8").toString("base64")}?=`;
}

function formatAddress(address) {
  const match = String(address).match(/^(.*)<([^>]+)>$/);

  if (!match) {
    return address;
  }

  const name = match[1].trim().replace(/^"|"$/g, "");
  const email = match[2].trim();
  return `"${name.replace(/"/g, '\\"')}" <${email}>`;
}

function extractEmailAddress(address) {
  const match = String(address).match(/<([^>]+)>/);
  return match ? match[1].trim() : String(address).trim();
}

async function sendApprovalEmail(registration) {
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !EMAIL_FROM) {
    throw new Error("SMTP email settings are not configured.");
  }

  const socket = tls.connect({
    host: SMTP_HOST,
    port: SMTP_PORT,
    servername: SMTP_HOST,
    rejectUnauthorized: !SMTP_ALLOW_INSECURE_TLS
  });

  socket.on("error", () => {});

  try {
    await smtpRequest(socket, null, [220]);
    await smtpRequest(socket, `EHLO ${SMTP_HOST}`, [250]);
    await smtpRequest(socket, "AUTH LOGIN", [334]);
    await smtpRequest(socket, Buffer.from(SMTP_USER).toString("base64"), [334]);
    await smtpRequest(socket, Buffer.from(SMTP_PASS).toString("base64"), [235]);

    const fromEmail = extractEmailAddress(EMAIL_FROM);
    await smtpRequest(socket, `MAIL FROM:<${fromEmail}>`, [250]);
    await smtpRequest(socket, `RCPT TO:<${registration.email}>`, [250, 251]);
    await smtpRequest(socket, "DATA", [354]);

    const subject = `${EVENT_NAME} confirmation code`;
    const message = [
      `From: ${formatAddress(EMAIL_FROM)}`,
      `To: ${registration.email}`,
      `Subject: ${encodeEmailSubject(subject)}`,
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=utf-8",
      "",
      `Hi ${registration.name},`,
      "",
      `Your payment for ${EVENT_NAME} has been approved.`,
      `Your confirmation code is: ${registration.code}`,
      "",
      "Please keep this code safe and bring it with you for check-in.",
      "",
      EVENT_NAME,
      "."
    ].join("\r\n");

    await smtpRequest(socket, message, [250]);
    await smtpRequest(socket, "QUIT", [221]);
  } finally {
    socket.end();
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > MAX_BODY_SIZE) {
        reject(new Error("Upload is too large. Please use a receipt under 8MB."));
        req.destroy();
      }
    });

    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function cleanFileName(name) {
  const safe = String(name || "receipt").replace(/[^a-z0-9._-]/gi, "-").slice(0, 80);
  return safe || "receipt";
}

function getReceiptExtension(receipt) {
  const fromName = path.extname(receipt.name || "").toLowerCase();
  if ([".jpg", ".jpeg", ".png", ".webp", ".pdf"].includes(fromName)) {
    return fromName;
  }

  if (receipt.type === "application/pdf") return ".pdf";
  if (receipt.type === "image/png") return ".png";
  if (receipt.type === "image/webp") return ".webp";
  return ".jpg";
}

function createCode(registrations) {
  const usedCodes = new Set(
    registrations
      .map((registration) => Number(registration.code))
      .filter((code) => Number.isInteger(code) && code >= 1 && code <= 60)
  );

  for (let code = 1; code <= 60; code += 1) {
    if (!usedCodes.has(code)) {
      return String(code);
    }
  }

  throw new Error("All 60 hangout slots have been taken.");
}

function required(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function validateRegistration(data) {
  const fields = [
    "name",
    "email",
    "phone",
    "location",
    "skill",
    "department",
    "level",
    "businessOwner",
    "inviting",
    "expectation"
  ];

  for (const field of fields) {
    if (!required(data[field])) {
      return `${field} is required.`;
    }
  }

  if (!data.receipt || !required(data.receipt.content)) {
    return "Receipt is required.";
  }

  return null;
}

async function saveReceipt(receipt, code) {
  if (!receipt || !required(receipt.content)) {
    return "";
  }

  const extension = getReceiptExtension(receipt);
  const base64 = receipt.content.replace(/^data:[^;]+;base64,/, "");
  const originalName = cleanFileName(path.basename(receipt.name, path.extname(receipt.name)));
  const fileName = `${code}-${originalName}${extension}`;
  const filePath = path.join(UPLOADS_DIR, fileName);

  await fs.writeFile(filePath, Buffer.from(base64, "base64"));
  return `/uploads/${fileName}`;
}

function handleConfig(res) {
  sendJson(res, 200, {
    eventName: EVENT_NAME,
    feeNaira: EVENT_FEE_NAIRA,
    bankName: BANK_NAME,
    bankAccountName: BANK_ACCOUNT_NAME,
    bankAccountNumber: BANK_ACCOUNT_NUMBER
  });
}

async function handleRegister(req, res) {
  try {
    const body = await readBody(req);
    const data = JSON.parse(body || "{}");
    const validationError = validateRegistration(data);

    if (validationError) {
      sendJson(res, 400, { error: validationError });
      return;
    }

    const registrations = await readRegistrations();
    const existingPending = registrations.find(
      (registration) => registration.email.toLowerCase() === data.email.trim().toLowerCase()
        && registration.paymentStatus === "Pending review"
    );

    if (existingPending) {
      sendJson(res, 409, { error: "This email already has a pending registration." });
      return;
    }

    const pendingId = `TCH-PENDING-${Date.now()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
    const receiptUrl = await saveReceipt(data.receipt, pendingId);

    const registration = {
      id: pendingId,
      code: "",
      name: data.name.trim(),
      email: data.email.trim(),
      phone: data.phone.trim(),
      location: data.location.trim(),
      skill: data.skill.trim(),
      department: data.department.trim(),
      level: data.level.trim(),
      businessOwner: data.businessOwner,
      inviting: data.inviting,
      expectation: data.expectation.trim(),
      receiptUrl,
      paymentReference: pendingId,
      paidAmount: EVENT_FEE_NAIRA,
      paymentStatus: "Pending review",
      createdAt: new Date().toISOString()
    };

    registrations.unshift(registration);
    await writeRegistrations(registrations);

    sendJson(res, 201, {
      reference: registration.paymentReference,
      paymentStatus: registration.paymentStatus
    });
  } catch (error) {
    sendJson(res, 500, { error: error.message || "Registration failed." });
  }
}

async function handleApproveRegistration(req, res) {
  try {
    const body = await readBody(req);
    const data = JSON.parse(body || "{}");
    const registrations = await readRegistrations();
    const registration = registrations.find((item) => item.paymentReference === data.reference || item.id === data.reference);

    if (!registration) {
      sendJson(res, 404, { error: "Registration not found." });
      return;
    }

    if (registration.paymentStatus !== "Approved") {
      registration.code = createCode(registrations);
      registration.paymentStatus = "Approved";
      registration.approvedAt = new Date().toISOString();
      await writeRegistrations(registrations);
    }

    if (registration.emailStatus === "Sent") {
      sendJson(res, 200, { registration });
      return;
    }

    try {
      await sendApprovalEmail(registration);
      registration.emailStatus = "Sent";
      registration.emailSentAt = new Date().toISOString();
      await writeRegistrations(registrations);
    } catch (error) {
      registration.emailStatus = "Failed";
      registration.emailError = error.message || "Email could not be sent.";
      await writeRegistrations(registrations);
      sendJson(res, 500, {
        error: `Approved, but email failed: ${registration.emailError}`,
        registration
      });
      return;
    }

    sendJson(res, 200, { registration });
  } catch (error) {
    sendJson(res, 500, { error: error.message || "Could not approve registration." });
  }
}

async function handleRejectRegistration(req, res) {
  try {
    const body = await readBody(req);
    const data = JSON.parse(body || "{}");
    const registrations = await readRegistrations();
    const registration = registrations.find((item) => item.paymentReference === data.reference || item.id === data.reference);

    if (!registration) {
      sendJson(res, 404, { error: "Registration not found." });
      return;
    }

    registration.paymentStatus = "Rejected";
    registration.rejectedAt = new Date().toISOString();
    await writeRegistrations(registrations);
    sendJson(res, 200, { registration });
  } catch (error) {
    sendJson(res, 500, { error: error.message || "Could not reject registration." });
  }
}

async function handleListRegistrations(res) {
  try {
    const registrations = await readRegistrations();
    sendJson(res, 200, { registrations });
  } catch (error) {
    sendJson(res, 500, { error: error.message || "Could not load registrations." });
  }
}

async function serveStatic(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const requestedPath = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
  const normalized = path.normalize(requestedPath).replace(/^(\.\.[/\\])+/, "");
  const filePath = path.join(ROOT, normalized);

  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  try {
    const file = await fs.readFile(filePath);
    const extension = path.extname(filePath).toLowerCase();
    res.writeHead(200, { "Content-Type": contentTypes[extension] || "application/octet-stream" });
    res.end(file);
  } catch {
    res.writeHead(404);
    res.end("Not found");
  }
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/api/config") {
    handleConfig(res);
    return;
  }

  if (req.method === "POST" && req.url === "/api/register") {
    await handleRegister(req, res);
    return;
  }

  if (req.method === "POST" && req.url === "/api/admin/login") {
    await handleAdminLogin(req, res);
    return;
  }

  if (req.method === "GET" && req.url === "/admin/logout") {
    handleAdminLogout(res);
    return;
  }

  if (req.method === "GET" && req.url === "/api/registrations") {
    if (!requireAdmin(req, res)) return;
    await handleListRegistrations(res);
    return;
  }

  if (req.method === "POST" && req.url === "/api/admin/approve") {
    if (!requireAdmin(req, res)) return;
    await handleApproveRegistration(req, res);
    return;
  }

  if (req.method === "POST" && req.url === "/api/admin/reject") {
    if (!requireAdmin(req, res)) return;
    await handleRejectRegistration(req, res);
    return;
  }

  if (req.method === "GET") {
    const url = new URL(req.url, `http://${req.headers.host}`);

    if ((url.pathname === "/admin.html" || url.pathname.startsWith("/uploads/")) && !requireAdmin(req, res)) {
      return;
    }

    await serveStatic(req, res);
    return;
  }

  res.writeHead(405);
  res.end("Method not allowed");
});

ensureStorage()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`Hangout registration app running at http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
