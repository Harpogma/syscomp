// Chargement de SecLists — 10-million-password-list-top-100000.txt
// Source: https://github.com/danielmiessler/SecLists
const SECLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt";

let PASSWORD_MAP = new Map();   // password → rank (1-based)
let LIST_SIZE    = 0;
let listReady    = false;

async function loadPasswordList(onProgress, onReady) {
  try {
    const res = await fetch(SECLIST_URL);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const text = await res.text();
    const lines = text.split('\n');
    LIST_SIZE = 0;

    lines.forEach((line, i) => {
      const p = line.trim();
      if (p && !PASSWORD_MAP.has(p)) {
        PASSWORD_MAP.set(p, i + 1);
        LIST_SIZE++;
      }
    });

    listReady = true;
    onReady(LIST_SIZE);
  } catch (err) {
    onProgress(`erreur : ${err.message}`);
  }
}

// ── Benchmarks hashcat (RTX 4090) ──────────────────────────────────────────
const HASH_BENCHMARKS = {
  "NTLM":    { speed: 100_000_000_000, label: "NTLM (Windows)" },
  "MD5":     { speed:  56_000_000_000, label: "MD5" },
  "SHA-1":   { speed:  19_000_000_000, label: "SHA-1" },
  "SHA-256": { speed:   8_900_000_000, label: "SHA-256" },
  "WPA2":    { speed:       1_600_000, label: "WPA2-PBKDF2" },
  "bcrypt":  { speed:         184_000, label: "bcrypt (cost 5)" },
};

function estimateCrackTime(password) {
  const charset = getCharset(password);
  const combinations = Math.pow(charset, password.length);
  return Object.entries(HASH_BENCHMARKS).map(([algo, { speed, label }]) => {
    const seconds = combinations / speed;
    return { algo, label, speed, seconds, human: formatTime(seconds) };
  });
}

function getCharset(password) {
  let size = 0;
  if (/[a-z]/.test(password)) size += 26;
  if (/[A-Z]/.test(password)) size += 26;
  if (/[0-9]/.test(password)) size += 10;
  if (/[^a-zA-Z0-9]/.test(password)) size += 32;
  return size || 26;
}

function formatTime(seconds) {
  if (seconds < 0.001)           return "< 1 milliseconde";
  if (seconds < 1)               return `${(seconds * 1000).toFixed(0)} ms`;
  if (seconds < 60)              return `${seconds.toFixed(1)} secondes`;
  if (seconds < 3600)            return `${(seconds / 60).toFixed(1)} minutes`;
  if (seconds < 86400)           return `${(seconds / 3600).toFixed(1)} heures`;
  if (seconds < 86400 * 365)     return `${(seconds / 86400).toFixed(1)} jours`;
  if (seconds < 86400 * 365 * 1e3)  return `${(seconds / (86400*365)).toFixed(0)} ans`;
  if (seconds < 86400 * 365 * 1e9)  return `${(seconds / (86400*365*1e6)).toFixed(0)} millions d'années`;
  return "∞ (hors de portée)";
}

function getStrengthScore(password) {
  let score = 0;
  if (password.length >= 8)  score++;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  if (!PASSWORD_MAP.has(password)) score++;
  return score;
}

function getStrengthLabel(score) {
  if (score <= 1) return { label: "CRITIQUE",    color: "#ff3333", bar: 1 };
  if (score <= 2) return { label: "TRÈS FAIBLE", color: "#ff6600", bar: 2 };
  if (score <= 3) return { label: "FAIBLE",      color: "#ffaa00", bar: 3 };
  if (score <= 4) return { label: "MOYEN",       color: "#ffdd00", bar: 4 };
  if (score <= 5) return { label: "BON",         color: "#88cc00", bar: 5 };
  if (score <= 6) return { label: "FORT",        color: "#00cc66", bar: 6 };
  return              { label: "TRÈS FORT",  color: "#00ffaa", bar: 7 };
}
