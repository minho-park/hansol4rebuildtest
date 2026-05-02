const DATA_URL = "data.json";

const $ = (id) => document.getElementById(id);
const authCard = $("auth-card");
const videoCard = $("video-card");
const player = $("player");
const form = $("auth-form");
const nameInput = $("name");
const phoneInput = $("phone");
const submitBtn = $("submit-btn");
const statusEl = $("status");

const CRED_SEP = "";

function setStatus(text, kind = "") {
  statusEl.textContent = text;
  statusEl.className = "status" + (kind ? " " + kind : "");
}

function normalizePhone(raw) {
  return (raw || "").replace(/\D+/g, "");
}

function normalizeName(raw) {
  return (raw || "").normalize("NFC").trim();
}

function buildCredential(name, phone) {
  return name + CRED_SEP + phone;
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(credential, saltBytes, iterations) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(credential),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

async function tryDecryptEntry(entry, key) {
  try {
    const iv = b64ToBytes(entry.iv);
    const ct = b64ToBytes(entry.ct);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}

function isValidYouTubeId(id) {
  return /^[A-Za-z0-9_-]{11}$/.test(id);
}

function showVideo(videoId) {
  const url = new URL("https://www.youtube-nocookie.com/embed/" + videoId);
  url.searchParams.set("rel", "0");
  url.searchParams.set("modestbranding", "1");
  player.src = url.toString();
  authCard.classList.add("hidden");
  videoCard.classList.remove("hidden");
}

async function authenticate(credential) {
  if (location.protocol === "file:") {
    setStatus(
      "file:// 로 직접 열면 동작하지 않습니다. 로컬 서버(예: python3 -m http.server)로 띄워 주세요.",
      "error"
    );
    return;
  }

  let data;
  try {
    const res = await fetch(DATA_URL, { cache: "no-store" });
    if (!res.ok) throw new Error("data.json 로드 실패: " + res.status);
    data = await res.json();
  } catch (e) {
    setStatus("데이터를 불러오지 못했습니다. (콘솔 확인)", "error");
    console.error(e);
    return;
  }

  if (!data || !data.salt || !data.iterations || !Array.isArray(data.entries)) {
    setStatus("데이터 형식이 올바르지 않습니다.", "error");
    return;
  }

  const saltBytes = b64ToBytes(data.salt);
  const key = await deriveKey(credential, saltBytes, data.iterations);

  for (const entry of data.entries) {
    const pt = await tryDecryptEntry(entry, key);
    if (pt && isValidYouTubeId(pt)) {
      setStatus("인증 성공", "success");
      showVideo(pt);
      return;
    }
  }

  setStatus("등록되지 않은 정보입니다.", "error");
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = normalizeName(nameInput.value);
  const phone = normalizePhone(phoneInput.value);
  if (!name) {
    setStatus("이름을 입력해 주세요.", "error");
    return;
  }
  if (phone.length < 9) {
    setStatus("휴대폰 번호를 확인해 주세요.", "error");
    return;
  }
  submitBtn.disabled = true;
  setStatus("확인 중… (몇 초 걸릴 수 있어요)");
  try {
    await authenticate(buildCredential(name, phone));
  } finally {
    submitBtn.disabled = false;
  }
});
