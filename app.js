const DATA_URL = "data.json";

const $ = (id) => document.getElementById(id);
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

// v3: 각 entry는 콘텐츠 키(32B)를 사용자 키로 암호화한 것
async function tryDecryptContentKey(entry, userKey) {
  try {
    const iv = b64ToBytes(entry.iv);
    const ct = b64ToBytes(entry.ct);
    const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, userKey, ct);
    return new Uint8Array(raw);
  } catch {
    return null;
  }
}

function showSecretPage(html) {
  document.open();
  document.write(html);
  document.close();
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
  const userKey = await deriveKey(credential, saltBytes, data.iterations);

  for (const entry of data.entries) {
    const contentKeyBytes = await tryDecryptContentKey(entry, userKey);
    if (contentKeyBytes === null) continue;

    // 콘텐츠 키로 실제 HTML 복호화
    const contentKey = await crypto.subtle.importKey(
      "raw",
      contentKeyBytes,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    try {
      const contentIv = b64ToBytes(data.content.iv);
      const contentCt = b64ToBytes(data.content.ct);
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: contentIv },
        contentKey,
        contentCt
      );
      const html = new TextDecoder().decode(pt);
      setStatus("인증 성공", "success");
      showSecretPage(html);
    } catch {
      // 콘텐츠 키 복호화는 됐으나 콘텐츠 복호화 실패 (데이터 손상)
      setStatus("데이터를 복호화하지 못했습니다.", "error");
    }
    return;
  }

  setStatus("등록되지 않은 정보입니다.\n아래 대표번호로 연락하여 소유주 등록을 해주세요.", "error");
}

phoneInput.addEventListener("input", (e) => {
  const cleaned = e.target.value.replace(/[^\d-]/g, "");
  if (e.target.value !== cleaned) {
    const pos = e.target.selectionStart - (e.target.value.length - cleaned.length);
    e.target.value = cleaned;
    if (pos >= 0) e.target.setSelectionRange(pos, pos);
  }
});

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
