const express = require("express");
const dns = require("node:dns").promises;
const net = require("node:net");
const ipaddr = require("ipaddr.js");
const { Agent, fetch } = require("undici");
const cheerio = require("cheerio");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "20kb" }));
app.use(express.static("public"));

const PORT = process.env.PORT || 3000;
const MAX_HTML = 2 * 1024 * 1024;
const TIMEOUT_MS = 12000;
const MAX_REDIRECTS = 4;
const MAX_RESULTS = 60;

function isPublicAddress(address) {
  try {
    let ip = ipaddr.parse(address);
    if (ip.kind() === "ipv6" && ip.isIPv4MappedAddress()) ip = ip.toIPv4Address();
    return ip.range() === "unicast";
  } catch { return false; }
}

async function validateHost(hostname) {
  if (!hostname || hostname === "localhost" || hostname.endsWith(".localhost") ||
      hostname.endsWith(".local") || hostname.endsWith(".internal")) {
    throw new Error("تم رفض اسم مضيف محلي أو غير مسموح.");
  }
  if (net.isIP(hostname)) {
    if (!isPublicAddress(hostname)) throw new Error("تم رفض عنوان IP خاص أو محجوز.");
    return [hostname];
  }
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!records.length || records.some(r => !isPublicAddress(r.address))) {
    throw new Error("المضيف يشير إلى عنوان خاص أو محجوز، وتم رفض الطلب.");
  }
  return records.map(r => r.address);
}

async function safeRequest(inputUrl, method = "GET", maxBytes = MAX_HTML) {
  let current = new URL(inputUrl);
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (!["http:", "https:"].includes(current.protocol) || current.username || current.password) {
      throw new Error("يسمح فقط بروابط HTTP/HTTPS العامة ومن دون بيانات دخول داخل الرابط.");
    }
    const addresses = await validateHost(current.hostname);
    const pinnedAddress = addresses[0];
    const dispatcher = new Agent({
      connect: {
        lookup(host, opts, cb) {
          if (typeof opts === "function") cb = opts;
          cb(null, pinnedAddress, net.isIP(pinnedAddress));
        }
      }
    });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    let response;
    try {
      response = await fetch(current, {
        method, dispatcher, signal: controller.signal, redirect: "manual",
        headers: { "User-Agent": "StreamScanner/1.0 (public URL inspection)", "Accept": "text/html,application/vnd.apple.mpegurl,application/dash+xml,video/*,*/*;q=0.8" }
      });
      if ([301,302,303,307,308].includes(response.status)) {
        const location = response.headers.get("location");
        await response.body?.cancel();
        if (!location) throw new Error("إعادة توجيه غير صالحة.");
        if (hop === MAX_REDIRECTS) throw new Error("تجاوز الرابط الحد المسموح لإعادة التوجيه.");
        current = new URL(location, current);
        continue;
      }
      const contentType = response.headers.get("content-type") || "";
      const chunks = [];
      let total = 0;
      if (method !== "HEAD" && response.body) {
        for await (const chunk of response.body) {
          total += chunk.length;
          if (total > maxBytes) {
            controller.abort();
            throw new Error("حجم الصفحة أكبر من الحد المسموح للفحص.");
          }
          chunks.push(chunk);
        }
      }
      return {
        status: response.status, contentType, finalUrl: current.href,
        body: Buffer.concat(chunks).toString("utf8")
      };
    } finally {
      clearTimeout(timer);
      await dispatcher.close().catch(() => {});
    }
  }
  throw new Error("تعذر إكمال الطلب.");
}

function classify(url, tag = "") {
  const value = url.toLowerCase().split("?")[0];
  if (value.endsWith(".m3u8")) return "HLS / M3U8";
  if (value.endsWith(".mpd")) return "DASH / MPD";
  if (/\.(mp4|m4v|mov)$/.test(value)) return "MP4 / فيديو";
  if (value.endsWith(".ts")) return "MPEG-TS";
  if (/\.(webm|ogg)$/.test(value)) return "WebM / OGG";
  if (tag === "iframe" || tag === "embed") return "صفحة مشغل";
  return "رابط محتمل";
}
function absolute(raw, base) {
  try {
    const u = new URL(raw, base);
    if (!["http:", "https:"].includes(u.protocol) || u.username || u.password) return null;
    return u.href;
  } catch { return null; }
}

app.post("/api/scan", async (req, res) => {
  const input = String(req.body?.url || "").trim();
  const mode = ["auto", "page", "direct"].includes(req.body?.mode) ? req.body.mode : "auto";
  if (!input || input.length > 2048) return res.status(400).json({ error: "أدخل رابطًا صحيحًا." });
  let parsed;
  try { parsed = new URL(input); } catch { return res.status(400).json({ error: "صيغة الرابط غير صحيحة." }); }
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
    return res.status(400).json({ error: "يسمح فقط بروابط HTTP وHTTPS العامة." });
  }

  try {
    const page = await safeRequest(parsed.href, "GET", MAX_HTML);
    const $ = cheerio.load(page.body);
    const found = new Map();
    const add = (raw, tag = "") => {
      const url = absolute(raw, page.finalUrl);
      if (!url || found.has(url)) return;
      if (found.size < MAX_RESULTS) found.set(url, { url, type: classify(url, tag), tag });
    };

    const directLike = /\.(m3u8|mpd|mp4|m4v|mov|ts|webm|ogg)(\?|#|$)/i.test(parsed.pathname);
    if (mode === "direct" || directLike) add(page.finalUrl, "direct");
    if (mode !== "direct" && !directLike) {
      $("video, source, iframe, embed").each((_, el) => {
        const tag = el.tagName.toLowerCase();
        for (const attr of ["src", "data-src", "data-url", "data-video", "srcset"]) {
          const raw = $(el).attr(attr);
          if (raw) add(raw.split(",")[0].trim().split(/\s+/)[0], tag);
        }
      });
      $("a[href]").each((_, el) => add($(el).attr("href"), "a"));
      const patterns = [
        /https?:\\?\/\\?\/[^"'\\s<>]+?\.(?:m3u8|mpd|mp4|m4v|mov|ts|webm|ogg)(?:\?[^"'\\s<>]*)?/gi,
        /(?:file|source|src|hls|dash|stream|url)\s*[:=]\s*["']([^"']{5,2048})["']/gi
      ];
      for (const pattern of patterns) {
        let match;
        while ((match = pattern.exec(page.body)) !== null) add(match[1] || match[0], "code");
      }
    }

    const results = [];
    for (const item of found.values()) {
      let status = "لم يتم التحقق";
      let contentType = "";
      try {
        const check = await safeRequest(item.url, "HEAD", 1024);
        status = String(check.status);
        contentType = check.contentType;
      } catch (e) { status = "تعذر التحقق"; }
      results.push({ ...item, status, contentType });
    }

    res.json({
      scannedUrl: page.finalUrl, pageStatus: page.status, pageContentType: page.contentType,
      count: results.length, results,
      note: "الفحص يقرأ المصادر العامة الظاهرة في الصفحة فقط. لا ينفذ JavaScript ولا يتجاوز DRM أو تسجيل الدخول أو أنظمة الحماية."
    });
  } catch (error) {
    const message = error.name === "AbortError" ? "انتهت مهلة الاتصال." : error.message || "فشل الفحص.";
    res.status(422).json({ error: message });
  }
});

app.get("/health", (_, res) => res.json({ ok: true }));
app.listen(PORT, () => console.log(`Stream Scanner listening on ${PORT}`));
