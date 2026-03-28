"use strict";
require("dotenv").config();
const express  = require("express");
const cors     = require("cors");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const { nanoid } = require("nanoid");
const fetch    = require("node-fetch");
const crypto   = require("crypto");
const path     = require("path");
const fs       = require("fs");
const multer   = require("multer");
const mammoth  = require("mammoth");
const { Document, Packer, Paragraph, TextRun, HeadingLevel,
        AlignmentType, LevelFormat } = require("docx");
const db = require("./db");

const app = express();
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));
app.use(express.static(path.join(__dirname, "../public")));

const JWT_SECRET = process.env.JWT_SECRET  || "wenjiang-secret-change-me";
const ADMIN_KEY  = process.env.ADMIN_KEY   || "wenjiang-admin-2026";
const HPJ_APPID  = process.env.HPJ_APPID  || "";
const HPJ_SECRET = process.env.HPJ_SECRET || "";
const BASE_URL   = process.env.BASE_URL   || "http://localhost:3724";
const CLAUDE_KEY = process.env.CLAUDE_KEY || "";

// ── 上传目录 ─────────────────────────────────────────
const UPLOAD_DIR = path.join(__dirname, "../data/uploads");
const OUTPUT_DIR = path.join(__dirname, "../data/outputs");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /\.(docx|doc|pdf)$/i.test(file.originalname);
    cb(null, ok);
  },
});

// ── 套餐配置 ─────────────────────────────────────────
const PLANS = {
  monthly:   { name: "基础版·月付", price: 29900, days: 30  },
  quarterly: { name: "基础版·季付", price: 79900, days: 90  },
  yearly:    { name: "基础版·年付", price: 29900, days: 365 },
};

const FREE_LIMIT    = 3;   // 免费试用次数
const MONTHLY_LIMIT = 500; // 每月处理文件数

// ── 虎皮椒签名 ────────────────────────────────────────
function hpjSign(params, appSecret) {
  const str = Object.keys(params)
    .filter(k => k !== "hash" && params[k] !== null && params[k] !== undefined && params[k] !== "")
    .sort()
    .map(k => `${k}=${params[k]}`)
    .join("&");
  return crypto.createHash("md5").update(str + appSecret).digest("hex");
}

// ── 模板定义 ─────────────────────────────────────────
const TEMPLATES = {
  business: {
    name: "通用商务文档",
    fontBody: "宋体", sizeBody: 24,
    fontHeading: "黑体",
    h1: { size: 32, bold: true, align: AlignmentType.CENTER },
    h2: { size: 28, bold: true, align: AlignmentType.LEFT },
    h3: { size: 24, bold: true, align: AlignmentType.LEFT },
    lineSpacing: 360,
    margin: { top: 1440, bottom: 1440, left: 1814, right: 1814 },
  },
  official: {
    name: "政府公文格式",
    fontBody: "仿宋_GB2312", sizeBody: 24,
    fontHeading: "方正小标宋简体",
    h1: { size: 44, bold: false, align: AlignmentType.CENTER },
    h2: { size: 24, bold: true,  align: AlignmentType.LEFT },
    h3: { size: 24, bold: false, align: AlignmentType.LEFT },
    lineSpacing: 560,
    margin: { top: 2126, bottom: 2006, left: 1606, right: 1490 },
  },
  contract: {
    name: "合同协议格式",
    fontBody: "宋体", sizeBody: 24,
    fontHeading: "宋体",
    h1: { size: 28, bold: true,  align: AlignmentType.CENTER },
    h2: { size: 24, bold: true,  align: AlignmentType.LEFT },
    h3: { size: 24, bold: true,  align: AlignmentType.LEFT },
    lineSpacing: 360,
    margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 },
  },
  technical: {
    name: "技术报告格式",
    fontBody: "宋体", sizeBody: 24,
    fontHeading: "黑体",
    h1: { size: 28, bold: true,  align: AlignmentType.LEFT },
    h2: { size: 24, bold: true,  align: AlignmentType.LEFT },
    h3: { size: 24, bold: true,  align: AlignmentType.LEFT },
    lineSpacing: 360,
    margin: { top: 1440, bottom: 1440, left: 1814, right: 1814 },
  },
};

// ── 鉴权中间件 ────────────────────────────────────────
function authUser(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "未登录" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "登录已过期，请重新登录" }); }
}

function authAdmin(req, res, next) {
  const k = req.headers["x-admin-key"] || req.query.admin;
  if (k !== ADMIN_KEY) return res.status(401).json({ error: "无权限" });
  next();
}

// ── 注册 ──────────────────────────────────────────────
app.post("/api/register", async (req, res) => {
  const { phone, password, name, company } = req.body;
  if (!phone || !password) return res.status(400).json({ error: "手机号和密码必填" });
  if (!/^1[3-9]\d{9}$/.test(phone)) return res.status(400).json({ error: "手机号格式不正确" });
  if (password.length < 6) return res.status(400).json({ error: "密码至少6位" });
  if (db.prepare("SELECT id FROM users WHERE phone=?").get(phone))
    return res.status(400).json({ error: "该手机号已注册" });
  const hash = await bcrypt.hash(password, 10);
  db.prepare("INSERT INTO users(phone,password,name,company) VALUES(?,?,?,?)").run(phone, hash, name||"", company||"");
  res.json({ ok: true });
});

// ── 登录 ──────────────────────────────────────────────
app.post("/api/login", async (req, res) => {
  const { phone, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE phone=?").get(phone);
  if (!user) return res.status(400).json({ error: "手机号或密码错误" });
  if (!await bcrypt.compare(password, user.password))
    return res.status(400).json({ error: "手机号或密码错误" });
  if (user.expires && user.expires < new Date().toISOString().slice(0,10)) {
    db.prepare("UPDATE users SET status='expired' WHERE id=?").run(user.id);
    user.status = "expired";
  }
  db.prepare("UPDATE users SET last_login=datetime('now','localtime') WHERE id=?").run(user.id);
  db.prepare("INSERT INTO usage_log(user_id,phone,action) VALUES(?,?,?)").run(user.id, phone, "login");
  const token = jwt.sign({ id: user.id, phone: user.phone }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ ok: true, token, user: { phone: user.phone, name: user.name, company: user.company, status: user.status, plan: user.plan, expires: user.expires } });
});

// ── 用户信息 ──────────────────────────────────────────
app.get("/api/me", authUser, (req, res) => {
  const user = db.prepare("SELECT phone,name,company,status,plan,expires,free_uses,month_uses,month_year FROM users WHERE id=?").get(req.user.id);
  if (!user) return res.status(404).json({ error: "用户不存在" });
  if (user.expires && user.expires < new Date().toISOString().slice(0,10)) {
    db.prepare("UPDATE users SET status='expired' WHERE id=?").run(req.user.id);
    user.status = "expired";
  }
  const curMonth = new Date().toISOString().slice(0,7);
  const monthUses = user.month_year === curMonth ? (user.month_uses||0) : 0;
  res.json({ ...user, monthUses, monthRemaining: Math.max(0, MONTHLY_LIMIT - monthUses), freeRemaining: Math.max(0, FREE_LIMIT - (user.free_uses||0)) });
});

// ════════════════════════════════════════════════════
// ── 核心功能：文件处理 ────────────────────────────────
// ════════════════════════════════════════════════════

// ── 权限检查 & 扣量 ───────────────────────────────────
function checkAndDeduct(userId) {
  const user = db.prepare("SELECT * FROM users WHERE id=?").get(userId);
  const curMonth = new Date().toISOString().slice(0,7);

  if (user.status === "active") {
    const monthUses = user.month_year === curMonth ? (user.month_uses||0) : 0;
    if (monthUses >= MONTHLY_LIMIT) return { ok: false, error: `本月处理次数已达上限（${MONTHLY_LIMIT}次）` };
    if (user.month_year !== curMonth) {
      db.prepare("UPDATE users SET month_uses=1, month_year=? WHERE id=?").run(curMonth, userId);
    } else {
      db.prepare("UPDATE users SET month_uses=month_uses+1 WHERE id=?").run(userId);
    }
    return { ok: true };
  }

  const used = user.free_uses || 0;
  if (used >= FREE_LIMIT) return { ok: false, error: "免费次数已用完，请订阅后继续使用" };
  db.prepare("UPDATE users SET free_uses=free_uses+1 WHERE id=?").run(userId);
  return { ok: true };
}

// ── 提取 Word 文本结构 ────────────────────────────────
async function extractDocxStructure(filePath) {
  const result = await mammoth.extractRawText({ path: filePath });
  return result.value;
}

// ── 调用 Claude 分析并重排文档结构 ────────────────────
async function analyzeWithClaude(rawText, templateKey) {
  const tpl = TEMPLATES[templateKey] || TEMPLATES.business;
  const prompt = `你是一个专业的文档排版专家。我将给你一段从Word文档中提取的原始文本，请你分析其内容结构，并按照以下规则输出一个JSON格式的文档结构。

模板类型：${tpl.name}

输出要求：
返回一个JSON数组，每个元素代表一个段落，格式如下：
{
  "type": "h1" | "h2" | "h3" | "body" | "list",
  "text": "段落文本内容",
  "numbering": "编号（如有，如'第一条'/'1.1'/'（一）'等，提取出来单独放这里）"
}

判断规则：
- h1：文档主标题，通常居中，全文只有1-2个
- h2：章节标题，如"第一章"、"一、"、数字编号如"1."开头的主要章节
- h3：小节标题，如"（一）"、"1.1"、"第一条"等
- body：正文段落
- list：列表项（以序号、•、-等开头的条目）
- 空行和纯空白内容请忽略，不要输出
- numbering字段：如果标题或条款本身带有编号前缀，请将编号提取到numbering字段，text里只保留标题内容

只返回JSON数组，不要有任何其他说明文字。

原始文本：
${rawText.slice(0, 8000)}`;

  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": CLAUDE_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 4096,
      messages: [{ role: "user", content: prompt }],
    }),
  });

  if (!response.ok) {
    const t = await response.text();
    throw new Error("AI服务错误: " + t.slice(0, 200));
  }

  const data = await response.json();
  const text = data.content[0].text;
  const clean = text.replace(/```json|```/g, "").trim();
  return JSON.parse(clean);
}

// ── 根据结构和模板生成 Word 文档 ──────────────────────
async function buildDocx(structure, templateKey) {
  const tpl = TEMPLATES[templateKey] || TEMPLATES.business;

  const children = structure.map(item => {
    const num = item.numbering ? item.numbering + " " : "";
    const fullText = num + (item.text || "");

    if (item.type === "h1") {
      return new Paragraph({
        heading: HeadingLevel.HEADING_1,
        alignment: tpl.h1.align,
        spacing: { before: 400, after: 200, line: tpl.lineSpacing },
        children: [new TextRun({ text: fullText, font: tpl.fontHeading, size: tpl.h1.size, bold: tpl.h1.bold })],
      });
    }
    if (item.type === "h2") {
      return new Paragraph({
        heading: HeadingLevel.HEADING_2,
        alignment: tpl.h2.align,
        spacing: { before: 300, after: 160, line: tpl.lineSpacing },
        children: [new TextRun({ text: fullText, font: tpl.fontHeading, size: tpl.h2.size, bold: tpl.h2.bold })],
      });
    }
    if (item.type === "h3") {
      return new Paragraph({
        heading: HeadingLevel.HEADING_3,
        alignment: tpl.h3.align,
        spacing: { before: 200, after: 120, line: tpl.lineSpacing },
        children: [new TextRun({ text: fullText, font: tpl.fontHeading, size: tpl.h3.size, bold: tpl.h3.bold })],
      });
    }
    if (item.type === "list") {
      return new Paragraph({
        spacing: { line: tpl.lineSpacing },
        indent: { left: 480 },
        children: [new TextRun({ text: fullText, font: tpl.fontBody, size: tpl.sizeBody })],
      });
    }
    // body
    return new Paragraph({
      spacing: { line: tpl.lineSpacing },
      indent: { firstLine: 480 },
      children: [new TextRun({ text: fullText, font: tpl.fontBody, size: tpl.sizeBody })],
    });
  });

  const doc = new Document({
    sections: [{
      properties: {
        page: {
          size: { width: 11906, height: 16838 },
          margin: tpl.margin,
        },
      },
      children,
    }],
  });

  return await Packer.toBuffer(doc);
}

// ── 上传并处理文件 ─────────────────────────────────────
app.post("/api/process", authUser, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "请上传文件" });
  if (!CLAUDE_KEY) return res.status(500).json({ error: "AI服务未配置" });

  const templateKey = req.body.template || "business";
  if (!TEMPLATES[templateKey]) return res.status(400).json({ error: "无效模板" });

  // 权限检查
  const check = checkAndDeduct(req.user.id);
  if (!check.ok) {
    fs.unlinkSync(req.file.path);
    return res.status(403).json({ error: check.error });
  }

  // 记录文档
  const docId = db.prepare("INSERT INTO documents(user_id,file_name,template,status) VALUES(?,?,?,?)")
    .run(req.user.id, req.file.originalname, templateKey, "processing").lastInsertRowid;

  try {
    // 提取文本
    const rawText = await extractDocxStructure(req.file.path);
    if (!rawText || rawText.trim().length < 10) throw new Error("无法从文件中提取文本，请确认文件内容不为空");

    // AI 分析结构
    const structure = await analyzeWithClaude(rawText, templateKey);
    if (!Array.isArray(structure) || structure.length === 0) throw new Error("文档结构分析失败");

    // 生成排版后的 Word
    const buffer = await buildDocx(structure, templateKey);

    // 保存输出文件
    const outName = `wenjiang_${docId}_${Date.now()}.docx`;
    const outPath = path.join(OUTPUT_DIR, outName);
    fs.writeFileSync(outPath, buffer);

    db.prepare("UPDATE documents SET status='done', result_path=? WHERE id=?").run(outName, docId);
    db.prepare("INSERT INTO usage_log(user_id,phone,action) VALUES(?,?,?)").run(req.user.id, req.user.phone, `process:${req.file.originalname}`);

    res.json({ ok: true, docId, fileName: req.file.originalname, template: TEMPLATES[templateKey].name, structure });
  } catch (e) {
    db.prepare("UPDATE documents SET status='failed' WHERE id=?").run(docId);
    console.error("[处理失败]", e.message);
    res.status(500).json({ error: e.message });
  } finally {
    try { fs.unlinkSync(req.file.path); } catch(e) {}
  }
});

// ── 预览结构（不扣量，仅返回解析后的结构供前端预览）────
app.get("/api/preview/:docId", authUser, (req, res) => {
  const doc = db.prepare("SELECT * FROM documents WHERE id=? AND user_id=?").get(req.params.docId, req.user.id);
  if (!doc) return res.status(404).json({ error: "文档不存在" });
  res.json({ ok: true, doc });
});

// ── 下载处理后的文件 ──────────────────────────────────
app.get("/api/download/:docId", authUser, (req, res) => {
  const doc = db.prepare("SELECT * FROM documents WHERE id=? AND user_id=?").get(req.params.docId, req.user.id);
  if (!doc || doc.status !== "done") return res.status(404).json({ error: "文件不存在或未处理完成" });
  const filePath = path.join(OUTPUT_DIR, doc.result_path);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "文件已过期，请重新处理" });
  const downloadName = `文匠_${doc.file_name.replace(/\.[^.]+$/, "")}_${doc.template}.docx`;
  res.download(filePath, downloadName);
});

// ── 历史记录 ──────────────────────────────────────────
app.get("/api/documents", authUser, (req, res) => {
  const docs = db.prepare("SELECT id,file_name,template,status,created_at FROM documents WHERE user_id=? ORDER BY created_at DESC LIMIT 50").all(req.user.id);
  res.json(docs.map(d => ({ ...d, templateName: TEMPLATES[d.template]?.name || d.template })));
});

// ════════════════════════════════════════════════════
// ── 支付（虎皮椒）────────────────────────────────────
// ════════════════════════════════════════════════════
app.post("/api/order/create", authUser, async (req, res) => {
  const { plan } = req.body;
  const p = PLANS[plan];
  if (!p) return res.status(400).json({ error: "无效套餐" });

  const outTradeNo = "WJ" + Date.now() + nanoid(6).toUpperCase();
  db.prepare("INSERT INTO orders(user_id,out_trade_no,plan,amount,days) VALUES(?,?,?,?,?)").run(req.user.id, outTradeNo, plan, p.price/100, p.days);

  if (!HPJ_APPID || !HPJ_SECRET) {
    return res.json({ ok: true, payUrl: `${BASE_URL}/pay-mock?order=${outTradeNo}&amount=${p.price/100}&name=${encodeURIComponent(p.name)}`, outTradeNo, mock: true });
  }

  try {
    const title = p.name + " - 文匠文档排版";
    const time  = String(Math.floor(Date.now() / 1000));
    const nonceStr = nanoid(16);
    const params = { version: "1.1", appid: HPJ_APPID, trade_order_id: outTradeNo, total_fee: (p.price/100).toFixed(2), title, time, notify_url: `${BASE_URL}/api/order/notify`, return_url: `${BASE_URL}/app?pay=success&order=${outTradeNo}`, nonce_str: nonceStr };
    params.hash = hpjSign(params, HPJ_SECRET);
    const r = await fetch("https://api.xunhupay.com/payment/do.html", { method: "POST", body: new URLSearchParams(params) });
    const text = await r.text();
    let d; try { d = JSON.parse(text); } catch(e) { throw new Error("虎皮椒接口返回异常"); }
    if (d.errcode !== 0) throw new Error(d.errmsg || JSON.stringify(d));
    res.json({ ok: true, qrUrl: d.url_qrcode, payUrl: d.url, outTradeNo });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/order/status", authUser, async (req, res) => {
  const { order } = req.query;
  const row = db.prepare("SELECT * FROM orders WHERE out_trade_no=? AND user_id=?").get(order, req.user.id);
  if (!row) return res.status(404).json({ error: "订单不存在" });
  if (row.status === "paid") return res.json({ ok: true, paid: true });
  if (HPJ_APPID && HPJ_SECRET) {
    try {
      const time = String(Math.floor(Date.now() / 1000));
      const nonceStr = nanoid(16);
      const qp = { appid: HPJ_APPID, trade_order_id: order, time, nonce_str: nonceStr };
      qp.hash = hpjSign(qp, HPJ_SECRET);
      const r = await fetch("https://api.xunhupay.com/payment/query.html", { method: "POST", body: new URLSearchParams(qp) });
      const d = await r.json();
      if (d.errcode === 0 && d.status === "OD") { activateOrder(order); return res.json({ ok: true, paid: true }); }
    } catch(e) {}
  }
  res.json({ ok: true, paid: false });
});

app.post("/api/order/notify", express.urlencoded({ extended: true }), (req, res) => {
  const { trade_order_id, status } = req.body;
  if (HPJ_SECRET) {
    const p = { ...req.body }; delete p.hash;
    if (req.body.hash !== hpjSign(p, HPJ_SECRET)) return res.send("fail");
  }
  if (status === "OD") { activateOrder(trade_order_id); res.send("success"); }
  else res.send("fail");
});

app.post("/api/order/mock-pay", (req, res) => {
  activateOrder(req.body.outTradeNo);
  res.json({ ok: true });
});

function activateOrder(outTradeNo) {
  const order = db.prepare("SELECT * FROM orders WHERE out_trade_no=?").get(outTradeNo);
  if (!order || order.status === "paid") return;
  db.prepare("UPDATE orders SET status='paid', paid_at=datetime('now','localtime') WHERE out_trade_no=?").run(outTradeNo);
  const user = db.prepare("SELECT * FROM users WHERE id=?").get(order.user_id);
  if (!user) return;
  const base = (user.expires && user.expires > new Date().toISOString().slice(0,10)) ? new Date(user.expires) : new Date();
  base.setDate(base.getDate() + order.days);
  const expires = base.toISOString().slice(0,10);
  db.prepare("UPDATE users SET status='active', plan=?, expires=? WHERE id=?").run(order.plan, expires, order.user_id);
  db.prepare("INSERT INTO usage_log(user_id,phone,action) VALUES(?,?,?)").run(user.id, user.phone, "paid:" + order.plan);
}

// ── 模拟支付页面 ──────────────────────────────────────
app.get("/pay-mock", (req, res) => {
  const { order, amount, name } = req.query;
  res.send(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>模拟支付</title>
<style>body{font-family:system-ui;background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{background:#fff;border-radius:16px;padding:40px;text-align:center;max-width:360px;box-shadow:0 4px 24px rgba(0,0,0,0.08)}
.amount{font-size:40px;font-weight:800;color:#07C160;margin:20px 0}
.btn{display:block;width:100%;padding:14px;background:#07C160;color:#fff;border:none;border-radius:10px;font-size:16px;font-weight:700;cursor:pointer;margin-top:16px}</style></head>
<body><div class="box"><div style="font-size:32px">💚</div>
<h2>${decodeURIComponent(name||"")}</h2>
<div class="amount">¥${amount}</div>
<button class="btn" onclick="pay('${order}',this)">确认支付（演示）</button>
<div style="font-size:12px;color:#94A3B8;margin-top:12px">演示模式</div></div>
<script>async function pay(o,b){b.disabled=true;b.textContent="处理中...";await fetch('/api/order/mock-pay',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({outTradeNo:o})});location.href='/app?pay=success&order='+o;}</script></body></html>`);
});

// ── 管理后台 API ──────────────────────────────────────
app.get("/api/admin/users", authAdmin, (req, res) => {
  res.json(db.prepare("SELECT id,phone,name,company,status,plan,expires,free_uses,month_uses,month_year,created,last_login FROM users ORDER BY created DESC").all());
});

app.post("/api/admin/user-status", authAdmin, (req, res) => {
  const { id, status } = req.body;
  if (!["active","paused","inactive","expired"].includes(status)) return res.status(400).json({ error: "无效状态" });
  db.prepare("UPDATE users SET status=? WHERE id=?").run(status, id);
  res.json({ ok: true });
});

app.post("/api/admin/extend", authAdmin, (req, res) => {
  const { id, days, plan } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE id=?").get(id);
  if (!user) return res.status(404).json({ error: "用户不存在" });
  const base = (user.expires && user.expires > new Date().toISOString().slice(0,10)) ? new Date(user.expires) : new Date();
  base.setDate(base.getDate() + Number(days));
  const expires = base.toISOString().slice(0,10);
  db.prepare("UPDATE users SET status='active', expires=?, plan=? WHERE id=?").run(expires, plan||user.plan, id);
  res.json({ ok: true, expires });
});

app.get("/api/admin/stats", authAdmin, (req, res) => {
  res.json({
    total:   db.prepare("SELECT COUNT(*) as n FROM users").get().n,
    active:  db.prepare("SELECT COUNT(*) as n FROM users WHERE status='active'").get().n,
    revenue: db.prepare("SELECT COALESCE(SUM(amount),0) as n FROM orders WHERE status='paid'").get().n,
    docs:    db.prepare("SELECT COUNT(*) as n FROM documents WHERE status='done'").get().n,
    logs:    db.prepare("SELECT * FROM usage_log ORDER BY ts DESC LIMIT 100").all(),
  });
});

app.get("/api/admin/orders", authAdmin, (req, res) => {
  res.json(db.prepare("SELECT o.*,u.phone,u.name FROM orders o LEFT JOIN users u ON o.user_id=u.id ORDER BY o.created DESC LIMIT 200").all());
});

// ── 页面路由 ──────────────────────────────────────────
app.get("/admin", authAdmin, (req, res) => res.sendFile(path.join(__dirname, "../public/admin.html")));
app.get("/app",   (req, res) => res.sendFile(path.join(__dirname, "../public/app.html")));
app.get("/",      (req, res) => res.sendFile(path.join(__dirname, "../public/index.html")));

const PORT = process.env.PORT || 3724;
app.listen(PORT, () => {
  console.log(`\n文匠 SaaS 已启动: http://localhost:${PORT}`);
  console.log(`管理后台: http://localhost:${PORT}/admin?admin=${ADMIN_KEY}\n`);
});
