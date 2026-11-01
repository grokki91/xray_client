// Окно xdiag. Всё, что приходит из ядра, выводится только через textContent: строки логов
// клиентов — недоверенный текст.
"use strict";

const api = () => window.go.main.App;
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
};
const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); };

let current = null; // текущий View
let running = false;

// ─── Значки (линейные SVG, собираются из констант — без разбора HTML) ───────────
const ICONS = {
  pulse: ["M3 12h4l2-6 4 12 2-6h6"],
  list: ["M9 6h12", "M9 12h12", "M9 18h12", "M4 6h.01", "M4 12h.01", "M4 18h.01"],
  clock: ["M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18", "M12 7v5l3 2"],
  gear: ["M4 21v-7", "M4 10V3", "M12 21v-9", "M12 8V3", "M20 21v-5", "M20 12V3", "M1 14h6", "M9 8h6", "M17 16h6"],
  folder: ["M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"],
  moon: ["M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"],
  refresh: ["M21 12a9 9 0 1 1-2.64-6.36", "M21 3v6h-6"],
  arrow: ["M5 12h14", "M13 6l6 6-6 6"],
  copy: ["M9 9h10a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H11a2 2 0 0 1-2-2z", "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"],
  download: ["M12 3v12", "M7 10l5 5 5-5", "M5 21h14"],
  check: ["M5 12.5l4.5 4.5L19 7.5"],
  x: ["M6 6l12 12", "M18 6L6 18"],
  bang: ["M12 6v8", "M12 18h.01"],
  dash: ["M7 12h10"],
  shield: ["M12 3l8 3v6c0 5-3.4 8.2-8 9-4.6-.8-8-4-8-9V6z"],
  shieldCheck: ["M12 3l8 3v6c0 5-3.4 8.2-8 9-4.6-.8-8-4-8-9V6z", "M8.5 12l2.5 2.5 4.5-5"],
  shieldBang: ["M12 3l8 3v6c0 5-3.4 8.2-8 9-4.6-.8-8-4-8-9V6z", "M12 8v4.5", "M12 15.5h.01"],
  shieldQ: ["M12 3l8 3v6c0 5-3.4 8.2-8 9-4.6-.8-8-4-8-9V6z", "M9.8 9.6a2.3 2.3 0 1 1 3.2 2.1c-.6.3-1 .8-1 1.4", "M12 16h.01"],
  shieldDash: ["M12 3l8 3v6c0 5-3.4 8.2-8 9-4.6-.8-8-4-8-9V6z", "M9 12h6"],
};
const SVGNS = "http://www.w3.org/2000/svg";
function icon(name) {
  const s = document.createElementNS(SVGNS, "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("class", "i");
  s.setAttribute("aria-hidden", "true");
  (ICONS[name] || []).forEach((d) => {
    const p = document.createElementNS(SVGNS, "path");
    p.setAttribute("d", d);
    s.append(p);
  });
  return s;
}
// <i data-icon="…"> в разметке → SVG; id переносится на значок.
function mountIcons(root) {
  root.querySelectorAll("i[data-icon]").forEach((n) => {
    const s = icon(n.dataset.icon);
    if (n.id) s.id = n.id;
    n.replaceWith(s);
  });
}
function setIcon(id, name) {
  const s = icon(name);
  s.id = id;
  $(id).replaceWith(s);
}
mountIcons(document);

// ─── Тема ───────────────────────────────────────────────────────────────────
// "" — как в Windows; переключатель задаёт явную тему и сохраняет её в settings.json.
const sysDark = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
let themePref = "";
function applyTheme(t) {
  themePref = t || "";
  if (themePref) document.documentElement.dataset.theme = themePref;
  else delete document.documentElement.dataset.theme;
  $("themeDark").checked = themePref ? themePref === "dark" : !!(sysDark && sysDark.matches);
}
if (sysDark && sysDark.addEventListener) sysDark.addEventListener("change", () => applyTheme(themePref));
applyTheme("");
$("themeDark").addEventListener("change", () => {
  const t = $("themeDark").checked ? "dark" : "light";
  applyTheme(t);
  try { api().SetTheme(t).catch(() => {}); } catch (e) { /* без моста тема живёт до закрытия окна */ }
});

// ─── Вкладки ────────────────────────────────────────────────────────────────
const PAGES = {
  run: ["Диагностика подключения", "Подробный анализ проблемы"],
  details: ["Подробно", "Все улики сеанса"],
  history: ["История", "Прошлые сеансы на этом ПК"],
  settings: ["Настройки", "Профиль, мост к серверу и хранение"],
  data: ["Данные", "Что xdiag хранит на этом ПК"],
};
document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
function showTab(name) {
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === "tab-" + name));
  $("pageTitle").textContent = PAGES[name][0];
  $("pageSub").textContent = PAGES[name][1];
  if (name === "history") loadHistory();
  if (name === "settings") loadSettings();
  if (name === "data") loadData();
}

document.querySelectorAll(".dtab").forEach((b) => b.addEventListener("click", () => showDTab(b.dataset.dtab)));
function showDTab(name) {
  document.querySelectorAll(".dtab").forEach((b) => b.classList.toggle("active", b.dataset.dtab === name));
  document.querySelectorAll(".dpane").forEach((p) => p.classList.toggle("active", p.id === "dt-" + name));
}

// ─── Модальное окно ─────────────────────────────────────────────────────────
function modal({ title, text, yes = "Да", no = "Отмена", input = false, pre = null, count = 0 }) {
  return new Promise((resolve) => {
    $("mTitle").textContent = title || "";
    $("mText").textContent = text || "";
    $("mInput").hidden = !input;
    $("mInput").value = "";
    $("mPre").hidden = pre === null;
    $("mPre").textContent = pre || "";
    $("mYes").textContent = yes;
    $("mNo").textContent = no;
    $("mNo").hidden = no === null;
    $("mCount").hidden = !count;
    let timer = null;
    if (count) {
      let left = count;
      $("mCount").textContent = left;
      timer = setInterval(() => {
        left -= 1;
        $("mCount").textContent = Math.max(left, 0);
        if (left <= 0) { clearInterval(timer); done(true); }
      }, 1000);
    }
    $("modal").hidden = false;
    const done = (v) => {
      if (timer) clearInterval(timer);
      $("modal").hidden = true;
      $("mYes").onclick = $("mNo").onclick = null;
      resolve(input ? (v ? $("mInput").value : null) : v);
    };
    $("mYes").onclick = () => done(true);
    $("mNo").onclick = () => done(false);
    if (input) setTimeout(() => $("mInput").focus(), 50);
  });
}

// ─── Кольцо и итог ──────────────────────────────────────────────────────────
const RING = 2 * Math.PI * 52;
function setRing(pct, label, sub) {
  const p = Math.max(0, Math.min(100, Math.round(pct)));
  $("ringArc").style.strokeDashoffset = String(RING * (1 - p / 100));
  $("ringArc").style.opacity = p ? "1" : "0"; // скруглённый конец рисует точку и при 0
  $("ringPct").textContent = p + "%";
  if (label !== undefined) $("ringLabel").textContent = label;
  if (sub !== undefined) $("ringSub").textContent = sub;
}
function heroKind(kind) { $("hero").className = "card hero k-" + kind; }

// Звенья до первого результата: что будет проверено.
const STAGES0 = [["Интернет", "ожидает"], ["Сервер", "ожидает"], ["Профиль", "ожидает"], ["Клиент", "ожидает"]];
const STAGE_ICON = { ok: "check", fail: "x", warn: "bang", skip: "dash" };
function renderChain(stages, state) {
  const ch = $("chain");
  clear(ch);
  const list = stages && stages.length ? stages : STAGES0.map(([title, note]) => ({ title, note, state }));
  list.forEach((x) => {
    const li = el("li", "node n-" + x.state);
    const dot = el("span", "dot");
    if (STAGE_ICON[x.state]) dot.append(icon(STAGE_ICON[x.state]));
    const tx = el("span", "ntext");
    tx.append(el("b", null, x.title), el("span", "nnote", x.note));
    li.append(dot, tx);
    ch.append(li);
  });
}

// Уверенность — отдельно от цвета итога: красный — «не работает», а не «точно».
const CONF = {
  confirmed: ["c-high", "shieldCheck", "Высокая", "уверенность", "Есть прямое подтверждение проверкой."],
  likely: ["c-mid", "shieldBang", "Средняя", "уверенность", "Улики указывают на причину, прямого подтверждения нет."],
  possible: ["c-low", "shieldQ", "Низкая", "уверенность", "Одна из возможных причин — нужны дополнительные проверки."],
};
function setConf(cls, ic, main, sub, note) {
  $("conf").className = "confpill " + cls;
  setIcon("confIcon", ic);
  $("confMain").textContent = main;
  $("confSub").textContent = sub;
  $("confNote").textContent = note;
}
function confFor(v, st) {
  if (st.kind === "ok") {
    return v.code === "ok.client"
      ? ["c-high", "shieldCheck", "Проверено", "через сам клиент", "Трафик идёт через клиент — подключение работает."]
      : ["c-high", "shieldCheck", "Проверено", "эталонным ядром Xray", "Сервер и профиль работают; клиент отдельно не проверялся."];
  }
  if (st.kind === "incomplete") return ["c-none", "shieldDash", "Нет оценки", "проверка не завершена", "Повторите диагностику, чтобы получить вывод."];
  return CONF[v.level_code] || ["c-none", "shieldDash", "Не определена", "уверенность", "Причина не найдена — улики во вкладках ниже."];
}

function idleHero() {
  heroKind("idle");
  setRing(0, "Нет данных", "");
  $("sHead").textContent = "Готово к диагностике";
  $("sTitle").textContent = "VLESS + REALITY + XHTTP · Hiddify и v2rayN";
  setWhy("Нажмите «Диагностировать». Приложение ничего не меняет в системе и клиентах.");
  $("sAlt").textContent = "";
  clear($("sMeta"));
  $("fix").hidden = true;
  $("copy").hidden = true;
  renderChain(null, "idle");
  setConf("c-none", "shield", "—", "уверенность", "Появится после диагностики.");
}

function setWhy(text) {
  const n = $("sWhy");
  clear(n);
  String(text || "").split("`").forEach((part, i) => n.append(i % 2 ? el("code", null, part) : document.createTextNode(part)));
}

// ─── Последняя проверка ─────────────────────────────────────────────────────
function setLast(when, kind) {
  $("lastWhen").textContent = when || "—";
  $("lastDot").className = "ldot" + (kind ? " " + kind : "");
}
const fmtWhen = (at) => new Date(at).toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" }).replace(",", "");

// ─── События ядра ───────────────────────────────────────────────────────────
const stepNodes = new Map();
// Доля пути по шагу: порядок фаз ядра (0 → Windows и клиенты, 1 → сеть, 2 → сервер, 3–4 → мост, захват).
const STEP_AT = { W: 4, C: 10, N1: 20, C10: 30, P: 40, P1: 40, P3: 52, P3m: 70, P2: 80, P4: 84, S1: 88, S2: 90, S3: 93, C7: 96, save: 98 };
let progressPct = 0;
let waitTimer = null;
let t0 = 0;

function setProgress(pct) {
  progressPct = Math.max(progressPct, Math.min(100, pct));
  setRing(progressPct);
}

const clockText = (ms) => { const s = Math.floor(ms / 1000); return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0"); };

function stepLine(s, li) {
  if (!li) {
    li = el("li");
    li.append(el("span", "tm"), el("span", "m"), el("span"));
    li.children[2].append(el("span", "t"), el("span", "n"));
  }
  li.children[1].className = "m st-" + s.status;
  li.children[2].children[0].textContent = s.title;
  li.children[2].children[1].textContent = s.note ? " — " + s.note : "";
  li.children[2].className = s.status === "fail" ? "bad" : "";
  return li;
}

function onProgress(s) {
  const steps = $("steps");
  if (steps.firstChild && steps.firstChild.classList && steps.firstChild.classList.contains("muted")) clear(steps);
  let li = stepNodes.get(s.id);
  if (!li) {
    li = stepLine(s);
    li.children[0].textContent = running ? "[" + clockText(Date.now() - t0) + "]" : "";
    steps.append(li);
    stepNodes.set(s.id, li);
    $("cSteps").textContent = String(stepNodes.size);
  } else stepLine(s, li);
  steps.scrollTop = steps.scrollHeight;
  if (!running) return;
  const at = STEP_AT[s.id] !== undefined ? STEP_AT[s.id] : progressPct;
  setProgress(s.status === "run" ? at : at + 6);
  if (waitTimer) { clearInterval(waitTimer); waitTimer = null; }
  if (s.status === "run") {
    $("sTitle").textContent = s.title;
    setWhy(s.note || "…");
    if (s.wait) {
      // Пауза (лимит проб к серверу, повтор через 30 с): видно, что не зависло.
      let left = s.wait;
      const why = (s.note || "").split(": ").slice(1).join(": ");
      const tick = () => {
        const mm = left >= 60 ? Math.floor(left / 60) + " мин " + String(left % 60).padStart(2, "0") + " с" : left + " с";
        setWhy("Ожидание " + mm + (why ? ": " + why : ""));
        left -= 1;
        if (left < 0) { clearInterval(waitTimer); waitTimer = null; }
      };
      tick();
      waitTimer = setInterval(tick, 1000);
    }
  }
}

window.addEventListener("load", () => {
  const rt = window.runtime;
  rt.EventsOn("progress", onProgress);
  rt.EventsOn("budget", (u) => {
    $("budget").textContent = `к серверу: ${u.tls} из ${u.tls_max} TLS за минуту` + (u.wait_sec ? ` · слот через ${u.wait_sec} с` : "");
  });
  rt.EventsOn("consent", async (c) => {
    const titles = { bridge: "Мост к серверу", window: "Окно сервера", uac: "Захват (права администратора)", wait: "Бюджет проб" };
    const ok = await modal({ title: titles[c.kind] || "Подтверждение", text: c.text, yes: "Да", no: "Нет" });
    api().Answer(c.id, !!ok);
  });
  rt.EventsOn("window", (w) => {
    modal({ title: "Сейчас: «Подключить» в клиенте", text: w.text + "\nНажмите один раз и не повторяйте: больше 3 попыток в минуту сами похожи на шторм.",
      yes: "Понятно", no: null, count: w.seconds });
  });
  init();
});

async function init() {
  idleHero();
  try {
    const info = await api().Info();
    $("ver").textContent = "версия " + info.version;
    if (info.error) {
      await modal({ title: "Ошибка запуска", text: info.error, no: null, yes: "Закрыть" });
    }
    const s = await api().Settings();
    applyTheme(s.theme);
    $("optBridge").checked = !!s.use_bridge;
    const h = (await api().History()) || [];
    if (h.length) setLast(fmtWhen(h[0].at), /^ok/.test(h[0].code) ? "ok" : "problem");
  } catch (e) { /* окно работает и без настроек */ }
}

// ─── Диагностика ────────────────────────────────────────────────────────────
$("go").addEventListener("click", run);
$("rerun").addEventListener("click", run);
$("stop").addEventListener("click", () => api().Cancel());

let clockTimer = null;
function scanning(on) {
  running = on;
  $("go").disabled = on;
  $("go").classList.toggle("busy", on);
  $("goText").textContent = on ? "Идёт диагностика…" : "Диагностировать";
  $("rerun").disabled = on;
  $("rerun").classList.toggle("busy", on);
  $("stop").hidden = !on;
  if (clockTimer) { clearInterval(clockTimer); clockTimer = null; }
  if (waitTimer) { clearInterval(waitTimer); waitTimer = null; }
  if (on) {
    progressPct = 0;
    t0 = Date.now();
    heroKind("run");
    setProgress(2);
    $("sHead").textContent = "Идёт диагностика…";
    $("sTitle").textContent = "Подготовка";
    setWhy("…");
    $("sAlt").textContent = "";
    clear($("sMeta"));
    $("fix").hidden = true;
    $("copy").hidden = $("export").disabled = true;
    renderChain(null, "idle");
    setConf("c-run", "shield", "Оценивается", "уверенность", "Зависит от того, чем подтверждена причина.");
    const tick = () => { $("ringLabel").textContent = "Идёт анализ"; $("ringSub").textContent = clockText(Date.now() - t0); };
    tick();
    clockTimer = setInterval(tick, 1000);
  }
}

async function run() {
  if (running) return;
  scanning(true);
  clear($("steps"));
  stepNodes.clear();
  $("cSteps").textContent = "";
  showDTab("steps");
  let v = null;
  try {
    v = await api().Run({ client: $("client").value, bridge: $("optBridge").checked, capture: $("optCapture").checked,
      other_network: $("optOther").checked, offline: false });
    $("extrasNote").textContent = "";
  } catch (e) {
    await modal({ title: "Диагностика не выполнена", text: String(e), no: null, yes: "Закрыть" });
  } finally {
    scanning(false);
  }
  if (v) {
    current = v;
    renderVerdict(v);
    renderDetails(v);
    showDTab("verdict");
  } else if (current) renderVerdict(current);
  else idleHero();
}

function list(node, items, mk) {
  clear(node);
  (items || []).forEach((x) => node.append(mk ? mk(x) : el("li", null, x)));
  return (items || []).length;
}

// rich — текст с `командами` в <code>; только textContent, без разбора HTML.
function rich(tag, text) {
  const n = el(tag);
  String(text || "").split("`").forEach((part, i) => n.append(i % 2 ? el("code", null, part) : document.createTextNode(part)));
  return n;
}

function renderSummary(v) {
  const st = v.status && v.status.kind ? v.status : { kind: "unknown", head: v.title };
  heroKind(st.kind);
  $("sHead").textContent = st.head;
  $("sTitle").textContent = v.title;
  setWhy(v.why);
  $("sAlt").textContent = v.alternative ? "Альтернатива: " + v.alternative : "";

  // Кольцо — доля пройденных звеньев цепочки «Интернет → Сервер → Профиль → Клиент».
  const stg = v.stages || [];
  const ok = stg.filter((x) => x.state === "ok").length;
  const label = st.kind === "incomplete" ? "Не завершён" : "Анализ завершён";
  if (stg.length) setRing((ok / stg.length) * 100, label, `этапов: ${ok} из ${stg.length}`);
  else setRing(100, label, "");
  renderChain(stg, "skip");

  const meta = $("sMeta");
  clear(meta);
  const chip = (label, value) => {
    if (!value) return;
    const c = el("span", "chip");
    if (label) c.append(el("span", "muted", label));
    c.append(document.createTextNode(value));
    meta.append(c);
  };
  if (st.kind === "problem" && v.where && v.where !== "—") chip("где:", v.where.replace(/^L\d+ — /, "").toLowerCase());
  const t = v.target;
  if (t) {
    chip("профиль", t.profile ? "«" + t.profile + "»" : "");
    chip("сервер", t.server);
    chip("", t.transport);
    chip("", t.source);
    if (t.client) chip("", t.client + (t.state ? ": " + t.state : ""));
  }

  const c = confFor(v, st);
  setConf(c[0], c[1], c[2], c[3], c[4]);
  $("fix").hidden = !(v.actions || []).length;
  $("copy").hidden = $("export").disabled = false;
  setLast(v.when, st.kind === "ok" ? "ok" : st.kind === "problem" ? "problem" : "incomplete");
}

function renderVerdict(v) {
  renderSummary(v);
  $("vEmpty").hidden = true;
  $("verdict").hidden = false;
  $("vEvWrap").hidden = !list($("vEvidence"), v.evidence, (e) => {
    const li = el("li");
    li.append(el("span", "id", e.id), document.createTextNode(e.text));
    return li;
  });
  $("vActWrap").hidden = !list($("vActions"), v.actions, (a) => rich("li", a));
  $("vNextWrap").hidden = !list($("vNext"), v.next, (a) => rich("li", a));
  $("vAlsoWrap").hidden = !list($("vAlso"), v.also);
  $("vFindWrap").hidden = !list($("vFind"), v.findings);
  const nRuled = list($("vRuled"), v.ruled_out);
  $("vRuledWrap").hidden = !nRuled;
  $("vRuledWrap").open = false;
  $("vRuledSum").textContent = "Исключено проверками: " + nRuled;
  if (v.budget) $("budget").textContent = v.budget;
  // Ход проверок из сеанса (для открытого из истории — единственный источник).
  if (!stepNodes.size && (v.steps || []).length) {
    clear($("steps"));
    v.steps.forEach((s) => onProgress(s));
  }
}

// Улики по источнику — консолью: [ID] проверка — результат.
const SRC = { client: ["клиент", "Windows", "вы", "лог"], net: ["сеть", "эталон"], server: ["сервер"] };
function console_(node, lines, empty) {
  clear(node);
  if (!lines.length) { node.append(el("li", "muted", empty)); return 0; }
  lines.forEach((x) => node.append(x));
  return lines.length;
}
function evLine(d) {
  const li = el("li");
  const body = el("span");
  body.append(el("span", "tt", d.title + ": "), document.createTextNode(d.text));
  li.append(el("span", "id", "[" + d.id + "]"), body);
  return li;
}
const BADLOG = /error|fail|denied|refused|timeout|reset|ошибк/i;
function renderDetails(v) {
  const rows = $("dRows");
  clear(rows);
  (v.details || []).forEach((d) => {
    const tr = el("tr");
    tr.append(el("td", null, d.id), el("td", null, d.title), el("td", null, d.source), el("td", null, d.text));
    rows.append(tr);
  });
  list($("dNotes"), v.notes);
  $("dLogs").textContent = (v.logs || []).join("\n") || "—";

  const by = (srcs) => (v.details || []).filter((d) => srcs.includes(d.source)).map(evLine);
  const cnt = (id, n) => { $(id).textContent = n ? String(n) : ""; };
  cnt("cClient", console_($("conClient"), by(SRC.client), "Нет данных от клиента и Windows."));
  cnt("cNet", console_($("conNet"), by(SRC.net), "Сетевые пробы не выполнялись."));
  cnt("cServer", console_($("conServer"), by(SRC.server), "Данных сервера нет: мост не включён и doctor.json не импортирован."));
  cnt("cLogs", console_($("conLogs"), (v.logs || []).map((l) => el("li", BADLOG.test(l) ? "bad" : "", l)), "Строк логов нет. «Вставить логи клиента» — над итогом."));
}

$("fix").addEventListener("click", () => {
  showDTab("verdict");
  $("vActWrap").scrollIntoView({ behavior: "smooth", block: "start" });
});

$("copy").addEventListener("click", async () => {
  if (!current) return;
  try { await api().CopyReport(current.id); $("copyText").textContent = "Скопировано"; setTimeout(() => ($("copyText").textContent = "Копировать отчёт"), 1500); }
  catch (e) { modal({ title: "Не скопировано", text: String(e), no: null, yes: "Закрыть" }); }
});

$("export").addEventListener("click", async () => {
  if (!current) return;
  const s = await api().Settings().catch(() => ({}));
  try {
    const p = await api().ExportSession(current.id, !!s.export_include_address);
    if (p) modal({ title: "Экспорт сохранён", text: p + (s.export_include_address ? "\n(с адресом сервера — по настройке)" : "\nБез адреса сервера, ключей и UUID."), no: null, yes: "Ок" });
  } catch (e) { modal({ title: "Экспорт не сохранён", text: String(e), no: null, yes: "Закрыть" }); }
});

$("imp").addEventListener("click", async () => {
  try {
    const names = await api().ImportFiles();
    if (names && names.length) $("extrasNote").textContent = "к следующему запуску: " + names.join(", ");
  } catch (e) { modal({ title: "Импорт", text: String(e), no: null, yes: "Закрыть" }); }
});

$("logs").addEventListener("click", async () => {
  const t = await modal({ title: "Логи клиента", text: "Hiddify: «Логи» → «Скопировать» и вставьте сюда. В отчёт попадут только характерные строки, адреса и ключи будут заменены метками.",
    input: true, yes: "Добавить", no: "Отмена" });
  if (t) {
    const n = await api().PasteLogs(t);
    $("extrasNote").textContent = `к следующему запуску: логи (${n} строк)`;
  }
});

// ─── История ────────────────────────────────────────────────────────────────
async function loadHistory() {
  const rows = $("hRows");
  clear(rows);
  const l = (await api().History()) || [];
  if (!l.length) {
    const tr = el("tr");
    const td = el("td", "muted", "История пуста");
    td.colSpan = 4;
    tr.append(td);
    rows.append(tr);
  }
  l.forEach((x) => {
    const tr = el("tr");
    const when = new Date(x.at).toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
    const actions = el("td");
    const open = el("button", "link", "Открыть");
    open.onclick = async () => {
      try {
        current = await api().Session(x.id);
        stepNodes.clear();
        $("cSteps").textContent = "";
        renderVerdict(current);
        renderDetails(current);
        showDTab("verdict");
        showTab("run");
      } catch (e) { modal({ title: "Сеанс не открыт", text: String(e), no: null, yes: "Закрыть" }); }
    };
    const raw = el("button", "link", "Данные");
    raw.onclick = async () => {
      try { const t = await api().RevealData(x.id); modal({ title: "Сеанс целиком (расшифровано)", text: "Только для вас: здесь есть адрес сервера и SNI.", pre: t, no: null, yes: "Закрыть" }); }
      catch (e) { modal({ title: "Не прочитано", text: String(e), no: null, yes: "Закрыть" }); }
    };
    const del = el("button", "link", "Удалить");
    del.onclick = async () => { await api().DeleteSession(x.id); loadHistory(); };
    actions.append(open, document.createTextNode(" · "), raw, document.createTextNode(" · "), del);
    tr.append(el("td", null, when), el("td", null, x.short || x.code), el("td", null, levelText(x.level)), actions);
    rows.append(tr);
  });
}
const levelText = (l) => ({ confirmed: "подтверждено", likely: "вероятно", possible: "возможно" }[l] || "—");

$("hClear").addEventListener("click", async () => {
  if (await modal({ title: "Удалить историю?", text: "Все сеансы будут удалены. На SSD безвозвратность стирания не гарантируется.", yes: "Удалить" })) {
    await api().ClearHistory();
    loadHistory();
  }
});

// ─── Настройки ──────────────────────────────────────────────────────────────
async function loadSettings() {
  const s = await api().Settings();
  $("sUri").value = "";
  $("sUri").placeholder = s.has_uri ? "сохранён (скрыт). Вставьте новый, чтобы заменить; «-» — удалить" : "не задан";
  $("sUriHint").textContent = s.has_uri ? "Посмотреть сохранённый — вкладка «Данные»." : "";
  $("sAlias").value = s.alias || "";
  $("sV2").value = s.v2rayn_dir || "";
  $("sHid").value = s.hiddify_dir || "";
  $("sClient").value = s.client || "auto";
  $("sRet").value = s.retention_days;
  $("sLive").value = s.live_seconds;
  $("sRef").checked = !!s.reference;
  $("sBridge").checked = !!s.use_bridge;
  $("sAddr").checked = !!s.export_include_address;
}

$("sSave").addEventListener("click", async () => {
  const f = {
    retention_days: parseInt($("sRet").value, 10) || 0, export_include_address: $("sAddr").checked, client: $("sClient").value,
    live_seconds: parseInt($("sLive").value, 10) || 60, use_bridge: $("sBridge").checked, reference: $("sRef").checked,
    alias: $("sAlias").value.trim(), hiddify_dir: $("sHid").value.trim(), v2rayn_dir: $("sV2").value.trim(), new_uri: $("sUri").value.trim(),
  };
  try {
    await api().SaveSettings(f);
    $("sMsg").textContent = "Сохранено";
    $("optBridge").checked = f.use_bridge;
    loadSettings();
    setTimeout(() => ($("sMsg").textContent = ""), 2000);
  } catch (e) { $("sMsg").textContent = String(e); }
});

// ─── Данные ─────────────────────────────────────────────────────────────────
async function loadData() {
  const info = await api().Info();
  $("dataDir").textContent = info.data_dir;
  $("dataProt").textContent = info.protected ? "DPAPI" : "без шифрования";
  $("dataProt").className = "badge " + (info.protected ? "lv-ok" : "lv-likely");
  $("manual").textContent = ((await api().ManualCommands()) || []).join("\n");
}
$("dOpen").addEventListener("click", () => api().OpenDataDir());
$("dShow").addEventListener("click", async () => {
  try {
    const t = await api().RevealData("");
    modal({ title: "Сохранённые данные (расшифровано)", text: "Только для вас. Не пересылайте этот текст.", pre: t, no: null, yes: "Закрыть" });
  } catch (e) { modal({ title: "Не прочитано", text: String(e), no: null, yes: "Закрыть" }); }
});
