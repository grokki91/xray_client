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

// ─── Вкладки ────────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
function showTab(name) {
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === "tab-" + name));
  if (name === "history") loadHistory();
  if (name === "settings") loadSettings();
  if (name === "data") loadData();
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

// ─── События ядра ───────────────────────────────────────────────────────────
const stepNodes = new Map();
// Доля пути по шагу: порядок фаз ядра (0 → Windows и клиенты, 1 → сеть, 2 → сервер, 3–4 → мост, захват).
const STEP_AT = { W: 4, C: 10, N1: 20, C10: 30, P: 40, P1: 40, P3: 52, P3m: 70, P2: 80, P4: 84, S1: 88, S2: 90, S3: 93, C7: 96, save: 98 };
let progressPct = 0;
let waitTimer = null;

function setProgress(pct) {
  progressPct = Math.max(progressPct, Math.min(100, pct));
  $("barFill").style.width = progressPct + "%";
  $("barFill").parentElement.setAttribute("aria-valuenow", String(Math.round(progressPct)));
}

function onProgress(s) {
  const steps = $("steps");
  if (steps.firstChild && steps.firstChild.classList && steps.firstChild.classList.contains("muted")) clear(steps);
  let li = stepNodes.get(s.id);
  if (!li) {
    li = el("li");
    li.append(el("span", "m"), el("span", "t"), el("span", "n"));
    steps.append(li);
    stepNodes.set(s.id, li);
  }
  li.className = "";
  li.children[0].className = "m st-" + s.status;
  li.children[1].textContent = s.title;
  li.children[2].textContent = s.note || "";
  if (!running) return;
  const at = STEP_AT[s.id] !== undefined ? STEP_AT[s.id] : progressPct;
  setProgress(s.status === "run" ? at : at + 6);
  if (waitTimer) { clearInterval(waitTimer); waitTimer = null; }
  if (s.status === "run") {
    $("scanStep").textContent = s.title + (s.note ? " — " + s.note : "…");
    if (s.wait) {
      // Пауза (лимит проб к серверу, повтор через 30 с): видно, что не зависло.
      let left = s.wait;
      const why = (s.note || "").split(": ").slice(1).join(": ");
      const tick = () => {
        const mm = left >= 60 ? Math.floor(left / 60) + " мин " + String(left % 60).padStart(2, "0") + " с" : left + " с";
        $("scanStep").textContent = s.title + " — ожидание " + mm + (why ? ": " + why : "");
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
  try {
    const info = await api().Info();
    $("ver").textContent = "версия " + info.version;
    if (info.error) {
      await modal({ title: "Ошибка запуска", text: info.error, no: null, yes: "Закрыть" });
    }
    const s = await api().Settings();
    $("optBridge").checked = !!s.use_bridge;
  } catch (e) { /* окно работает и без настроек */ }
}

// ─── Диагностика ────────────────────────────────────────────────────────────
$("go").addEventListener("click", run);
$("stop").addEventListener("click", () => api().Cancel());

let clockTimer = null;
function scanning(on) {
  running = on;
  $("go").disabled = on;
  $("go").classList.toggle("busy", on);
  $("goText").textContent = on ? "Идёт диагностика…" : "Диагностировать";
  $("stop").hidden = !on;
  $("scan").hidden = !on;
  if (clockTimer) { clearInterval(clockTimer); clockTimer = null; }
  if (waitTimer) { clearInterval(waitTimer); waitTimer = null; }
  if (on) {
    progressPct = 0;
    setProgress(2);
    $("scanStep").textContent = "Подготовка…";
    const t0 = Date.now();
    const tick = () => {
      const s = Math.floor((Date.now() - t0) / 1000);
      $("scanTime").textContent = Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
    };
    tick();
    clockTimer = setInterval(tick, 1000);
  }
}

async function run() {
  if (running) return;
  scanning(true);
  clear($("steps"));
  stepNodes.clear();
  $("verdict").hidden = true;
  $("summary").hidden = true;
  try {
    const v = await api().Run({ client: $("client").value, bridge: $("optBridge").checked, capture: $("optCapture").checked,
      other_network: $("optOther").checked, offline: false });
    current = v;
    renderVerdict(v);
    renderDetails(v);
    $("extrasNote").textContent = "";
  } catch (e) {
    await modal({ title: "Диагностика не выполнена", text: String(e), no: null, yes: "Закрыть" });
  } finally {
    scanning(false);
  }
}

// rich — текст с `командами` в <code>; только textContent, без разбора HTML.
function rich(tag, text) {
  const n = el(tag);
  String(text || "").split("`").forEach((part, i) => n.append(i % 2 ? el("code", null, part) : document.createTextNode(part)));
  return n;
}

function list(node, items, mk) {
  clear(node);
  (items || []).forEach((x) => node.append(mk ? mk(x) : el("li", null, x)));
  return (items || []).length;
}

const ICON = { ok: "✓", problem: "✕", unknown: "?", incomplete: "!" };
const CONF = { confirmed: "●●● подтверждено", likely: "●●○ вероятно", possible: "●○○ возможно" };
const STAGE_ICON = { ok: "✓", fail: "✕", warn: "!", idle: "○", skip: "–" };

function renderSummary(v) {
  const st = v.status && v.status.kind ? v.status : { kind: "unknown", head: v.title };
  const box = $("summary");
  box.hidden = false;
  box.className = "card summary sum-" + st.kind;
  $("sIcon").textContent = ICON[st.kind] || "?";
  $("sHead").textContent = st.head;
  $("sTitle").textContent = v.title;
  // Уверенность — отдельно от цвета: красный — «не работает», а не «точно».
  let conf = "";
  if (st.kind === "ok") conf = v.code === "ok.client" ? "проверено через сам клиент" : "проверено эталонным ядром Xray";
  else if (CONF[v.level_code]) conf = "уверенность: " + CONF[v.level_code];
  $("sConf").textContent = conf;
  $("sConf").hidden = !conf;
  $("sWhere").textContent = st.kind === "problem" && v.where && v.where !== "—" ? "где: " + v.where.replace(/^L\d+ — /, "").toLowerCase() : "";
  $("sWhere").hidden = !$("sWhere").textContent;
  $("sWhen").textContent = v.when || "";

  const tg = $("sTarget");
  clear(tg);
  const t = v.target;
  if (t) {
    tg.append(el("span", "tlabel", "Проверено:"));
    const add = (label, value, strong) => {
      if (!value) return;
      const sp = el("span", "titem");
      if (label) sp.append(el("span", "muted", label + " "));
      sp.append(el(strong ? "b" : "span", null, value));
      tg.append(sp);
    };
    add("профиль", t.profile ? "«" + t.profile + "»" : "", true);
    add("сервер", t.server, true);
    add("", t.transport);
    add("", t.source);
    if (t.client) add("", t.client + (t.state ? ": " + t.state : ""), !!t.state);
  }
  tg.hidden = !t;

  const ch = $("chain");
  clear(ch);
  (v.stages || []).forEach((x) => {
    const li = el("li", "node n-" + x.state);
    li.append(el("span", "dot", STAGE_ICON[x.state] || "–"));
    const tx = el("span", "ntext");
    tx.append(el("b", null, x.title), el("span", "nnote", x.note));
    li.append(tx);
    ch.append(li);
  });
  ch.hidden = !(v.stages || []).length;
}

function renderVerdict(v) {
  renderSummary(v);
  $("verdict").hidden = false;
  $("vWhy").replaceWith(Object.assign(rich("p", v.why), { id: "vWhy" }));
  $("vAlt").textContent = v.alternative ? "Альтернатива: " + v.alternative : "";
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
}

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
}

$("copy").addEventListener("click", async () => {
  if (!current) return;
  try { await api().CopyReport(current.id); $("copy").textContent = "Скопировано"; setTimeout(() => ($("copy").textContent = "Скопировать отчёт (без адресов)"), 1500); }
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
      try { current = await api().Session(x.id); renderVerdict(current); renderDetails(current); showTab("run"); }
      catch (e) { modal({ title: "Сеанс не открыт", text: String(e), no: null, yes: "Закрыть" }); }
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
