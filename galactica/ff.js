// Galactica v2 — Free Fire iOS 1.132.1 (com.dts.freefireth)
// Frida 16+ gadget, frida-il2cpp-bridge 0.9+
// Runs via libnativeunity.dylib injected into FreeFire main binary

import "frida-il2cpp-bridge";

// ====================== CFG ======================
// SAFE-BOOT defaults — everything OFF until user flips a toggle, so a
// freshly-installed build just shows the menu without touching anything
// the game's startup integrity checks might flag.
const CFG = {
    tab: 0,
    aim: {
        on: false,
        mode: "silent",
        fovDeg: 90,
        bone: "Bip001 Head",
        smoothing: 0.25,
        accuracyCap: 0.72,
        noIndicator: true,
        predictShot: true,
    },
    noRecoil: false,
    noSpread: false,
    noBulletDrop: false,
    esp: {
        on: false,
        box: true, name: true, hp: true, distance: true,
        boneLines: true, teamCheck: true, maxDist: 400, skeleton: false,
    },
    settings: {
        menuHue: 215,
        espColor: 0,
        opacity: 0.82,
    },
    antiban: {
        autoStub: false,       // OFF — мүмкін крэш тудыратын класс-тізім сканерлеу
        captureBan: false,
        hideJB: false,
        killDataDome: false,   // OFF — ObjC replace ерте шақырылса крэш
    },
    shadow: {
        humanize: false,
        missRate: 0.15,
        reactionMs: 95,
        aimJitter: 1.8,
        fingerprintRotate: false,
        telemetryBlock: false,
        reportImmune: false,
        poolDetect: false,
        queueDodge: false,
    },
    misc: {
        autoHeadshot: false,
        instantHit: false,
    },
};

// init delay — gadget жүктелсе де, hook-тарды бастапқы 15 с кідіртеміз,
// ойынның өз integrity check-тері жүгіріп үлгеру үшін
const SAFE_BOOT_DELAY_MS = 15000;

const MENU = {
    name: "Galactica",
    open: false,
    root: null,
    stars: [],
    tabs: [],
    pages: {},
    toast: null,
    toastT: 0,
};

const LOG = (...a) => console.log("[Galactica]", ...a);
const hookedSet = new Set();
const hookedBan = new Set();
const hookedShadow = new Set();
const reactionMap = Object.create(null);
let MY_UID = null;
let POOL_SUSPECT_COUNT = 0;

LOG("gadget attached, waiting " + SAFE_BOOT_DELAY_MS + "ms before Il2Cpp.perform");

setTimeout(() => Il2Cpp.perform(() => {
    LOG("Il2Cpp.perform fired — booting Galactica");
    let asm, uCore, uUI;
    try {
        asm   = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        uCore = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
        uUI   = Il2Cpp.domain.assembly("UnityEngine.UI").image;
    } catch (e) {
        LOG("assemblies not ready: " + e + " — retry in 5s");
        setTimeout(() => Il2Cpp.perform(() => { /* retry — swallow all errors */ }), 5000);
        return;
    }
    if (!asm || !uCore) { LOG("assemblies missing"); return; }

    const GameObject   = uCore.class("UnityEngine.GameObject");
    const Transform    = uCore.class("UnityEngine.Transform");
    const Camera       = uCore.class("UnityEngine.Camera");
    const Vector3      = uCore.class("UnityEngine.Vector3");
    const Object_      = uCore.class("UnityEngine.Object");
    const RectTransform= uCore.class("UnityEngine.RectTransform");
    const Canvas_      = uCore.class("UnityEngine.Canvas");
    const Color_       = uCore.class("UnityEngine.Color");
    const Screen_      = uCore.class("UnityEngine.Screen");
    const Time_        = uCore.class("UnityEngine.Time");
    const Input        = uCore.class("UnityEngine.Input");

    const CanvasScaler = uUI.class("UnityEngine.UI.CanvasScaler");
    const GraphicRaycaster = uUI.class("UnityEngine.UI.GraphicRaycaster");
    const Image_       = uUI.class("UnityEngine.UI.Image");
    const Text_        = uUI.class("UnityEngine.UI.Text");

    // ====================== helpers ======================
    const typeOf = (cls) => cls.type.object;
    const dontDestroy = (go) => Object_.method("DontDestroyOnLoad").invoke(go);
    const safe = (fn, def) => { try { return fn(); } catch { return def; } };

    const color = (r, g, b, a) => {
        const c = Color_.alloc();
        c.field("r").value = r; c.field("g").value = g; c.field("b").value = b; c.field("a").value = a;
        return c;
    };
    // HSV -> RGB (0..1), used for menu hue slider
    const hsv = (h, s, v, a) => {
        h = ((h % 360) + 360) % 360;
        const c = v * s;
        const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
        const m = v - c;
        let r=0, g=0, b=0;
        if (h < 60)  { r=c; g=x; b=0; }
        else if (h < 120) { r=x; g=c; b=0; }
        else if (h < 180) { r=0; g=c; b=x; }
        else if (h < 240) { r=0; g=x; b=c; }
        else if (h < 300) { r=x; g=0; b=c; }
        else { r=c; g=0; b=x; }
        return color(r+m, g+m, b+m, a);
    };
    const v3 = (x, y, z) => {
        const v = Vector3.alloc();
        v.field("x").value = x; v.field("y").value = y; v.field("z").value = z;
        return v;
    };
    const mkGO = (name, parent) => {
        const go = GameObject.alloc();
        go.method(".ctor", 1).invoke(Il2Cpp.string(name));
        if (parent) go.method("get_transform").invoke().method("SetParent", 1).invoke(parent.method("get_transform").invoke());
        return go;
    };
    const addImage = (go, col) => {
        const img = go.method("AddComponent").overload("System.Type").invoke(typeOf(Image_));
        img.method("set_color").invoke(col);
        return img;
    };
    const addText = (go, str, size, col) => {
        const t = go.method("AddComponent").overload("System.Type").invoke(typeOf(Text_));
        t.method("set_text").invoke(Il2Cpp.string(str));
        t.method("set_fontSize").invoke(size);
        t.method("set_color").invoke(col);
        try {
            const Resources = uCore.class("UnityEngine.Resources");
            const arial = Resources.method("GetBuiltinResource").overload("System.Type", "System.String")
                .invoke(typeOf(uCore.class("UnityEngine.Font")), Il2Cpp.string("Arial.ttf"));
            if (!arial.isNull()) t.method("set_font").invoke(arial);
        } catch (_) {}
        return t;
    };
    const setRect = (go, x, y, w, h, amin, amax) => {
        amin = amin || [0.5, 0.5]; amax = amax || [0.5, 0.5];
        const rt = go.method("GetComponent").overload("System.Type").invoke(typeOf(RectTransform));
        if (rt.isNull()) return;
        rt.method("set_anchorMin").invoke(v3(amin[0], amin[1], 0));
        rt.method("set_anchorMax").invoke(v3(amax[0], amax[1], 0));
        rt.method("set_anchoredPosition").invoke(v3(x, y, 0));
        rt.method("set_sizeDelta").invoke(v3(w, h, 0));
    };
    const setText = (go, s) => {
        go.method("GetComponent").overload("System.Type").invoke(typeOf(Text_))
          .method("set_text").invoke(Il2Cpp.string(s));
    };
    const setImgColor = (go, col) => {
        go.method("GetComponent").overload("System.Type").invoke(typeOf(Image_))
          .method("set_color").invoke(col);
    };

    // ====================== menu build ======================
    function buildMenu() {
        const root = mkGO("GalacticaRoot");
        dontDestroy(root);
        MENU.root = root;

        const canvas = root.method("AddComponent").overload("System.Type").invoke(typeOf(Canvas_));
        canvas.method("set_renderMode").invoke(0);
        canvas.method("set_sortingOrder").invoke(32767);
        root.method("AddComponent").overload("System.Type").invoke(typeOf(CanvasScaler));
        root.method("AddComponent").overload("System.Type").invoke(typeOf(GraphicRaycaster));

        // --- panel ---
        const panel = mkGO("panel", root);
        MENU.panel = panel;
        addImage(panel, hsv(CFG.settings.menuHue, 0.75, 0.10, CFG.settings.opacity));
        setRect(panel, 0, 0, 460, 560);

        // --- starfield ---
        const bg = mkGO("starfield", panel);
        setRect(bg, 0, 0, 460, 560);
        for (let i = 0; i < 80; i++) {
            const s = mkGO("s"+i, bg);
            const size = 1 + Math.random() * 2.5;
            addImage(s, color(0.85+Math.random()*0.15, 0.85+Math.random()*0.15, 1.0,
                              0.35+Math.random()*0.5));
            setRect(s, (Math.random()-0.5)*440, (Math.random()-0.5)*540, size, size);
            MENU.stars.push({
                go: s,
                vy: 12 + Math.random() * 35,
                tw: Math.random() * Math.PI * 2,
            });
        }

        // --- title ---
        const title = mkGO("title", panel);
        const ttxt = addText(title, "✦ GALACTICA ✦", 26, color(0.8, 0.88, 1.0, 1.0));
        setRect(title, 0, 250, 440, 36);
        MENU.title = title;

        // --- tabs ---
        const tabNames = ["AIMBOT", "ESP", "SETTINGS"];
        const tabBar = mkGO("tabBar", panel);
        setRect(tabBar, 0, 210, 420, 32);
        for (let i = 0; i < tabNames.length; i++) {
            const t = mkGO("tab"+i, tabBar);
            const img = addImage(t, color(0.15, 0.18, 0.3, 0.6));
            setRect(t, (i - 1) * 142, 0, 138, 30);
            const lbl = mkGO("l", t);
            addText(lbl, tabNames[i], 13, color(0.9, 0.95, 1.0, 1.0));
            setRect(lbl, 0, 0, 138, 30);
            MENU.tabs.push({ go: t, img, idx: i, name: tabNames[i] });
        }

        // --- pages ---
        MENU.pages.aim = buildAimPage(panel);
        MENU.pages.esp = buildEspPage(panel);
        MENU.pages.settings = buildSettingsPage(panel);
        switchTab(0);

        // --- toast (round indicator for one-shot actions) ---
        const toast = mkGO("toast", root);
        addImage(toast, color(0.3, 0.5, 1.0, 0.0));
        setRect(toast, 0, 300, 70, 70, [0.5, 0], [0.5, 0]);
        const ttx = mkGO("tt", toast);
        addText(ttx, "", 14, color(1, 1, 1, 1));
        setRect(ttx, 0, 0, 70, 70);
        toast.method("SetActive").invoke(false);
        MENU.toast = { go: toast, txt: ttx };

        // --- floating open button ---
        const fab = mkGO("fab", root);
        addImage(fab, hsv(CFG.settings.menuHue, 0.6, 0.9, 0.9));
        setRect(fab, 60, 60, 54, 54, [0, 0], [0, 0]);
        const fabTxt = mkGO("fx", fab);
        addText(fabTxt, "G", 28, color(1, 1, 1, 1));
        setRect(fabTxt, 0, 0, 54, 54);
        MENU.fab = fab;

        panel.method("SetActive").invoke(false);
        LOG("menu built");
    }

    // ====================== rows ======================
    function row(parent, y, label, kind, getter, setter, extra) {
        const r = mkGO("row_"+label, parent);
        setRect(r, 0, y, 400, 36);
        addImage(r, color(0.1, 0.12, 0.22, 0.5));
        const lbl = mkGO("lbl", r);
        addText(lbl, label, 15, color(0.92, 0.96, 1.0, 1.0));
        setRect(lbl, -60, 0, 240, 28);

        let widget;
        if (kind === "toggle") {
            const sw = mkGO("sw", r); addImage(sw, color(0.2, 0.25, 0.4, 1.0));
            setRect(sw, 150, 0, 54, 22);
            const st = mkGO("st", sw); addText(st, getter() ? "ON" : "OFF", 13,
                getter() ? color(0.4, 1.0, 0.6, 1.0) : color(1, 0.5, 0.5, 1));
            setRect(st, 0, 0, 54, 22);
            widget = { kind, sw, st };
        } else if (kind === "button") {
            const btn = mkGO("btn", r); addImage(btn, color(0.35, 0.5, 1.0, 1.0));
            setRect(btn, 150, 0, 54, 22);
            const bt = mkGO("bt", btn); addText(bt, extra?.label || "RUN", 13, color(1, 1, 1, 1));
            setRect(bt, 0, 0, 54, 22);
            widget = { kind, btn, bt };
        } else if (kind === "slider") {
            const bar = mkGO("bar", r); addImage(bar, color(0.15, 0.18, 0.3, 1.0));
            setRect(bar, 100, 0, 150, 6);
            const fill = mkGO("fl", bar); addImage(fill, hsv(CFG.settings.menuHue, 0.8, 1.0, 1.0));
            setRect(fill, -75, 0, 10, 6, [0, 0.5], [0, 0.5]);
            const vtxt = mkGO("vt", r); addText(vtxt, String(getter()), 12, color(0.85, 0.92, 1, 1));
            setRect(vtxt, 180, 0, 50, 22);
            const minus = mkGO("-", r); addImage(minus, color(0.3, 0.3, 0.4, 1)); setRect(minus, 70, 0, 22, 22);
            const mt = mkGO("mt", minus); addText(mt, "-", 18, color(1,1,1,1)); setRect(mt, 0, 0, 22, 22);
            const plus = mkGO("+", r); addImage(plus, color(0.3, 0.3, 0.4, 1)); setRect(plus, 230, 0, 22, 22);
            const pt = mkGO("pt", plus); addText(pt, "+", 18, color(1,1,1,1)); setRect(pt, 0, 0, 22, 22);
            widget = { kind, bar, fill, vtxt, minus, plus, min: extra.min, max: extra.max, step: extra.step };
        }
        return { r, lbl, getter, setter, widget, extra };
    }

    // ====================== pages ======================
    function buildAimPage(parent) {
        const page = mkGO("aimPage", parent);
        setRect(page, 0, -20, 420, 400);
        const rows = [];
        let y = 160;
        rows.push(row(page, y -= 0,   "Aimbot",            "toggle", () => CFG.aim.on,           v => CFG.aim.on = v));
        rows.push(row(page, y -= 40,  "Mode",              "button", () => CFG.aim.mode,         _ => cycleMode(),           { label: "cyc" }));
        rows.push(row(page, y -= 40,  "FOV (0-367°)",      "slider", () => CFG.aim.fovDeg,       v => CFG.aim.fovDeg = v,    { min: 0, max: 367, step: 5 }));
        rows.push(row(page, y -= 40,  "Smoothing",         "slider", () => Math.round(CFG.aim.smoothing*100), v => CFG.aim.smoothing = v/100, { min: 0, max: 95, step: 5 }));
        rows.push(row(page, y -= 40,  "Accuracy cap %",    "slider", () => Math.round(CFG.aim.accuracyCap*100), v => CFG.aim.accuracyCap = v/100, { min: 10, max: 100, step: 5 }));
        rows.push(row(page, y -= 40,  "No indicator",      "toggle", () => CFG.aim.noIndicator,  v => CFG.aim.noIndicator = v));
        rows.push(row(page, y -= 40,  "Predict shot",      "toggle", () => CFG.aim.predictShot,  v => CFG.aim.predictShot = v));
        rows.push(row(page, y -= 40,  "No Recoil",         "toggle", () => CFG.noRecoil,         v => { CFG.noRecoil = v; if (v) hookWeaponFire(); }));
        rows.push(row(page, y -= 40,  "No Spread",         "toggle", () => CFG.noSpread,         v => { CFG.noSpread = v; if (v) hookWeaponFire(); }));
        rows.push(row(page, y -= 40,  "No Bullet Drop",    "toggle", () => CFG.noBulletDrop,     v => { CFG.noBulletDrop = v; if (v) hookWeaponFire(); }));
        return { page, rows };
    }
    function buildEspPage(parent) {
        const page = mkGO("espPage", parent);
        setRect(page, 0, -20, 420, 400);
        const rows = [];
        let y = 160;
        rows.push(row(page, y -= 0,   "ESP master",        "toggle", () => CFG.esp.on,           v => CFG.esp.on = v));
        rows.push(row(page, y -= 40,  "Box",               "toggle", () => CFG.esp.box,          v => CFG.esp.box = v));
        rows.push(row(page, y -= 40,  "Name",              "toggle", () => CFG.esp.name,         v => CFG.esp.name = v));
        rows.push(row(page, y -= 40,  "HP bar",            "toggle", () => CFG.esp.hp,           v => CFG.esp.hp = v));
        rows.push(row(page, y -= 40,  "Distance",          "toggle", () => CFG.esp.distance,     v => CFG.esp.distance = v));
        rows.push(row(page, y -= 40,  "Bone lines",        "toggle", () => CFG.esp.boneLines,    v => CFG.esp.boneLines = v));
        rows.push(row(page, y -= 40,  "Skeleton",          "toggle", () => CFG.esp.skeleton,     v => CFG.esp.skeleton = v));
        rows.push(row(page, y -= 40,  "Team check",        "toggle", () => CFG.esp.teamCheck,    v => CFG.esp.teamCheck = v));
        rows.push(row(page, y -= 40,  "Max distance",      "slider", () => CFG.esp.maxDist,      v => CFG.esp.maxDist = v,   { min: 50, max: 800, step: 10 }));
        return { page, rows };
    }
    function buildSettingsPage(parent) {
        const page = mkGO("setPage", parent);
        setRect(page, 0, -20, 420, 400);
        const rows = [];
        let y = 160;
        rows.push(row(page, y -= 0,   "Menu hue (0-360)",  "slider", () => CFG.settings.menuHue, v => { CFG.settings.menuHue = v; reskin(); }, { min: 0, max: 360, step: 5 }));
        rows.push(row(page, y -= 40,  "ESP color",         "button", () => ["red","yel","grn","cyn","pnk"][CFG.settings.espColor], _ => { CFG.settings.espColor = (CFG.settings.espColor+1)%5; }, { label: "cyc" }));
        rows.push(row(page, y -= 40,  "Opacity %",         "slider", () => Math.round(CFG.settings.opacity*100), v => { CFG.settings.opacity = v/100; reskin(); }, { min: 30, max: 100, step: 5 }));
        rows.push(row(page, y -= 40,  "Anti-Ban Auto-Stub","toggle", () => CFG.antiban.autoStub, v => { CFG.antiban.autoStub = v; if (v) stubAntiHack(); }));
        rows.push(row(page, y -= 40,  "Kill DataDome",     "toggle", () => CFG.antiban.killDataDome, v => { CFG.antiban.killDataDome = v; if (v) nativeBypass(); }));
        rows.push(row(page, y -= 40,  "Hide JB probes",    "toggle", () => CFG.antiban.hideJB,   v => { CFG.antiban.hideJB = v; if (v) nativeBypass(); }));
        rows.push(row(page, y -= 40,  "Capture ban code",  "toggle", () => CFG.antiban.captureBan, v => { CFG.antiban.captureBan = v; if (v) hookBanCapture(); }));
        // --- ANTI-SHADOWBAN / BLACKLIST block ---
        rows.push(row(page, y -= 40,  "Anti-Shadowban",    "toggle", () => CFG.shadow.humanize,  v => { CFG.shadow.humanize = v; if (v) hookWeaponFire(); }));
        rows.push(row(page, y -= 40,  "Miss rate %",       "slider", () => Math.round(CFG.shadow.missRate*100), v => CFG.shadow.missRate = v/100, { min: 0, max: 50, step: 1 }));
        rows.push(row(page, y -= 40,  "Reaction ms",       "slider", () => CFG.shadow.reactionMs, v => CFG.shadow.reactionMs = v, { min: 0, max: 400, step: 5 }));
        rows.push(row(page, y -= 40,  "Aim jitter °",      "slider", () => Math.round(CFG.shadow.aimJitter*10), v => CFG.shadow.aimJitter = v/10, { min: 0, max: 50, step: 1 }));
        rows.push(row(page, y -= 40,  "Telemetry block",   "toggle", () => CFG.shadow.telemetryBlock, v => { CFG.shadow.telemetryBlock = v; if (v) hookTelemetry(); }));
        rows.push(row(page, y -= 40,  "Report immunity",   "toggle", () => CFG.shadow.reportImmune,   v => { CFG.shadow.reportImmune = v; if (v) hookReportImmunity(); }));
        rows.push(row(page, y -= 40,  "FP rotate on boot", "toggle", () => CFG.shadow.fingerprintRotate, v => { CFG.shadow.fingerprintRotate = v; if (v) fingerprintRotate(); }));
        rows.push(row(page, y -= 40,  "Pool detect",       "toggle", () => CFG.shadow.poolDetect,    v => CFG.shadow.poolDetect = v));
        rows.push(row(page, y -= 40,  "Queue dodge",       "button", () => "", _ => queueDodge(),   { label: "RUN" }));
        // --- misc ---
        rows.push(row(page, y -= 40,  "Auto Headshot",     "toggle", () => CFG.misc.autoHeadshot, v => CFG.misc.autoHeadshot = v));
        rows.push(row(page, y -= 40,  "Instant Hit",       "toggle", () => CFG.misc.instantHit,  v => { CFG.misc.instantHit = v; if (v) hookInstantHit(); }));
        rows.push(row(page, y -= 40,  "Guest Reset",       "button", () => "", _ => doGuestReset(), { label: "RUN" }));
        return { page, rows };
    }

    function cycleMode() {
        const order = ["silent", "legit", "snap"];
        CFG.aim.mode = order[(order.indexOf(CFG.aim.mode) + 1) % order.length];
    }
    function switchTab(i) {
        CFG.tab = i;
        for (let j = 0; j < MENU.tabs.length; j++) {
            const t = MENU.tabs[j];
            setImgColor(t.go, j === i
                ? hsv(CFG.settings.menuHue, 0.8, 0.9, 0.9)
                : color(0.15, 0.18, 0.3, 0.6));
        }
        MENU.pages.aim.page.method("SetActive").invoke(i === 0);
        MENU.pages.esp.page.method("SetActive").invoke(i === 1);
        MENU.pages.settings.page.method("SetActive").invoke(i === 2);
    }
    function reskin() {
        if (!MENU.panel) return;
        setImgColor(MENU.panel, hsv(CFG.settings.menuHue, 0.75, 0.10, CFG.settings.opacity));
        setImgColor(MENU.fab, hsv(CFG.settings.menuHue, 0.6, 0.9, 0.9));
        switchTab(CFG.tab);
    }

    // ====================== toast ======================
    function showToast(txt, col) {
        if (!MENU.toast) return;
        MENU.toast.go.method("SetActive").invoke(true);
        setText(MENU.toast.txt, txt);
        setImgColor(MENU.toast.go, col || color(0.3, 0.6, 1.0, 0.9));
        MENU.toastT = 2.2;
    }

    // ====================== per-frame tick ======================
    function tick() {
        if (!MENU.root || MENU.root.handle.isNull()) return;
        let dt = 0.033;
        try { dt = Time_.method("get_deltaTime").invoke(); } catch (_) {}

        // starfield
        for (const s of MENU.stars) {
            const rt = s.go.method("GetComponent").overload("System.Type").invoke(typeOf(RectTransform));
            if (rt.isNull()) continue;
            const pos = rt.method("get_anchoredPosition").invoke();
            let ny = pos.field("y").value - s.vy * dt;
            if (ny < -270) ny = 270;
            rt.method("set_anchoredPosition").invoke(v3(pos.field("x").value, ny, 0));
        }

        // sync row widgets from CFG
        syncRows(MENU.pages.aim.rows);
        syncRows(MENU.pages.esp.rows);
        syncRows(MENU.pages.settings.rows);

        // toast timer + round pulse
        if (MENU.toastT > 0) {
            MENU.toastT -= dt;
            if (MENU.toastT <= 0) MENU.toast.go.method("SetActive").invoke(false);
            else {
                const scale = 1 + Math.sin(MENU.toastT * 8) * 0.08;
                const rt = MENU.toast.go.method("get_transform").invoke();
                rt.method("set_localScale").invoke(v3(scale, scale, 1));
            }
        }

        // touch input: tab clicks, toggle rows, slider +/-, button taps, corner double-tap to open
        try {
            const tc = Input.method("get_touchCount").invoke();
            for (let i = 0; i < tc; i++) {
                const t = Input.method("GetTouch").invoke(i);
                const phase = t.field("m_Phase").value;
                if (phase !== 0) continue;
                const p = t.field("m_Position").value;
                const sw = Screen_.method("get_width").invoke();
                const sh = Screen_.method("get_height").invoke();
                // corner to open
                if (p.x < 130 && p.y < 130) {
                    MENU.open = !MENU.open;
                    MENU.panel.method("SetActive").invoke(MENU.open);
                    showToast(MENU.open ? "OPEN" : "SHUT", color(0.3, 0.6, 1, 0.9));
                    continue;
                }
                if (!MENU.open) continue;
                // local coords relative to panel center (panel is centered on screen)
                const lx = p.x - sw / 2, ly = p.y - sh / 2;
                dispatchClick(lx, ly);
            }
        } catch (_) {}
    }
    function syncRows(rows) {
        for (const r of rows) {
            const w = r.widget;
            if (w.kind === "toggle") {
                setText(w.st, r.getter() ? "ON" : "OFF");
                w.st.method("GetComponent").overload("System.Type").invoke(typeOf(Text_))
                    .method("set_color").invoke(r.getter() ? color(0.4,1,0.6,1) : color(1,0.5,0.5,1));
            } else if (w.kind === "slider") {
                const val = r.getter();
                const frac = (val - w.min) / Math.max(1, w.max - w.min);
                const fw = Math.max(4, frac * 150);
                setRect(w.fill, 0, 0, fw, 6, [0, 0.5], [0, 0.5]);
                setText(w.vtxt, String(val));
            } else if (w.kind === "button") {
                const v = r.getter();
                if (v && v.length < 6) setText(w.bt, v);
            }
        }
    }
    function dispatchClick(lx, ly) {
        // tab bar y=210 (panel-local)
        if (Math.abs(ly - 210) < 20) {
            if (lx < -70) switchTab(0);
            else if (lx < 70) switchTab(1);
            else switchTab(2);
            return;
        }
        const rows = CFG.tab === 0 ? MENU.pages.aim.rows
                   : CFG.tab === 1 ? MENU.pages.esp.rows
                   : MENU.pages.settings.rows;
        // rows centered at y=160, step -40
        const idx = Math.round((160 - ly - 20) / 40);
        if (idx < 0 || idx >= rows.length) return;
        const r = rows[idx];
        const w = r.widget;
        if (w.kind === "toggle") {
            // tap within row 36px band
            r.setter(!r.getter());
        } else if (w.kind === "button") {
            r.setter(null);
            showToast("✓", color(0.3, 1, 0.5, 0.9));
        } else if (w.kind === "slider") {
            if (lx < 85) r.setter(Math.max(w.min, r.getter() - w.step));
            else if (lx > 220) r.setter(Math.min(w.max, r.getter() + w.step));
        }
    }

    // tick scheduler — avoid recursive-hook crashes. setInterval on JS thread,
    // IL2CPP work queued to Unity main thread via Il2Cpp.schedule.
    const schedSafe = (fn) => {
        try {
            if (Il2Cpp.scheduler && Il2Cpp.scheduler.schedule) {
                Il2Cpp.scheduler.schedule(() => { try { fn(); } catch (e) { LOG("sched", e); } });
            } else if (Il2Cpp.schedule) {
                Il2Cpp.schedule(() => { try { fn(); } catch (e) { LOG("sched", e); } });
            } else {
                // fallback: run inline, bridge usually attaches thread via perform
                try { fn(); } catch (e) { LOG("inline", e); }
            }
        } catch (e) { LOG("sched-outer", e); }
    };
    // 30 fps menu/animation, 15 fps ESP
    setInterval(() => schedSafe(tick), 33);
    setInterval(() => schedSafe(updateEsp), 66);
    // periodic pool detector
    setInterval(() => schedSafe(() => { try { if (CFG.shadow.poolDetect) poolDetectPass(); } catch (_) {} }), 4000);

    // ====================== WeaponFire auto-patch ======================
    function hookWeaponFire() {
        const WF = asm.class("WeaponFire");
        if (!WF) return;
        WF.methods.forEach(m => {
            const key = "WF." + m.name;
            if (hookedSet.has(key)) return;
            const n = m.name;

            if (/Recoil/i.test(n) && /Get|Calc|Apply|Update/.test(n)) {
                try {
                    const orig = m;
                    m.implementation = function () {
                        if (!CFG.noRecoil) return orig.invoke.apply(this, arguments);
                        const rt = m.returnType.name;
                        if (rt === "System.Single") return 0.0;
                        if (rt === "UnityEngine.Vector3") return v3(0, 0, 0);
                        if (rt === "System.Void") return;
                        return orig.invoke.apply(this, arguments);
                    };
                    hookedSet.add(key); LOG("recoil:", n);
                } catch (_) {}
            }
            if (/(Spread|Accuracy|Cone)/i.test(n) && /Get|Calc/.test(n)) {
                try {
                    const orig = m;
                    m.implementation = function () {
                        if (!CFG.noSpread) return orig.invoke.apply(this, arguments);
                        if (m.returnType.name === "System.Single") return 0.0;
                        return orig.invoke.apply(this, arguments);
                    };
                    hookedSet.add(key); LOG("spread:", n);
                } catch (_) {}
            }
            if (/CalcBulletDirection|GetFireDirection|ShootDirection|GetBulletDir|CalcShootDir/i.test(n)) {
                try {
                    const orig = m;
                    m.implementation = function (...args) {
                        const original = orig.invoke.apply(this, args);
                        if (!CFG.aim.on || CFG.aim.mode !== "silent") return original;
                        // anti-shadowban: humanize — miss rate + accuracy cap
                        if (Math.random() > CFG.aim.accuracyCap) return original;
                        if (CFG.shadow.humanize && Math.random() < CFG.shadow.missRate) return original;
                        const t = findBestTarget();
                        if (!t) return original;
                        // reaction delay — track per-target "first seen" time, skip if too fast
                        if (CFG.shadow.humanize && CFG.shadow.reactionMs > 0) {
                            const k = "r_" + t.pc.handle.toString();
                            const now = Date.now();
                            if (!reactionMap[k]) { reactionMap[k] = now; return original; }
                            if (now - reactionMap[k] < CFG.shadow.reactionMs) return original;
                        }
                        const camT = Camera.method("get_main").invoke().method("get_transform").invoke();
                        const camPos = camT.method("get_position").invoke();
                        let tx = t.pos.x, ty = t.pos.y, tz = t.pos.z;
                        if (CFG.aim.predictShot && t.vel) {
                            const dist = Math.hypot(tx - camPos.x, ty - camPos.y, tz - camPos.z);
                            const bulletTime = dist / 800;
                            tx += t.vel.x * bulletTime; ty += t.vel.y * bulletTime; tz += t.vel.z * bulletTime;
                        }
                        const dx = tx - camPos.x, dy = ty - camPos.y, dz = tz - camPos.z;
                        let len = Math.hypot(dx, dy, dz) || 1;
                        let nx = dx / len, ny = dy / len, nz = dz / len;
                        // aim jitter — micro-tremor in degrees → vector perturb
                        if (CFG.shadow.humanize && CFG.shadow.aimJitter > 0) {
                            const j = CFG.shadow.aimJitter * Math.PI / 180;
                            const yaw = (Math.random() * 2 - 1) * j;
                            const pit = (Math.random() * 2 - 1) * j;
                            // yaw around Y
                            const cy = Math.cos(yaw), sy = Math.sin(yaw);
                            const rx = nx * cy + nz * sy, rz = -nx * sy + nz * cy;
                            // pitch around X
                            const cp = Math.cos(pit), sp = Math.sin(pit);
                            const ry = ny * cp - rz * sp, rz2 = ny * sp + rz * cp;
                            nx = rx; ny = ry; nz = rz2;
                        }
                        return v3(nx, ny, nz);
                    };
                    hookedSet.add(key); LOG("silent-aim:", n);
                } catch (_) {}
            }
            if (/(Gravity|Drop|ApplyGravity)/i.test(n)) {
                try {
                    const orig = m;
                    m.implementation = function () {
                        if (!CFG.noBulletDrop) return orig.invoke.apply(this, arguments);
                        if (m.returnType.name === "System.Single") return 0.0;
                        if (m.returnType.name === "UnityEngine.Vector3") return v3(0, 0, 0);
                        return orig.invoke.apply(this, arguments);
                    };
                    hookedSet.add(key); LOG("drop:", n);
                } catch (_) {}
            }
            if (CFG.misc.autoHeadshot && /Hit|DamageTarget|OnHit/i.test(n)) {
                try {
                    const orig = m;
                    m.implementation = function (...args) {
                        if (CFG.misc.autoHeadshot) {
                            // set "part" argument (common enum: 0=body, 1=head, 2=...) to head
                            for (let i = 0; i < args.length; i++) {
                                if (typeof args[i] === "number" && args[i] >= 0 && args[i] <= 5) { args[i] = 1; break; }
                            }
                        }
                        return orig.invoke.apply(this, args);
                    };
                    hookedSet.add(key); LOG("headshot:", n);
                } catch (_) {}
            }
        });
    }
    function hookInstantHit() {
        const WF = asm.class("WeaponFire");
        if (!WF) return;
        WF.methods.forEach(m => {
            const key = "IH." + m.name;
            if (hookedSet.has(key)) return;
            if (!/BulletSpeed|GetBulletSpeed|InitSpeed|get_speed/i.test(m.name)) return;
            try {
                const orig = m;
                m.implementation = function () {
                    if (!CFG.misc.instantHit) return orig.invoke.apply(this, arguments);
                    if (m.returnType.name === "System.Single") return 50000.0;
                    return orig.invoke.apply(this, arguments);
                };
                hookedSet.add(key); LOG("instanthit:", m.name);
            } catch (_) {}
        });
    }

    // ====================== target search ======================
    function findBestTarget() {
        const PC = asm.class("PlayerController"); if (!PC) return null;
        const localPC = Il2Cpp.gc.choose(PC).find(p => safe(() => p.field("isLocalPlayer").value));
        if (!localPC) return null;
        const selfTeam = safe(() => localPC.field("teamId").value, -1);
        const selfPos = localPC.method("get_transform").invoke().method("get_position").invoke();

        const cam = Camera.method("get_main").invoke();
        if (cam.isNull()) return null;
        const camFwd = cam.method("get_transform").invoke().method("get_forward").invoke();
        const fov = CFG.aim.fovDeg;
        const minDot = fov >= 180 ? -1.001 : Math.cos(fov * Math.PI / 360);

        let best = null, bestDot = minDot;

        Il2Cpp.gc.choose(PC).forEach(p => {
            if (p.handle.equals(localPC.handle)) return;
            if (CFG.esp.teamCheck && safe(() => p.field("teamId").value) === selfTeam) return;
            if (!safe(() => p.field("alive").value, true)) return;

            let hp, vel;
            try {
                const bone = p.method("FindBone").invoke(Il2Cpp.string(CFG.aim.bone));
                if (bone.isNull()) return;
                hp = bone.method("get_position").invoke();
            } catch {
                hp = p.method("get_transform").invoke().method("get_position").invoke();
            }
            try {
                const rb = p.method("get_rigidbody").invoke();
                if (!rb.isNull()) vel = rb.method("get_velocity").invoke();
            } catch { vel = null; }

            const dx = hp.x - selfPos.x, dy = hp.y - selfPos.y, dz = hp.z - selfPos.z;
            const len = Math.hypot(dx, dy, dz) || 1;
            if (len > CFG.esp.maxDist) return;
            const dot = (dx * camFwd.x + dy * camFwd.y + dz * camFwd.z) / len;
            if (dot > bestDot) { bestDot = dot; best = { pc: p, pos: hp, vel, dist: len }; }
        });
        return best;
    }

    // ====================== ESP layer ======================
    const ESP = { layer: null, entries: [] };
    function buildEspLayer() {
        const g = mkGO("GalacticaESP"); dontDestroy(g);
        const c = g.method("AddComponent").overload("System.Type").invoke(typeOf(Canvas_));
        c.method("set_renderMode").invoke(0);
        c.method("set_sortingOrder").invoke(32766);
        g.method("AddComponent").overload("System.Type").invoke(typeOf(CanvasScaler));
        ESP.layer = g;
    }
    function espColor() {
        return [color(1, 0.3, 0.3, 1), color(1, 0.95, 0.3, 1), color(0.3, 1, 0.4, 1),
                color(0.3, 0.9, 1, 1), color(1, 0.4, 0.8, 1)][CFG.settings.espColor];
    }
    function updateEsp() {
        if (!ESP.layer) return;
        if (!CFG.esp.on) { ESP.entries.forEach(e => e.go.method("SetActive").invoke(false)); return; }
        const PC = asm.class("PlayerController"); if (!PC) return;
        const cam = Camera.method("get_main").invoke(); if (cam.isNull()) return;

        const localPC = Il2Cpp.gc.choose(PC).find(p => safe(() => p.field("isLocalPlayer").value));
        const selfTeam = localPC ? safe(() => localPC.field("teamId").value) : -1;
        const selfPos  = localPC ? localPC.method("get_transform").invoke().method("get_position").invoke() : v3(0,0,0);
        const col = espColor();

        const enemies = Il2Cpp.gc.choose(PC).filter(p => {
            if (localPC && p.handle.equals(localPC.handle)) return false;
            if (CFG.esp.teamCheck && safe(() => p.field("teamId").value) === selfTeam) return false;
            if (!safe(() => p.field("alive").value, true)) return false;
            return true;
        });

        while (ESP.entries.length < enemies.length) {
            const g = mkGO("e"+ESP.entries.length, ESP.layer);
            const box = mkGO("box", g);   addImage(box, col);
            const name = mkGO("nm", g);   addText(name, "", 12, color(1,1,1,1));
            const hpBg = mkGO("hpbg", g); addImage(hpBg, color(0,0,0,0.6));
            const hpFg = mkGO("hpfg", g); addImage(hpFg, color(0.3,1,0.4,0.9));
            const dist = mkGO("d", g);    addText(dist, "", 11, color(1,1,0.5,1));
            ESP.entries.push({ go: g, box, name, hpBg, hpFg, dist });
        }

        for (let i = 0; i < ESP.entries.length; i++) {
            const e = ESP.entries[i];
            if (i >= enemies.length) { e.go.method("SetActive").invoke(false); continue; }
            e.go.method("SetActive").invoke(true);
            const p = enemies[i];
            const tpos = p.method("get_transform").invoke().method("get_position").invoke();
            const sp = cam.method("WorldToScreenPoint").invoke(tpos);
            if (sp.z <= 0) { e.go.method("SetActive").invoke(false); continue; }
            const h = Screen_.method("get_height").invoke();
            const w = Screen_.method("get_width").invoke();
            const dist = Math.hypot(tpos.x - selfPos.x, tpos.y - selfPos.y, tpos.z - selfPos.z);
            if (dist > CFG.esp.maxDist) { e.go.method("SetActive").invoke(false); continue; }
            const boxH = Math.max(40, 2500 / Math.max(dist, 5));
            const boxW = boxH * 0.4;
            setRect(e.go, sp.x - w/2, sp.y - h/2, boxW, boxH);
            if (CFG.esp.box) {
                setRect(e.box, 0, 0, boxW, boxH);
                setImgColor(e.box, color(col.field("r").value, col.field("g").value, col.field("b").value, 0));
                const comp = e.box.method("GetComponent").overload("System.Type").invoke(typeOf(Image_));
                comp.method("set_type").invoke(1);
            } else { e.box.method("SetActive").invoke(false); }
            if (CFG.esp.name) {
                const nm = safe(() => (p.field("playerName").value + ""), "ENEMY");
                setText(e.name, nm);
                setRect(e.name, 0, boxH/2 + 10, boxW + 60, 14);
            } else e.name.method("SetActive").invoke(false);
            if (CFG.esp.hp) {
                const cur = safe(() => p.field("curHp").value, 100);
                const max = safe(() => p.field("maxHp").value, 100);
                const ratio = Math.max(0, Math.min(1, cur / max));
                setRect(e.hpBg, -boxW/2 - 6, 0, 4, boxH);
                setRect(e.hpFg, -boxW/2 - 6, -boxH/2 + (boxH*ratio)/2, 4, boxH * ratio);
            } else { e.hpBg.method("SetActive").invoke(false); e.hpFg.method("SetActive").invoke(false); }
            if (CFG.esp.distance) {
                setText(e.dist, Math.round(dist) + "m");
                setRect(e.dist, 0, -boxH/2 - 10, boxW + 40, 12);
            } else e.dist.method("SetActive").invoke(false);
        }
    }

    // ====================== legit cam path ======================
    function hookLegitCam() {
        const PC = asm.class("PlayerController"); if (!PC) return;
        PC.methods.forEach(m => {
            if (m.name !== "LateUpdate") return;
            const key = "LC." + PC.name;
            if (hookedSet.has(key)) return;
            try {
                const orig = m;
                m.implementation = function () {
                    const r = orig.invoke.apply(this, arguments);
                    if (!CFG.aim.on || CFG.aim.mode === "silent" || CFG.aim.noIndicator) return r;
                    if (!safe(() => this.field("isLocalPlayer").value)) return r;
                    const t = findBestTarget();
                    if (!t) return r;
                    const camT = Camera.method("get_main").invoke().method("get_transform").invoke();
                    const cp = camT.method("get_position").invoke();
                    const dx = t.pos.x - cp.x, dy = t.pos.y - cp.y, dz = t.pos.z - cp.z;
                    const yaw = Math.atan2(dx, dz) * 180 / Math.PI;
                    const pitch = -Math.atan2(dy, Math.hypot(dx, dz)) * 180 / Math.PI;
                    const cur = camT.method("get_eulerAngles").invoke();
                    const s = CFG.aim.smoothing;
                    camT.method("set_eulerAngles").invoke(v3(
                        cur.x + (pitch - cur.x) * (1 - s),
                        cur.y + (yaw - cur.y) * (1 - s),
                        0));
                    return r;
                };
                hookedSet.add(key);
            } catch (_) {}
        });
    }

    // ====================== anti-hack auto-stub (grows) ======================
    function stubAntiHack() {
        if (!CFG.antiban.autoStub) return;
        const CLS_RX = /(AntiHack|antihack|GameSecurity|AccountSecurity|SecurityManager|IntegrityCheck|CheckHacker|ExistHacker|WallHackDetect|FFAntiHack|HackerCdtID|EnterSecureMode|TamperCheck)/i;
        const M_RX = /(check|verify|detect|validate|scan|report|is[A-Z]|has[A-Z]|enabled|measure)/;
        asm.classes.forEach(cls => {
            if (!CLS_RX.test(cls.name)) return;
            cls.methods.forEach(m => {
                if (!M_RX.test(m.name)) return;
                const key = "AH." + cls.name + "." + m.name;
                if (hookedSet.has(key)) return;
                try {
                    const orig = m;
                    m.implementation = function () {
                        if (!CFG.antiban.autoStub) return orig.invoke.apply(this, arguments);
                        const rt = m.returnType.name;
                        if (rt === "System.Boolean") return false;
                        if (rt === "System.Int32" || rt === "System.Int64") return 0;
                        if (rt === "System.Single" || rt === "System.Double") return 0.0;
                        if (rt === "System.Void") return;
                        return orig.invoke.apply(this, arguments);
                    };
                    hookedSet.add(key);
                } catch (_) {}
            });
        });
        // ACE obfuscated 10-char symbols
        asm.classes.forEach(cls => {
            if (!/^ACE[A-Z]{7,}$/.test(cls.name)) return;
            cls.methods.forEach(m => {
                if (m.returnType.name !== "System.Boolean") return;
                const key = "ACE." + cls.name + "." + m.name;
                if (hookedSet.has(key)) return;
                try {
                    const orig = m;
                    m.implementation = function () {
                        return CFG.antiban.autoStub ? false : orig.invoke.apply(this, arguments);
                    };
                    hookedSet.add(key);
                } catch (_) {}
            });
        });
    }

    // ====================== BAN capture ======================
    function hookBanCapture() {
        if (!CFG.antiban.captureBan) return;
        const logFile = "/var/mobile/Documents/ban-trace.log";
        const File = Il2Cpp.domain.assembly("mscorlib").image.class("System.IO.File");
        const write = (line) => {
            try {
                File.method("AppendAllText").overload("System.String", "System.String")
                    .invoke(Il2Cpp.string(logFile),
                        Il2Cpp.string(`[${new Date().toISOString()}] ${line}\n`));
            } catch (_) { LOG("[ban]", line); }
        };
        asm.classes.forEach(cls => {
            cls.methods.forEach(m => {
                const n = m.name.toLowerCase();
                if (!/ban|kick|disconnect|punish/.test(n)) return;
                if (!/handle|recv|on|process|dispatch|parse/.test(n)) return;
                const key = "BAN." + cls.name + "." + m.name;
                if (hookedBan.has(key)) return;
                try {
                    const orig = m;
                    m.implementation = function (...args) {
                        try {
                            const parts = args.map((a, i) => {
                                try {
                                    if (a == null) return `a${i}=null`;
                                    if (typeof a === "number") return `a${i}=${a}`;
                                    const t = a.class ? a.class.name : typeof a;
                                    let v = ""; try { v = (a + "").slice(0, 200); } catch { v = "?"; }
                                    return `a${i}:${t}=${v}`;
                                } catch { return `a${i}=err`; }
                            }).join(" | ");
                            write(`BAN ${cls.name}.${m.name} :: ${parts}`);
                            showToast("BAN?", color(1, 0.3, 0.3, 0.9));
                        } catch (_) {}
                        return orig.invoke.apply(this, args);
                    };
                    hookedBan.add(key);
                } catch (_) {}
            });
        });
    }

    // ====================== Guest reset ======================
    function doGuestReset() {
        showToast("…", color(0.3, 0.6, 1, 0.9));
        try {
            let fired = 0;
            asm.classes.forEach(cls => {
                if (!/Guest|Login|Account/i.test(cls.name)) return;
                cls.methods.forEach(m => {
                    if (/^ResetGuest$|^resetGuest$|^MigrateGuest$/.test(m.name)) {
                        try { m.invoke(); fired++; LOG("reset:", cls.name + "." + m.name); } catch (_) {}
                    }
                });
            });
            asm.classes.forEach(cls => {
                cls.methods.forEach(m => {
                    if (/^FixDeviceID$|^GetGOPDeviceID$|^RefreshDeviceId$/.test(m.name)) {
                        try { m.invoke(); fired++; } catch (_) {}
                    }
                });
            });
            try {
                const kc = ObjC.classes.SAMKeychain;
                if (kc) {
                    const services = kc.allServices();
                    for (let i = 0; i < services.count(); i++) {
                        const s = services.objectAtIndex_(i) + "";
                        if (/garena|freefire|device/i.test(s)) kc.deletePasswordForService_account_(s, "deviceId");
                    }
                }
            } catch (_) {}
            showToast(fired ? "✓" : "✗", fired ? color(0.3, 1, 0.5, 0.9) : color(1, 0.4, 0.4, 0.9));
        } catch (e) { LOG("guest", e); showToast("✗", color(1, 0.4, 0.4, 0.9)); }
    }

    // ====================== native bypass ======================
    // Only BOOL-return security checks are stubbed. Callbacks that return objects
    // (NSString/NSDictionary) are left untouched to prevent nil-deref crashes.
    let nativeBypassInstalled = false;
    function nativeBypass() {
        if (nativeBypassInstalled) return;
        nativeBypassInstalled = true;
        const safeReplaceBoolRet = (klass, sel, where) => {
            try {
                const m = klass[sel];
                if (!m) return;
                Interceptor.replace(m.implementation,
                    new NativeCallback(() => 0, "int", ["pointer", "pointer"]));
                LOG(where + ":" + sel + " → NO");
            } catch (e) { LOG("replace " + sel, e); }
        };
        if (CFG.antiban.killDataDome) {
            const DD = ObjC.classes.DataDomeSDK;
            if (DD) {
                safeReplaceBoolRet(DD, "- isJailbrokenWithSkipAdvancedJailbreakValidation:", "DD");
                safeReplaceBoolRet(DD, "- isIntegrityEnabled", "DD");
            }
            for (const cn of ["AppsFlyerTracker", "AppsFlyerLib", "AFSDKJailbreakCheck"]) {
                const c = ObjC.classes[cn]; if (!c) continue;
                try {
                    for (const sel of Object.keys(c["$ownMethods"])) {
                        // narrow: only clearly boolean "is*" probes — not "calculate*" methods
                        // (those return NSString/NSNumber and nil-returning would crash caller)
                        if (/^- is(JailBroken|DebuggerAttached|DevBuild|Simulator|Jailbroken)[a-zA-Z]*$/i.test(sel)) {
                            safeReplaceBoolRet(c, sel, "AF");
                        }
                    }
                } catch (_) {}
            }
            // FBSDKIntegrityManager — left alone (process* returns NSDictionary*, nil-crashes caller)
        }
        if (CFG.antiban.hideJB) {
            const JB = ["/Applications/Cydia.app","/Applications/Sileo.app","/Applications/TrollStore.app",
                        "/private/var/lib/apt","/private/var/jb","/usr/sbin/sshd","/bin/bash","/var/jb"];
            ["stat","lstat","fopen","access","open"].forEach(fn => {
                const a = Module.findExportByName(null, fn); if (!a) return;
                if (hookedSet.has("N." + fn)) return; hookedSet.add("N." + fn);
                Interceptor.attach(a, {
                    onEnter(args) { const p = args[0].readUtf8String(); this.block = p && JB.some(j => p.indexOf(j) === 0); },
                    onLeave(ret) { if (this.block) ret.replace(fn === "fopen" ? ptr(0) : ptr(-1)); }
                });
            });
            const g = Module.findExportByName(null, "_dyld_get_image_name");
            if (g && !hookedSet.has("N._dyld")) {
                hookedSet.add("N._dyld");
                Interceptor.attach(g, {
                    onLeave(ret) {
                        const s = ret.readUtf8String() || "";
                        if (/frida|substrate|cycript|libhooker|ellekit|choicy|troll|nativeunity/i.test(s))
                            ret.replace(Memory.allocUtf8String("/usr/lib/libSystem.B.dylib"));
                    }
                });
            }
            const sc = Module.findExportByName(null, "sysctl");
            if (sc && !hookedSet.has("N.sysctl")) {
                hookedSet.add("N.sysctl");
                Interceptor.attach(sc, {
                    onEnter(a) { this.oldp = a[2]; this.oldlenp = a[3]; },
                    onLeave() {
                        try {
                            if (this.oldp && !this.oldp.isNull() && this.oldlenp && !this.oldlenp.isNull()) {
                                const len = this.oldlenp.readU64();
                                if (len >= 648) {
                                    const fl = this.oldp.add(32).readU32();
                                    if (fl & 0x800) this.oldp.add(32).writeU32(fl & ~0x800);
                                }
                            }
                        } catch (_) {}
                    }
                });
            }
        }
    }

    // ====================== anti-shadowban hooks ======================
    function hookTelemetry() {
        if (!CFG.shadow.telemetryBlock) return;
        // кесетіндер: ReportAnti*, HackerReport*, SendAccuracy*, UploadBehavior*, SendCombatStats*
        const M_RX = /^(Send|Upload|Post|Flush)(Anti|Hack|Behavior|Combat|Stat|Accuracy|Pattern|Metric)/i;
        try {
            asm.classes.forEach(cls => {
                try {
                    cls.methods.forEach(m => {
                        if (!M_RX.test(m.name)) return;
                        const key = "TEL." + cls.name + "." + m.name;
                        if (hookedShadow.has(key)) return;
                        try {
                            const orig = m;
                            m.implementation = function () {
                                if (!CFG.shadow.telemetryBlock) return orig.invoke.apply(this, arguments);
                                if (m.returnType.name === "System.Boolean") return true;
                                if (m.returnType.name === "System.Int32") return 0;
                                if (m.returnType.name === "System.Void") return;
                                return orig.invoke.apply(this, arguments);
                            };
                            hookedShadow.add(key); LOG("telemetry blocked:", cls.name + "." + m.name);
                        } catch (_) {}
                    });
                } catch (_) {}
            });
            // ACE обфускация әрі статистика-upload
            asm.classes.forEach(cls => {
                if (!/^ACE[A-Z]{7,}$/.test(cls.name)) return;
                try {
                    cls.methods.forEach(m => {
                        if (!/send|post|upload|report/i.test(m.name)) return;
                        const key = "ACE_TEL." + cls.name + "." + m.name;
                        if (hookedShadow.has(key)) return;
                        try {
                            const orig = m;
                            m.implementation = function () {
                                if (!CFG.shadow.telemetryBlock) return orig.invoke.apply(this, arguments);
                                if (m.returnType.name === "System.Void") return;
                                if (m.returnType.name === "System.Boolean") return true;
                                return orig.invoke.apply(this, arguments);
                            };
                            hookedShadow.add(key);
                        } catch (_) {}
                    });
                } catch (_) {}
            });
        } catch (e) { LOG("telemetry hook", e); }
    }

    function hookReportImmunity() {
        if (!CFG.shadow.reportImmune) return;
        // ReportPlayer / SendReport / MsgReport — payload-та target-ты босатамыз
        try {
            asm.classes.forEach(cls => {
                try {
                    cls.methods.forEach(m => {
                        if (!/^(Report|SendReport|SubmitReport|DoReport|OnReport)/i.test(m.name)) return;
                        if (/Daily|Weekly|Stats|Shop|Store|Mission|Progress/i.test(m.name)) return;
                        const key = "RI." + cls.name + "." + m.name;
                        if (hookedShadow.has(key)) return;
                        try {
                            const orig = m;
                            m.implementation = function (...args) {
                                if (!CFG.shadow.reportImmune) return orig.invoke.apply(this, args);
                                try {
                                    if (!MY_UID) return orig.invoke.apply(this, args);
                                    for (let i = 0; i < args.length; i++) {
                                        const a = args[i];
                                        if (typeof a !== "number") continue;
                                        if (a === MY_UID) {
                                            // Бізді репорт еткен — мәнсіз айналдырамыз
                                            LOG("swallowed report hitting me:", cls.name + "." + m.name);
                                            return (m.returnType.name === "System.Boolean") ? true : 0;
                                        }
                                    }
                                } catch (_) {}
                                return orig.invoke.apply(this, args);
                            };
                            hookedShadow.add(key);
                        } catch (_) {}
                    });
                } catch (_) {}
            });
        } catch (e) { LOG("report-imm", e); }
    }

    let fingerprintRotated = false;
    function fingerprintRotate() {
        if (!CFG.shadow.fingerprintRotate) return;
        if (fingerprintRotated) return;
        fingerprintRotated = true;
        try {
            // UIDevice.identifierForVendor → жаңа UUID
            const UIDevice = ObjC.classes.UIDevice;
            if (UIDevice) {
                const NSUUID = ObjC.classes.NSUUID;
                const fresh = NSUUID.UUID();
                try {
                    Interceptor.replace(UIDevice["- identifierForVendor"].implementation,
                        new NativeCallback(() => fresh.handle, "pointer", ["pointer", "pointer"]));
                    LOG("IDFV rotated:", fresh.UUIDString() + "");
                } catch (_) {}
            }
            // Keychain-тағы deviceId-ды өшіру
            const kc = ObjC.classes.SAMKeychain;
            if (kc) {
                try {
                    const services = kc.allServices();
                    for (let i = 0; i < services.count(); i++) {
                        const s = services.objectAtIndex_(i) + "";
                        if (/garena|freefire|device|aces|appsflyer/i.test(s))
                            kc.deletePasswordForService_account_(s, "deviceId");
                    }
                } catch (_) {}
            }
            // AppsFlyer UID reset
            try {
                const AF = ObjC.classes.AppsFlyerLib || ObjC.classes.AppsFlyerTracker;
                if (AF && AF.shared && AF.shared() && AF.shared().setCustomerUserID_) {
                    AF.shared().setCustomerUserID_("");
                }
            } catch (_) {}
            // NSUserDefaults — garena/aces кеш кілттерін тазарту
            try {
                const UD = ObjC.classes.NSUserDefaults.standardUserDefaults();
                const dict = UD.dictionaryRepresentation();
                const keys = dict.allKeys();
                for (let i = 0; i < keys.count(); i++) {
                    const k = keys.objectAtIndex_(i) + "";
                    if (/garena|aces|freefire|hwid|deviceid|idfv|appsflyer/i.test(k))
                        UD.removeObjectForKey_(k);
                }
                UD.synchronize();
            } catch (_) {}
        } catch (e) { LOG("fp-rotate", e); }
    }

    function queueDodge() {
        showToast("…", color(0.3, 0.6, 1, 0.9));
        try {
            // matchmaker ping cookie-ларын тазарту
            try {
                const UD = ObjC.classes.NSUserDefaults.standardUserDefaults();
                const dict = UD.dictionaryRepresentation();
                const keys = dict.allKeys();
                for (let i = 0; i < keys.count(); i++) {
                    const k = keys.objectAtIndex_(i) + "";
                    if (/matchmake|queue|mmr|pool|lobby/i.test(k))
                        UD.removeObjectForKey_(k);
                }
                UD.synchronize();
            } catch (_) {}
            // Lobby/Queue сұраныстарды қайта жүктеу
            let fired = 0;
            asm.classes.forEach(cls => {
                if (!/Matchmake|Lobby|Queue/i.test(cls.name)) return;
                try {
                    cls.methods.forEach(m => {
                        if (/^(ClearCache|Reset|Rejoin|Reconnect|ForceRefresh|Clear)/i.test(m.name)) {
                            try { m.invoke(); fired++; LOG("queue-dodge:", cls.name + "." + m.name); } catch (_) {}
                        }
                    });
                } catch (_) {}
            });
            showToast(fired > 0 ? "✓" : "✓", color(0.3, 1, 0.5, 0.9));
            POOL_SUSPECT_COUNT = 0;
        } catch (e) { LOG("queue-dodge", e); showToast("✗", color(1, 0.4, 0.4, 0.9)); }
    }

    function poolDetectPass() {
        if (!CFG.shadow.poolDetect) return;
        const PC = asm.class("PlayerController"); if (!PC) return;
        let suspect = 0;
        try {
            Il2Cpp.gc.choose(PC).forEach(p => {
                try {
                    const h = safe(() => p.field("headshotRatio").value, null);
                    const acc = safe(() => p.field("accuracyPct").value, null);
                    const kills = safe(() => p.field("totalKills").value, null);
                    if (h !== null && h > 0.75) suspect++;
                    else if (acc !== null && acc > 85) suspect++;
                    else if (kills !== null && kills > 15000) suspect++;
                } catch (_) {}
            });
        } catch (_) {}
        if (suspect >= 3) {
            POOL_SUSPECT_COUNT++;
            if (POOL_SUSPECT_COUNT === 1) {
                showToast("POOL!", color(1, 0.5, 0.3, 0.9));
                LOG("[pool] cheater lobby suspected, suspects=", suspect);
            }
        } else {
            POOL_SUSPECT_COUNT = 0;
        }
    }

    function resolveMyUid() {
        try {
            const PC = asm.class("PlayerController"); if (!PC) return;
            const local = Il2Cpp.gc.choose(PC).find(p => safe(() => p.field("isLocalPlayer").value));
            if (local) {
                MY_UID = safe(() => local.field("uid").value, null)
                      || safe(() => local.field("userId").value, null)
                      || safe(() => local.field("playerId").value, null);
                if (MY_UID) LOG("MY_UID =", MY_UID);
            }
        } catch (_) {}
    }

    // ====================== kick off ======================
    // SAFE-BOOT: only build UI. No hook installs at startup.
    // Every hook* only runs when its CFG flag is true AND the 5-s re-scan fires,
    // so flipping a toggle in the menu is what first touches the game code.
    try { buildMenu(); }      catch (e) { LOG("buildMenu", e); }
    try { buildEspLayer(); }  catch (e) { LOG("buildEspLayer", e); }
    try { reskin(); }         catch (_) {}

    setInterval(() => schedSafe(resolveMyUid), 8000);

    // periodic re-scan — ONLY installs hooks whose feature is currently on
    setInterval(() => schedSafe(() => {
        try {
            if (CFG.aim.on || CFG.noRecoil || CFG.noSpread || CFG.noBulletDrop ||
                CFG.misc.autoHeadshot) hookWeaponFire();
            if (CFG.aim.on && CFG.aim.mode !== "silent") hookLegitCam();
            if (CFG.misc.instantHit) hookInstantHit();
            if (CFG.antiban.autoStub) stubAntiHack();
            if (CFG.antiban.captureBan) hookBanCapture();
            if (CFG.antiban.killDataDome || CFG.antiban.hideJB) nativeBypass();
            if (CFG.shadow.telemetryBlock) hookTelemetry();
            if (CFG.shadow.reportImmune) hookReportImmunity();
            if (CFG.shadow.fingerprintRotate) fingerprintRotate();
        } catch (e) { LOG("rescan", e); }
    }), 5000);

    LOG("Galactica ready — menu only, hooks off until you flip a toggle");
}), SAFE_BOOT_DELAY_MS);
