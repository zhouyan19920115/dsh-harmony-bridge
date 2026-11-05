/**
 * DSH Harmony 桥接 —— 客户端插件（浏览器端）。
 *
 * 两处入口：
 *   1. 插件详情页右上角「打开桥接设置」按钮（plugins.detail.actions）→ 打开整页设置面板（main 槽）；
 *   2. 「设置」里多一节「DSH Harmony 桥接」（settings.section）。
 *
 * 配置读写走后端本地接口 /plugins/dsh-harmony-bridge/api（loopback only）。
 */
window.__ModuleLoader__.load({
  id: "dsh-harmony-bridge",
  factory: (require) => {
    const module = { exports: {} };
    const exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
    const React = require("react");
    const h = React.createElement;
    const API = "/plugins/dsh-harmony-bridge/api";
    const PACKAGE_NAME = "dsh-harmony-bridge";
    const PANEL_ID = "dsh-harmony-bridge-settings";

    const FIELDS = [
      { key: "port", label: "端口", type: "number", hint: "手机自动探测优先扫 8787；换端口后手机要手动填地址" },
      { key: "host", label: "监听地址", type: "text", hint: "0.0.0.0 = 局域网可连；127.0.0.1 = 只有本机/中继能连" },
      { key: "relay", label: "云中继地址", type: "text", hint: "wss://…；留空 = 只走局域网" },
      { key: "relayPublicUrl", label: "中继公开地址", type: "text", hint: "可选：中继对手机暴露的地址" },
      { key: "relayName", label: "中继设备名", type: "text", hint: "可选：中继里显示的名字" },
      { key: "deviceId", label: "设备号 deviceId", type: "text", hint: "第一次接中继时填；已有 bridge.json 的电脑留空" },
      { key: "deviceToken", label: "设备令牌 deviceToken", type: "password", hint: "和 deviceId 一起填" },
      { key: "account", label: "账号 account", type: "text", hint: "可选：多设备归同一账号" },
      { key: "accountToken", label: "账号令牌 accountToken", type: "password", hint: "和 account 一起填" },
      { key: "relayCa", label: "中继证书 relayCa", type: "text", hint: "可选：自签证书 PEM 文件路径" }
    ];

    const CSS = `
.dhb-section{display:flex;flex-direction:column;gap:14px;max-width:860px;color:var(--dsw-alias-label-primary,#111827)}
.dhb-title{margin:0;font-size:18px;line-height:26px;font-weight:650}
.dhb-subtitle{margin:3px 0 0;color:var(--dsw-alias-label-tertiary,#6b7280);font-size:12px;line-height:18px}
.dhb-panel{border:1px solid var(--dsw-alias-border-l2,#d8dbe0);border-radius:8px;padding:14px;background:var(--dsw-alias-bg-layer-2,#f8fafc);display:flex;flex-direction:column;gap:12px}
.dhb-row{display:grid;grid-template-columns:180px minmax(0,1fr);gap:8px 14px;align-items:center}
.dhb-label{font-size:12px;color:var(--dsw-alias-label-secondary,#4b5563)}
.dhb-hint{margin:0;font-size:11px;line-height:16px;color:var(--dsw-alias-label-tertiary,#6b7280)}
.dhb-input{width:100%;box-sizing:border-box;height:32px;border:1px solid var(--dsw-alias-border-l2,#d8dbe0);border-radius:7px;background:var(--dsw-alias-bg-layer-1,#fff);color:inherit;padding:0 9px;font:inherit;font-size:12px}
.dhb-check{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--dsw-alias-label-secondary,#4b5563)}
.dhb-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.dhb-btn{height:32px;border:1px solid #2f6fed;border-radius:8px;background:#2f6fed;color:#fff;padding:0 16px;font:inherit;font-size:12px;cursor:pointer}
.dhb-btn:hover{background:#3b7bf0}
.dhb-btn:disabled{opacity:.5;cursor:default}
.dhb-btn.ghost{background:transparent;border-color:var(--dsw-alias-border-l2,#d8dbe0);color:inherit}
.dhb-msg{margin:0;font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary,#4b5563);white-space:pre-wrap}
.dhb-meta{display:grid;grid-template-columns:128px minmax(0,1fr);gap:6px 14px;font-size:12px;line-height:18px}
.dhb-key{color:var(--dsw-alias-label-tertiary,#6b7280)}
.dhb-value{min-width:0;word-break:break-all;color:var(--dsw-alias-label-secondary,#4b5563)}
.dhb-page{padding:24px 28px;overflow:auto;height:100%;box-sizing:border-box}
.dhb-back{height:30px;border:1px solid var(--dsw-alias-border-l2,#d8dbe0);border-radius:8px;background:transparent;color:inherit;padding:0 12px;font:inherit;font-size:12px;cursor:pointer;margin-bottom:16px}
.dhb-openBtn{height:30px;border:1px solid var(--dsw-alias-border-l3,#d1d5db);border-radius:8px;background:transparent;color:inherit;padding:0 12px;font:inherit;font-size:12px;cursor:pointer;white-space:nowrap}
`;

    function ensureStyles() {
      try {
        if (document.getElementById("dhb-styles") !== null) return;
        const style = document.createElement("style");
        style.id = "dhb-styles";
        style.textContent = CSS;
        document.head.appendChild(style);
      } catch {
        /* 非浏览器环境忽略 */
      }
    }

    async function request(path, options) {
      const res = await fetch(`${API}${path}`, options);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`);
      return data;
    }

    function BridgeSettings() {
      const [status, setStatus] = React.useState(undefined);
      const [form, setForm] = React.useState({});
      const [message, setMessage] = React.useState("");
      const [busy, setBusy] = React.useState(false);

      const load = async () => {
        try {
          const data = await request("/status");
          setStatus(data);
          setForm(data.config ?? {});
        } catch (error) {
          setMessage(`读取失败: ${error.message}`);
        }
      };
      React.useEffect(() => { load(); }, []);

      const setField = (key, value) => setForm((prev) => ({ ...prev, [key]: value }));
      const save = async () => {
        setBusy(true);
        try {
          const res = await request("/config", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(form)
          });
          setMessage(`已保存: ${res.file}\n重启 DSH 后生效（插件会按新配置启动桥接）。`);
          await load();
        } catch (error) {
          setMessage(`保存失败: ${error.message}`);
        } finally {
          setBusy(false);
        }
      };

      const bridge = status?.bridge ?? {};
      return h("div", { className: "dhb-section" },
        h("div", null,
          h("h2", { className: "dhb-title" }, "DSH Harmony 手机桥接"),
          h("p", { className: "dhb-subtitle" }, "手机 App 通过这个桥接连上本机 DSH；改完重启 DSH 生效。")
        ),
        h("div", { className: "dhb-panel" },
          h("div", { className: "dhb-meta" },
            h("span", { className: "dhb-key" }, "桥接地址"),
            h("span", { className: "dhb-value" }, bridge.url ?? "—"),
            h("span", { className: "dhb-key" }, "随 DSH 启动"),
            h("span", { className: "dhb-value" }, bridge.autoStart === false ? "关" : "开"),
            h("span", { className: "dhb-key" }, "配置文件"),
            h("span", { className: "dhb-value" }, status?.configFile ?? "—")
          )
        ),
        h("div", { className: "dhb-panel" },
          FIELDS.map((field) => h("div", { className: "dhb-row", key: field.key },
            h("label", { className: "dhb-label", htmlFor: `dhb-${field.key}` }, field.label),
            h("div", null,
              h("input", {
                id: `dhb-${field.key}`,
                className: "dhb-input",
                type: field.type,
                value: form[field.key] ?? "",
                onChange: (event) => setField(field.key, field.type === "number" ? Number(event.target.value || 0) : event.target.value)
              }),
              h("p", { className: "dhb-hint" }, field.hint)
            )
          )),
          h("label", { className: "dhb-check" },
            h("input", {
              type: "checkbox",
              checked: form.autoStart !== false,
              onChange: (event) => setField("autoStart", event.target.checked)
            }),
            "随 DSH 自动启动桥接"
          ),
          h("label", { className: "dhb-check" },
            h("input", {
              type: "checkbox",
              checked: form.verbose === true,
              onChange: (event) => setField("verbose", event.target.checked)
            }),
            "把桥接日志打到 DSH 控制台"
          ),
          h("div", { className: "dhb-actions" },
            h("button", { className: "dhb-btn", onClick: save, disabled: busy }, busy ? "保存中…" : "保存"),
            h("button", { className: "dhb-btn ghost", onClick: load, disabled: busy }, "重新读取")
          ),
          message.length > 0 ? h("p", { className: "dhb-msg" }, message) : null
        )
      );
    }

    /** 插件详情页右上角的按钮 */
    function OpenBridgeAction({ subject, packageName, onOpen }) {
      if (subject?.kind !== "bundle" && subject?.kind !== "row") return null;
      if (subject.pkg?.name !== packageName) return null;
      if (subject.kind === "row" && subject.row?.moduleName !== packageName) return null;
      return h("button", { type: "button", className: "dhb-openBtn", onClick: onOpen }, "打开桥接设置");
    }

    /** 整页设置面板 */
    function BridgePage({ onBack }) {
      return h("div", { className: "dhb-page" },
        h("button", { type: "button", className: "dhb-back", onClick: onBack }, "‹ 返回插件详情"),
        h(BridgeSettings, null)
      );
    }

    function apply(ctx) {
      try {
        ensureStyles();
        // 1) 插件详情页右上角按钮 + 整页设置面板
        if (typeof ctx.inject === "function") {
          ctx.inject(["layout", "pluginNavigation"], (pageCtx) => {
            const stopPage = pageCtx.slots.inject("main", () => pageCtx.slots.register({
              name: "main", key: PANEL_ID,
              inject: () => ({
                onBack: () => pageCtx.pluginNavigation.openBundle(PACKAGE_NAME)
              })
            }, BridgePage));
            const stopAction = pageCtx.slots.inject("plugins.detail.actions", () => pageCtx.slots.register({
              name: "plugins.detail.actions", id: "dsh-harmony-bridge-open", order: 20,
              inject: () => ({
                packageName: PACKAGE_NAME,
                onOpen: () => pageCtx.layout.selectPanel(PANEL_ID)
              })
            }, OpenBridgeAction));
            return () => {
              stopAction();
              stopPage();
            };
          });
        }
        // 2) 「设置」里的一节
        ctx.slots.inject("settings.section", () => ctx.slots.register({
          name: "settings.section", id: "harmony-bridge", order: 450, label: "DSH Harmony 桥接"
        }, BridgeSettings));
      } catch (error) {
        console.error("[dsh-harmony-bridge] settings UI failed to load:", error);
      }
    }

    exports.apply = apply;
    exports.inject = ["slots", "locale"];
    exports.name = "dsh-harmony-bridge-client";
    return module.exports;
  }
});
