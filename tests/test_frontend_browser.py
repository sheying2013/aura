"""Offline browser regressions: all documents, scripts and APIs are route fixtures.

No application service is started. No live API or external resource is contacted.
Run: python3 -m pytest tests/test_frontend_browser.py -q
"""
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "backend" / "static"


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as playwright:
        candidates = [os.environ.get("AURA_TEST_BROWSER"),
                      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
        executable = next((p for p in candidates if p and Path(p).is_file()), None)
        try:
            instance = playwright.chromium.launch(
                headless=True,
                timeout=10000,
                executable_path=executable,
                args=["--disable-background-networking", "--disable-component-update",
                      "--no-first-run", "--no-default-browser-check",
                      "--host-resolver-rules=MAP * ~NOTFOUND"],
            )
        except sync_api.Error as exc:
            pytest.skip(f"Local browser unavailable (no download attempted): {exc}")
        yield instance
        instance.close()


def node(node_id="n1", status="offline", **overrides):
    return {"id": node_id, "name": node_id, "group": "default", "port": 52001,
            "status": status, "protocol": "socks5", "entryProto": "mixed",
            "upTraffic": 0, "downTraffic": 0, "ping": 0, **overrides}


@pytest.fixture
def ui(browser):
    context = browser.new_context(service_workers="block")
    page = context.new_page()
    page.set_default_timeout(5000)
    page.set_default_navigation_timeout(10000)
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    state = {
        "nodes": [node("n1"), node("n2", "online"), node("n3", "disabled")],
        "settings": {"inboundPort": 2080, "autoRefresh": True, "relayDomains": [
            {"id": "r1", "domain": "relay.example", "port": 33440,
             "authUser": "user", "authPass": "pass", "groups": ["ALL"]}]},
        "requests": [], "responses": {}, "passwordChangeRequired": False,
        "subs": [],
    }

    def route(request_route):
        request = request_route.request
        parsed = urlparse(request.url)
        path = parsed.path
        if parsed.hostname != "aura.test":
            request_route.abort()  # Fonts and any other external URL never leave the browser.
            return
        if path in ("/", "/index.html"):
            request_route.fulfill(body=(STATIC / "index.html").read_text(), content_type="text/html")
            return
        if path == "/js/main.js":
            request_route.fulfill(body=(STATIC / "js" / "main.js").read_text(),
                                  content_type="application/javascript")
            return
        if not path.startswith("/api/"):
            request_route.abort()
            return
        payload = json.loads(request.post_data or "null")
        state["requests"].append((request.method, path, payload))
        custom = state["responses"].get(path)
        if custom:
            status, data = custom
        else:
            status = 200
            if path == "/api/auth/check":
                data = {"ok": True}
            elif path == "/api/auth/status":
                data = {"passwordChangeRequired": state["passwordChangeRequired"]}
            elif path == "/api/nodes":
                data = {"items": state["nodes"]}
            elif path == "/api/settings":
                if request.method == "PUT":
                    state["settings"] = payload
                    data = {"configApplied": True}
                else:
                    data = state["settings"]
            elif path == "/api/subs":
                data = state["subs"]
            elif path == "/api/config/status":
                data = {"running": True, "uptime": 3661}
            elif path == "/api/config":
                data = {"config": {"inbounds": []}}
            elif path == "/api/config/apply":
                data = {"ok": True, "message": "applied"}
            elif path == "/api/nodes/ping":
                data = []
            elif request.method == "PATCH" and path.startswith("/api/nodes/"):
                target = next(n for n in state["nodes"] if n["id"] == path.rsplit("/", 1)[1])
                target.update(payload)
                data = target
            else:
                data = {"ok": True}
        request_route.fulfill(status=status, body=json.dumps(data), content_type="application/json")

    context.route("**/*", route)
    page.add_init_script("""
        localStorage.setItem('sb_auth_token', 'offline-test-token');
        window.__streams = [];
        window.EventSource = class {
            constructor(url) { this.url = url; window.__streams.push(this); }
            close() { this.closed = true; }
        };
    """)
    page.goto("http://aura.test/index.html", wait_until="load")
    page.wait_for_function("document.getElementById('sys-uptime').textContent === '01:01:01'")
    yield page, state
    context.close()
    assert not errors, "Unexpected frontend runtime errors: " + "\n".join(errors)


def requests(state, path):
    return [request for request in state["requests"] if request[1] == path]


def test_static_copies_are_identical():
    assert (ROOT / "static/js/main.js").read_bytes() == (STATIC / "js/main.js").read_bytes()
    assert (ROOT / "index.html").read_bytes() == (STATIC / "index.html").read_bytes()


def test_dialog_focus_keyboard_trap_restore_and_single_resolution(ui):
    page, _ = ui
    page.locator("#btn-theme").focus()
    page.evaluate("""() => {
        window.__resolved = [];
        _auraDialog({title:'test', message:'enter text', input:'initial', okText:'OK',
            cancelText:'Cancel', resolve:value => window.__resolved.push(value)});
    }""")
    dialog = page.locator('[role="dialog"]')
    assert dialog.get_attribute("aria-modal") == "true"
    field = dialog.locator("input")
    sync_api.expect(field).to_be_focused()
    field.press("Shift+Tab")
    sync_api.expect(dialog.locator('[data-act="ok"]')).to_be_focused()
    page.keyboard.press("Tab")
    sync_api.expect(field).to_be_focused()
    field.fill("accepted")
    page.keyboard.press("Enter")
    # Closing transition may still receive clicks; promise callback runs only once.
    page.evaluate("document.querySelector('[role=dialog] [data-act=ok]').click()")
    assert page.evaluate("window.__resolved") == ["accepted"]
    sync_api.expect(page.locator("#btn-theme")).to_be_focused()
    page.wait_for_function("!document.querySelector('[role=dialog]')")
    page.evaluate("window.__result = 'pending'; void auraConfirm('confirm').then(v => window.__result=v)")
    page.locator('[role=dialog] [data-act=ok]').wait_for()
    page.keyboard.press("Escape")
    page.wait_for_function("window.__result === false")
    page.wait_for_function("!document.querySelector('[role=dialog]')")
    page.evaluate("window.__result = 'pending'; void auraConfirm('confirm').then(v => window.__result=v)")
    sync_api.expect(page.locator('[role=dialog] [data-act=ok]')).to_be_focused()
    page.keyboard.press("Enter")
    page.wait_for_function("window.__result === true")


@pytest.mark.parametrize("status", [400, 409, 500])
def test_api_non_2xx_has_detail_and_no_false_delete_success(ui, status):
    page, state = ui
    state["responses"]["/api/nodes/n1"] = (status, {"detail": f"rejected-{status}"})
    page.evaluate("window.auraConfirm=async()=>true")
    page.evaluate("deleteSingleNode('n1')")
    logs = page.locator("#system-logs-container").inner_text()
    assert f"rejected-{status}" in logs
    assert "节点删除成功" not in logs
    assert not requests(state, "/api/config/apply")


def test_config_apply_checks_body_ok_and_401_logs_out(ui):
    page, state = ui
    state["responses"]["/api/config/apply"] = (200, {"ok": False, "message": "reload rejected"})
    assert page.evaluate("applyConfigSilent()") is False
    assert "reload rejected" in page.locator("#system-logs-container").inner_text()
    state["responses"]["/api/test-unauthorized"] = (401, {"detail": "expired"})
    message = page.evaluate("api('/api/test-unauthorized').catch(e=>e.message)")
    assert "401" in message
    assert page.evaluate("localStorage.getItem('sb_auth_token')") is None
    assert page.evaluate("document.body.classList.contains('locked')")
    assert page.evaluate("window.__streams.every(s=>s.closed)")


def defer_probes(page):
    page.evaluate("""() => {
        const original = window.fetch;
        window.__probeRequests=[];
        window.fetch=(path, options) => {
            if (path === '/api/nodes/ping') {
                window.__probeRequests.push(JSON.parse(options.body));
                return new Promise(resolve => window.__resolveProbe=resolve);
            }
            return original(path, options);
        };
    }""")


def test_single_probe_survives_replacement_deduplicates_and_unlocks(ui):
    page, _ = ui
    defer_probes(page)
    page.evaluate("""() => {
        window.__probeJob=pingSingleNode('n1');
        pingSingleNode('n1'); triggerPingAll();
    }""")
    assert page.evaluate("window.__probeRequests.length") == 1
    assert page.evaluate("window.__probeRequests[0].manual") is True
    page.evaluate("loadNodes()")
    button = page.locator('[data-probe-id="n1"]')
    sync_api.expect(button).to_be_disabled()
    sync_api.expect(page.locator('[data-probe-all]')).to_be_disabled()
    page.evaluate("""() => {
        window.__resolveProbe(new Response(JSON.stringify([]), {status:200,
            headers:{'Content-Type':'application/json'}})); return window.__probeJob;
    }""")
    sync_api.expect(button).to_be_enabled()
    sync_api.expect(page.locator('[data-probe-all]')).to_be_enabled()
    assert "后台测活繁忙" in page.locator("#aura-toast-box").inner_text()


def test_bulk_probe_locks_current_rows_and_unlocks_on_error(ui):
    page, _ = ui
    defer_probes(page)
    page.evaluate("""() => {
        window.__probeJob=triggerPingAll();
        triggerPingAll(); pingSingleNode('n1');
    }""")
    assert page.evaluate("window.__probeRequests.length") == 1
    page.evaluate("loadNodes()")
    assert page.locator("[data-probe-id]:enabled").count() == 0
    page.evaluate("""() => {
        window.__resolveProbe(new Response(JSON.stringify({detail:'busy'}), {status:409,
            headers:{'Content-Type':'application/json'}})); return window.__probeJob;
    }""")
    assert page.locator("[data-probe-id]:disabled").count() == 0
    assert "busy" in page.locator("#system-logs-container").inner_text()


def test_checkbox_does_not_replace_rows_and_disabled_search_applies(ui):
    page, state = ui
    page.locator('.nav-item[data-target="nodes"]').click()
    page.evaluate("""() => {
        window.__row=document.querySelector('#nodes-tbody tr[data-id=n1]');
        window.__port=window.__row.querySelector('.port-input');
        window.__port.value='59999'; window.__port.focus();
        toggleSelectNode('n1');
    }""")
    assert page.evaluate("document.querySelector('#nodes-tbody tr[data-id=n1]') === window.__row")
    assert page.evaluate("document.activeElement === window.__port")
    assert page.evaluate("document.getElementById('chk-all').indeterminate")
    page.evaluate("document.getElementById('chk-all').checked=true; toggleSelectAll(document.getElementById('chk-all'))")
    assert page.evaluate("window.__port.value") == "59999"
    assert not page.evaluate("document.getElementById('chk-all').indeterminate")
    state["nodes"].append(node("n4", "disabled", name="other"))
    page.evaluate("loadNodes()")
    page.locator("#filter-group").select_option("__DISABLED__")
    page.locator("#search-keyword").fill("n3")
    assert page.locator("#nodes-tbody tr[data-id]").count() == 1
    assert page.locator("#nodes-tbody tr[data-id]").get_attribute("data-id") == "n3"


def test_offline_is_enabled_and_reenable_resets_probe_state(ui):
    page, state = ui
    assert "停用" in page.locator('tr[data-id="n1"] td[data-cell=actions]').inner_text()
    page.evaluate("toggleNodeEnable('n1')")
    assert requests(state, "/api/nodes/n1")[-1][2] == {"status": "disabled", "disabledAuto": False}
    page.evaluate("toggleNodeEnable('n1')")
    assert requests(state, "/api/nodes/n1")[-1][2] == {
        "status": "offline", "disabledAuto": False, "consecutiveFails": 0}
    page.evaluate("enableAllDisabledNodes()")
    assert requests(state, "/api/nodes/n3")[-1][2]["status"] == "offline"
    assert not requests(state, "/api/nodes/n2")


def test_bulk_status_reports_partial_failure_instead_of_false_success(ui):
    page, state = ui
    state["responses"]["/api/nodes/n2"] = (409, {"detail": "conflict"})
    page.evaluate("selectedNodeIds=new Set(['n1','n2'])")
    page.evaluate("disableSelectedNodes()")
    logs = page.locator("#system-logs-container").inner_text()
    assert "成功 1 个，失败 1 个" in logs
    assert "conflict" in logs
    assert len(requests(state, "/api/config/apply")) == 1


def test_traffic_clear_cancel_has_one_confirmation_no_success_and_no_apply(ui):
    page, state = ui
    page.evaluate("() => { window.__confirms=0; window.auraConfirm=async()=>{window.__confirms++;return false}; }")
    page.evaluate("clearAllData()")
    assert page.evaluate("window.__confirms") == 1
    assert not requests(state, "/api/traffic/reset")
    assert "已清空" not in page.locator("#system-logs-container").inner_text()
    page.evaluate("window.auraConfirm=async()=>true")
    page.evaluate("clearAllData()")
    page.evaluate("resetNodeTraffic('n1')")
    assert len(requests(state, "/api/traffic/reset")) == 1
    assert not requests(state, "/api/config/apply")


def test_already_applied_operations_do_not_apply_twice(ui):
    page, state = ui
    state["responses"]["/api/nodes/convert-entry"] = (200, {"converted": 2})
    state["responses"]["/api/subs/refresh"] = (200, {"results": [{"ok": True, "id": "s1"}]})
    page.evaluate("handleConvertEntry()")
    page.evaluate("window.__answers=['default','renamed']; window.auraPrompt=async()=>window.__answers.shift()")
    page.evaluate("renameGroup()")
    page.evaluate("refreshSub('s1')")
    assert not requests(state, "/api/config/apply")
    state["responses"]["/api/subs/refresh"] = (200, {"results": [{"ok": False, "error": "fetch rejected"}]})
    page.evaluate("refreshSub('s1')")
    assert "fetch rejected" in page.locator("#aura-toast-box").inner_text()


def test_failed_clipboard_has_no_success_and_log_dom_is_bounded(ui):
    page, _ = ui
    page.evaluate("""() => {
        Object.defineProperty(navigator,'clipboard',{configurable:true,
            value:{writeText:async()=>{throw Error('denied')}}});
        document.execCommand=()=>false;
    }""")
    assert page.evaluate("copyToClipboard('test')") is False
    logs = page.locator("#system-logs-container").inner_text()
    assert "复制失败" in logs
    assert "已复制到剪贴板" not in logs
    page.evaluate("for(let i=0;i<500;i++) addLog('INFO','row-'+i)")
    assert page.locator("#system-logs-container > div").count() == 200
    assert "row-499" in page.locator("#system-logs-container").inner_text()


def test_dashboard_uses_sse_and_backend_uptime_not_demo_values(ui):
    page, state = ui
    state["nodes"][0].update(upTraffic=1048576, downTraffic=2097152)
    page.evaluate("loadNodes()")
    page.evaluate("""window.__streams.at(-1).onmessage({data:JSON.stringify({type:'traffic',
        upRate:1048576, downRate:2097152, activeConnections:7, nodes:[]})})""")
    assert page.locator("#dash-stat-up-rate").inner_text() == "1.00 MB/s"
    assert page.locator("#dash-stat-down-rate").inner_text() == "2.00 MB/s"
    assert page.locator("#dash-stat-active-connections").inner_text() == "7"
    assert page.locator("#card-traffic-total").inner_text() == "3.00 MB"
    page.locator('.nav-item[data-target="nodes"]').click()
    page.locator('.nav-item[data-target="dashboard"]').click()
    assert page.locator("#dash-stat-down-rate").inner_text() == "2.00 MB/s"
    assert page.locator("#sys-uptime").inner_text() == "01:01:01"
    state["responses"]["/api/config/status"] = (200, {"running": False, "uptime": None})
    page.evaluate("loadEngineStatus()")
    assert page.locator("#sys-uptime").inner_text() == "--:--:--"
    assert page.locator("[data-val]").count() == 0
    page.evaluate("""window.__streams.at(-1).onmessage({data:JSON.stringify({type:'traffic',
        upRate:0, downRate:0, nodes:[]})})""")
    assert page.locator("#dash-stat-active-connections").inner_text() == "--"
    assert page.locator("#dash-stat-up-rate").inner_text() == "0.00 MB/s"
    assert not page.evaluate("bgLogs.some(log=>log.includes('[SYS] PROBE NODE_'))")


def test_refresh_does_not_replace_focused_relay_or_settings_drafts(ui):
    page, state = ui
    page.locator('.nav-item[data-target="relay"]').click()
    field = page.locator("#relay-card-r1 input[type=text]").first
    field.focus()
    page.evaluate("window.__relayField=document.activeElement")
    page.evaluate("loadSettings()")
    assert page.evaluate("document.activeElement === window.__relayField && window.__relayField.isConnected")
    field.fill("draft.example")
    page.locator("#btn-theme").focus()
    page.evaluate("loadSettings()")
    assert field.input_value() == "draft.example"
    assert page.evaluate("window.__relayField.isConnected")
    page.locator('.nav-item[data-target="settings"]').click()
    page.locator("#setting-listen-ip").fill("127.0.0.1")
    page.locator("#btn-theme").focus()
    state["settings"]["listenIp"] = "0.0.0.0"
    page.evaluate("loadSettings()")
    assert page.locator("#setting-listen-ip").input_value() == "127.0.0.1"
    page.evaluate("saveSystemSettings()")
    assert state["settings"]["listenIp"] == "127.0.0.1"
    assert not page.evaluate("settingsDirty")


def test_traffic_rows_are_incremental_and_last_row_has_width_immediately(ui):
    page, state = ui
    state["nodes"] = [node(f"n{i}", upTraffic=1024, downTraffic=1024) for i in range(176)]
    page.evaluate("loadNodes()")
    assert page.locator(".traffic-bar-row").count() == 176
    assert page.locator(".traffic-bar-row .tb-fill-up").last.evaluate("el=>el.style.width") == "50%"
    page.evaluate("window.__bar=document.querySelector('.traffic-bar-row')")
    page.evaluate("nodeState[0].upTraffic=3072; renderTrafficChart()")
    assert page.evaluate("window.__bar === document.querySelector('.traffic-bar-row')")
    assert page.locator(".traffic-bar-row .tb-fill-up").first.evaluate("el=>el.style.width") == "75%"
    page.evaluate("nodeState=[]; renderTrafficChart()")
    assert "暂无节点流量数据" in page.locator("#traffic-chart-container").inner_text()


def test_inline_event_arguments_cannot_inject_javascript(ui):
    page, state = ui
    hostile = "n');window.__injected=true;//"
    state["nodes"] = [node(hostile)]
    page.evaluate("loadNodes()")
    page.locator('.nav-item[data-target="nodes"]').click()
    page.locator("#nodes-tbody .chk-node").check()
    assert page.evaluate("window.__injected === undefined")
    assert page.evaluate("id=>selectedNodeIds.has(id)", hostile)
    state["settings"]["relayDomains"][0]["id"] = hostile
    state["nodes"][0]["group"] = "g');window.__injected=true;//"
    page.evaluate("loadNodes()")
    page.evaluate("loadSettings()")
    page.locator('.nav-item[data-target="relay"]').click()
    page.locator("#relay-domain-list input[type=text]").first.fill("safe.example")
    page.locator("#relay-domain-list input[type=checkbox]").last.check()
    assert page.evaluate("window.__injected === undefined")
    assert page.evaluate("id=>relayDirty.has(id)", hostile)


def test_first_password_gate_does_not_start_data_or_sse(ui):
    page, state = ui
    state["passwordChangeRequired"] = True
    page.evaluate("doLogout()")
    state["requests"].clear()
    page.evaluate("authToken='offline-test-token'; checkAuth()")
    assert not requests(state, "/api/nodes")
    assert not requests(state, "/api/settings")
    assert not requests(state, "/api/config/status")
    assert page.locator("#pwd-modal").evaluate("el=>el.classList.contains('active')")
    assert page.evaluate("window.__streams.every(s=>s.closed)")


def test_action_button_font_size_and_disabled_nodes_grouped_display(ui):
    page, state = ui
    page.locator('.nav-item[data-target="nodes"]').click()
    # 1. 验证操作列按钮字体大小已放大（从8px提高至11px）
    font_size = page.locator('#nodes-tbody .btn-action').first.evaluate(
        "el => window.getComputedStyle(el).fontSize"
    )
    assert font_size == "11px"

    # 2. 模拟多个不同分组的停用节点
    state["nodes"].append(node("n4", "disabled", name="hk-dis", group="香港"))
    state["nodes"].append(node("n5", "disabled", name="jp-dis", group="日本"))
    page.evaluate("loadNodes()")

    # 3. 验证下拉菜单中停用节点项包含全部及各子分组
    options = page.locator("#filter-group option").all_inner_texts()
    option_values = page.locator("#filter-group option").evaluate_all(
        "opts => opts.map(o => o.value)"
    )
    assert "__DISABLED__" in option_values
    assert "__DISABLED__:香港" in option_values
    assert "__DISABLED__:日本" in option_values

    # 4. 选择特定分组的停用节点，验证只展示该分组
    page.locator("#filter-group").select_option("__DISABLED__:香港")
    assert page.locator("#nodes-tbody tr[data-id]").count() == 1
    assert page.locator("#nodes-tbody tr[data-id]").get_attribute("data-id") == "n4"

    # 5. 选择全部停用节点，验证按分组展示分组隔断标题
    page.locator("#filter-group").select_option("__DISABLED__")
    assert page.locator("#nodes-tbody tr[data-id]").count() == 3
    assert page.locator("#nodes-tbody tr.group-header-row").count() >= 2

@pytest.mark.parametrize("entry_proto", ["mixed", "ss"])
def test_all_export_paths_use_saved_domain_and_preserve_original(ui, entry_proto):
    page, state = ui
    original = "socks5://original:pass@upstream.test:40136#original"
    state["nodes"] = [node("n1", entryProto=entry_proto, ssPass="secret", rawConfig={"uri": original}),
                      node("n2", port=52002, entryProto=entry_proto, group="other")]
    state["settings"]["exportDomain"] = "nodes.example.com"
    page.evaluate("loadNodes()")
    page.evaluate("loadSettings()")
    page.locator('.nav-item[data-target="settings"]').click()
    assert page.locator("#setting-export-domain").input_value() == "nodes.example.com"
    page.evaluate("copyToClipboard = async () => true")
    page.evaluate("exportSingleNode('n1')")
    text = page.locator("#export-text-area").input_value()
    assert "@nodes.example.com:52001" in text
    assert ":52002" not in text
    assert text.count("@nodes.example.com:") == (1 if entry_proto == "ss" else 2)
    page.evaluate("selectedNodeIds = new Set(['n2']); exportSelectedNodes()")
    text = page.locator("#export-text-area").input_value()
    assert "@nodes.example.com:52002" in text
    assert ":52001" not in text
    page.evaluate("generateExportText()")
    text = page.locator("#export-text-area").input_value()
    assert "@nodes.example.com:52001" in text and "@nodes.example.com:52002" in text
    page.locator("#export-type-select").select_option("original")
    page.evaluate("generateExportText()")
    text = page.locator("#export-text-area").input_value()
    assert original in text
    assert "nodes.example.com" not in text
    page.evaluate("exportSingleNode('n1')")
    assert original in page.locator("#export-text-area").input_value()
    page.evaluate("selectedNodeIds = new Set(['n1']); exportSelectedNodes()")
    assert original in page.locator("#export-text-area").input_value()


def test_export_domain_drafts_failed_save_and_clear(ui):
    page, state = ui
    state["settings"]["exportDomain"] = "saved.example.com"
    page.evaluate("loadSettings()")
    page.locator('.nav-item[data-target="settings"]').click()
    field = page.locator("#setting-export-domain")
    field.fill("draft.example.com")
    page.evaluate("loadSettings()")
    assert field.input_value() == "draft.example.com"
    assert page.evaluate("getExportHost()") == "saved.example.com"
    state["responses"]["/api/settings"] = (422, {"detail": "invalid domain"})
    page.evaluate("saveSystemSettings()")
    assert page.evaluate("settingsDirty")
    assert page.evaluate("getExportHost()") == "saved.example.com"
    state["responses"].pop("/api/settings")
    page.evaluate("saveSystemSettings()")
    assert state["settings"]["exportDomain"] == "draft.example.com"
    assert page.evaluate("getExportHost()") == "draft.example.com"
    assert not page.evaluate("settingsDirty")
    field.fill("")
    page.evaluate("saveSystemSettings()")
    assert state["settings"]["exportDomain"] == ""
    assert page.evaluate("getExportHost()") == "aura.test"
    page.evaluate("generateExportText()")
    assert "@aura.test:52001" in page.locator("#export-text-area").input_value()


def test_export_domain_normalized_save_skips_reload_message(ui):
    page, state = ui
    page.locator('.nav-item[data-target="settings"]').click()
    field = page.locator("#setting-export-domain")
    field.fill(" NODES.Example.COM. ")
    state["responses"]["/api/settings"] = (200, {
        "ok": True, "exportDomain": "nodes.example.com", "configApplied": True, "configReloaded": False})
    page.evaluate("saveSystemSettings()")
    assert page.evaluate("getExportHost()") == "nodes.example.com"
    assert field.input_value() == "nodes.example.com"
    assert page.evaluate("bgLogs.some(log=>log.includes('无需重载内核'))")
    assert not requests(state, "/api/config/apply")


def test_export_uri_credentials_ipv6_and_ss_utf8(ui):
    page, _ = ui
    data = {"port": 52001, "authUser": "u@:# /", "authPass": "p@:/?# %", "name": "sample"}
    lines = page.evaluate("n=>exportLinkLines(n, '2001:db8::1', 'both')", data)
    assert lines == [
        "socks5://u%40%3A%23%20%2F:p%40%3A%2F%3F%23%20%25@[2001:db8::1]:52001",
        "http://u%40%3A%23%20%2F:p%40%3A%2F%3F%23%20%25@[2001:db8::1]:52001",
    ]
    assert page.evaluate("n=>exportLinkLines(n, '[2001:db8::1]', 'socks5')", data) == lines[:1]
    data.update(entryProto="ss", ssPass="caf\u00e9\u5bc6\u7801")
    result = page.evaluate("n=>exportLinkLines(n, 'nodes.example.com', 'both')[0]", data)
    import base64
    encoded = result.split("ss://", 1)[1].split("@", 1)[0]
    assert base64.b64decode(encoded + "=" * (-len(encoded) % 4)).decode() == "aes-256-gcm:" + data["ssPass"]
    assert "@nodes.example.com:52001" in result


def test_stale_settings_fetch_does_not_replace_saved_domain(ui):
    page, _ = ui
    page.locator('.nav-item[data-target="settings"]').click()
    page.evaluate("""() => {
        const originalApi = api;
        window.__releaseSettings = null;
        api = async (path, options = {}) => {
            if (path === '/api/settings' && !options.method) {
                return new Promise(resolve => { window.__releaseSettings = () => resolve({
                    json: async () => ({exportDomain:'old.example.com'})
                }); });
            }
            return originalApi(path, options);
        };
        window.__pendingSettings = loadSettings();
    }""")
    page.locator("#setting-export-domain").fill("new.example.com")
    page.evaluate("saveSystemSettings()")
    page.evaluate("window.__releaseSettings(); window.__pendingSettings")
    assert page.evaluate("getExportHost()") == "new.example.com"
    assert page.locator("#setting-export-domain").input_value() == "new.example.com"
