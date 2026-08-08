#!/usr/bin/env python3
"""Aura 面板命令行配置界面。

安装后终端输入 `aura` 进入交互式配置：
  1) 查看面板信息（端口/路径/账号/状态）
  2) 修改面板端口
  3) 修改网页登录路径
  4) 修改登录账号
  5) 修改登录密码
  6) 更新面板（git pull + 重启服务）
  7) 服务状态 / 重启 / 停止

全部配置持久化到 data/panel.conf 与 db settings 表，重启后生效。
"""
import os
import shutil
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
sys.path.insert(0, BASE_DIR)

import db          # noqa: E402
import panel_config  # noqa: E402


# ---------- 输出工具 ----------
def c(text, code="0"):
    return f"\033[{code}m{text}\033[0m"


def info(s):
    print(c("[*] ", "36") + s)


def ok(s):
    print(c("[✔] ", "32") + s)


def warn(s):
    print(c("[!] ", "33") + s)


def fail(s):
    print(c("[✘] ", "31") + s)


def title(s):
    print("\n" + c("═" * 50, "34"))
    print(c("  " + s, "34;1"))
    print(c("═" * 50, "34"))


# ---------- 服务控制 ----------
def _service_unit() -> str:
    """systemd 服务名：aura（若已安装）。"""
    if shutil.which("systemctl"):
        r = subprocess.run(["systemctl", "list-unit-files", "aura.service"],
                           capture_output=True, text=True)
        if "aura.service" in r.stdout:
            return "aura"
    return ""


def service_running() -> bool:
    """通过 Web API 或进程判断面板是否在运行。"""
    unit = _service_unit()
    if unit:
        r = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
        return r.stdout.strip() == "active"
    # 非 systemd：探测端口
    port = panel_config.get("port") or 19001
    try:
        import socket
        s = socket.socket()
        s.settimeout(0.5)
        s.connect(("127.0.0.1", int(port)))
        s.close()
        return True
    except OSError:
        return False


def restart_service():
    """重启面板：优先 systemd，否则前台进程由调用方处理。"""
    unit = _service_unit()
    if unit:
        subprocess.run(["systemctl", "restart", unit], check=False)
        ok(f"已重启服务（{unit}.service）")
        return True
    return False


def stop_service():
    unit = _service_unit()
    if unit:
        subprocess.run(["systemctl", "stop", unit], check=False)
        ok(f"已停止服务（{unit}.service）")
        return True
    return False


# ---------- 面板信息 ----------
def show_panel_info():
    cfg = panel_config.show()
    port = cfg.get("port", 19001)
    path = cfg.get("panel_path", "/admin") or "/admin"
    username = cfg.get("username", "admin") or "admin"
    running = service_running()

    print("\n" + c("─ Aura 面板信息 ─", "36;1"))
    print(f"  网页访问地址 : http://<服务器IP>:{port}{path}")
    print(f"  登录账号     : {c(username, '33')}")
    print(f"  登录密码     : {c('(已设置，不可显示)', '33')}")
    print(f"  面板状态     : " + (c("运行中", "32") if running else c("未运行", "31")))
    if running:
        print(f"  登录地址     : http://<服务器IP>:{port}{path}")
    print(c("─" * 30, "36"))


# ---------- 交互输入 ----------
def prompt(p, default="", validator=None):
    """带默认值与校验的输入。返回字符串或 None（取消）。"""
    d = f" [{c(default, '33')}]" if default else ""
    while True:
        try:
            val = input(f"{p}{d} > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if not val:
            val = default
        if not val:
            print("  输入不能为空，请重试")
            continue
        if validator and not validator(val):
            print("  输入不合法，请重试")
            continue
        return val


def _valid_port(s):
    return s.isdigit() and 1 <= int(s) <= 65535


def _valid_path(s):
    return s.startswith("/") and " " not in s and "?" not in s and "#" not in s


def _valid_username(s):
    return 1 <= len(s) <= 32 and not any(ch in s for ch in " /\t\n")


def _valid_password(s):
    return len(s) >= 6


# ---------- 密码（存 db settings 表 auth） ----------
def _change_password():
    title("修改登录密码")
    import auth
    # 旧密码为空时（首次）允许直接设置
    current = (db.get_setting("auth", {}) or {}).get("password_hash")
    if current:
        old = prompt("输入旧密码", "")
        if old is None:
            return
        if not auth.verify_password(old, current):
            fail("旧密码错误")
            return
    else:
        info("尚未设置密码，将直接创建")
    p1 = prompt("输入新密码（至少 6 位）", validator=_valid_password)
    if p1 is None:
        return
    p2 = prompt("再次输入新密码", "")
    if p2 is None:
        return
    if p1 != p2:
        fail("两次输入不一致")
        return
    # 直接写哈希（不经过 change_password 的 token 逻辑，CLI 无会话）
    from auth import hash_password
    db.set_setting("auth", {
        "password_hash": hash_password(p1),
        "password_change_required": False,
        "changed_at": int(time.time() * 1000),
    })
    ok("密码已更新")
    if service_running():
        info("如需立即生效，请重启服务（菜单 7）")


# ---------- 改用户名（同时改密码逻辑） ----------
def _change_username():
    title("修改登录账号")
    cur = panel_config.get("username") or "admin"
    print(f"  当前账号: {c(cur, '33')}")
    new = prompt("输入新账号（3-32 位，不含空格/斜杠）", validator=_valid_username)
    if new is None:
        return
    if new == cur:
        warn("账号未变化")
        return
    panel_config.set_many({"username": new})
    ok(f"账号已改为 {new}")
    if service_running():
        info("如需立即生效，请重启服务（菜单 7）")


# ---------- 改端口 ----------
def _change_port():
    title("修改面板端口")
    cur = panel_config.get("port") or 19001
    print(f"  当前端口: {c(cur, '33')}")
    new = prompt("输入新端口（1-65535）", str(cur), validator=_valid_port)
    if new is None:
        return
    if int(new) == int(cur):
        warn("端口未变化")
        return
    # 检测占用
    try:
        import socket
        s = socket.socket()
        s.settimeout(0.5)
        s.bind(("0.0.0.0", int(new)))
        s.close()
    except OSError:
        fail(f"端口 {new} 已被占用")
        return
    panel_config.set_many({"port": int(new)})
    ok(f"面板端口已改为 {new}")
    if service_running():
        restart = input("  立即重启生效？[Y/n] > ").strip().lower()
        if restart in ("", "y", "yes"):
            if not restart_service():
                warn("非 systemd 环境，请手动重启面板进程")


# ---------- 改路径 ----------
def _change_path():
    title("修改网页登录路径")
    cur = panel_config.get("panel_path") or "/admin"
    print(f"  当前路径: {c(cur, '33')}")
    new = prompt("输入新路径（以 / 开头，如 /admin）", cur, validator=_valid_path)
    if new is None:
        return
    if new == cur:
        warn("路径未变化")
        return
    panel_config.set_many({"panel_path": new})
    ok(f"网页路径已改为 {new}")
    if service_running():
        restart = input("  立即重启生效？[Y/n] > ").strip().lower()
        if restart in ("", "y", "yes"):
            if not restart_service():
                warn("非 systemd 环境，请手动重启面板进程")


# ---------- 更新面板 ----------
def _update_panel():
    title("更新面板")
    if not os.path.isdir(os.path.join(ROOT_DIR, ".git")):
        warn("不是 git 仓库，跳过 git pull（可手动更新代码）")
        return
    running = service_running()
    info("git pull 拉取最新代码...")
    r = subprocess.run(["git", "-C", ROOT_DIR, "pull"], capture_output=True, text=True)
    print(r.stdout.strip())
    if r.returncode != 0:
        fail("git pull 失败：" + r.stderr.strip())
        return
    ok("代码已更新")
    if running and restart_service():
        ok("服务已重启")
    else:
        info("面板未运行或非 systemd，请手动重启")


# ---------- 服务菜单 ----------
def _service_menu():
    title("服务状态 / 重启 / 停止")
    unit = _service_unit()
    running = service_running()
    print(f"  运行状态: " + (c("运行中", "32") if running else c("未运行", "31")))
    if unit:
        print(f"  systemd : {unit}.service")
    else:
        warn("  未检测到 systemd 服务（非 systemd 环境或未用安装脚本部署）")
    print()
    print("  [1] 重启面板")
    print("  [2] 停止面板")
    print("  [3] 返回")
    choice = input("\n  请选择 > ").strip()
    if choice == "1":
        if restart_service():
            ok("重启完成")
        else:
            warn("非 systemd 环境，无法自动重启；请手动重启面板进程")
    elif choice == "2":
        if not stop_service():
            warn("非 systemd 环境，无法自动停止")
    else:
        return


# ---------- 主菜单 ----------
MENU = """
  ┌────────────────────────────────────────────┐
  │  Aura · SingBox 中转节点管理面板             │
  │  交互式配置                                 │
  └────────────────────────────────────────────┘

  [1] 查看面板信息
  [2] 修改面板端口
  [3] 修改网页登录路径
  [4] 修改登录账号
  [5] 修改登录密码
  [6] 更新面板（git pull + 重启）
  [7] 服务状态 / 重启 / 停止
  [0] 退出
"""


def main():
    while True:
        print(MENU)
        choice = input("  请选择 > ").strip()
        if choice == "1":
            show_panel_info()
        elif choice == "2":
            _change_port()
        elif choice == "3":
            _change_path()
        elif choice == "4":
            _change_username()
        elif choice == "5":
            _change_password()
        elif choice == "6":
            _update_panel()
        elif choice == "7":
            _service_menu()
        elif choice in ("0", "q", "quit", "exit"):
            print(c("再见！", "32"))
            break
        else:
            warn("无效选择")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + c("再见！", "32"))
