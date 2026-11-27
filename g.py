#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""guard.py - Ubuntu 隔离虚拟机的网络与隐私守护脚本（仅用 Python 3 标准库）

用法:
    python3 guard.py --check          # 只做 5 项硬性自检：全过 -> 0，任一失败 -> 1
    python3 guard.py                  # 自检通过后进入看门狗循环（默认 10 秒一轮）
    python3 guard.py --interval 5     # 自定义轮询间隔（秒，默认 10）
    python3 guard.py --keep-running   # 触发强杀后继续监控（默认强杀后退出 2）
"""

import argparse
import glob
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

EXPECTED_IP = "154.64.240.214"
EXPECTED_COUNTRY = "US"
EXPECTED_TZ = "America/Los_Angeles"
IFACE = "singbox_tun"
IPINFO_URL = "https://ipinfo.io/json"
IPIFY_URL = "https://api.ipify.org"
HTTP_TIMEOUT = 8.0
WATCHDOG_IP_TIMEOUT = 5.0
CMD_TIMEOUT = 10.0
FAIL_THRESHOLD = 2
USER_AGENT = "us-guard/1.0 (+python-urllib)"

_NO_COLOR = os.environ.get("NO_COLOR") is not None
_FORCE_COLOR = os.environ.get("FORCE_COLOR") is not None


def _supports(stream):
    if _NO_COLOR:
        return False
    if _FORCE_COLOR:
        return True
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def _paint(code, text, stream=None):
    stream = stream or sys.stdout
    if _supports(stream):
        return "\033[%sm%s\033[0m" % (code, text)
    return text


def red(text, stream=None):
    return _paint("1;31", text, stream)


def green(text, stream=None):
    return _paint("1;32", text, stream)


def yellow(text, stream=None):
    return _paint("1;33", text, stream)


def cyan(text, stream=None):
    return _paint("1;36", text, stream)


def bold(text, stream=None):
    return _paint("1", text, stream)


def log(msg):
    print("%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg), flush=True)


def log_err(msg):
    sys.stderr.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    sys.stderr.flush()


def run(cmd, timeout=CMD_TIMEOUT):
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        out = proc.stdout.decode("utf-8", "replace").strip()
        err = proc.stderr.decode("utf-8", "replace").strip()
        return proc.returncode, out, err
    except FileNotFoundError:
        return 127, "", "command not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %.0fs: %s" % (timeout, " ".join(cmd))
    except OSError as exc:
        return 126, "", "cannot exec %s: %s" % (cmd[0], exc)


def http_get(url, timeout):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as resp:
        raw = resp.read(65536)
        return getattr(resp, "status", 200), raw.decode("utf-8", "replace")


def check_interface():
    rc, out, err = run(["ip", "-br", "a"])
    if rc != 0:
        return False, "`ip -br a` 执行失败 (rc=%d): %s" % (rc, err or out)
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0].split("@")[0]
        if name != IFACE:
            continue
        state = parts[1].upper() if len(parts) > 1 else "UNKNOWN"
        if state == "DOWN":
            return False, "%s 存在但状态为 DOWN，隧道没起来" % IFACE
        if state == "LOWERLAYERDOWN":
            return False, "%s 存在但底层链路 DOWN" % IFACE
        return True, "%s 在线 (state=%s)" % (IFACE, state)
    return False, "`ip -br a` 中找不到 %s 网卡（sing-box 未启动或未接管 TUN）" % IFACE


def _ufw_active_in(text):
    low = (text or "").lower()
    if "status: active" in low:
        return True
    if "status: inactive" in low:
        return False
    return None


def check_ufw():
    rc, out, err = run(["ufw", "status"])
    text = "%s\n%s" % (out, err)
    verdict = _ufw_active_in(text)
    if rc == 0 and verdict is True:
        return True, "ufw status = active（直接读取）"
    if rc == 0 and verdict is False:
        return False, "ufw status = inactive（防火墙没开）"
    rc_s, out_s, err_s = run(["sudo", "-n", "ufw", "status"])
    verdict_s = _ufw_active_in("%s\n%s" % (out_s, err_s))
    if rc_s == 0 and verdict_s is True:
        return True, "ufw status = active（sudo -n）"
    conf = "/etc/ufw/ufw.conf"
    enabled = None
    try:
        with open(conf, "r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("ENABLED="):
                    enabled = line.split("=", 1)[1].strip().strip('"').strip("'").lower()
    except OSError:
        enabled = None
    if enabled == "no":
        return False, "ufw.conf 中 ENABLED=no（防火墙没开）"
    if enabled == "yes":
        rc2, _, _ = run(["systemctl", "is-active", "--quiet", "ufw"])
        if rc2 == 0:
            return True, "ufw.conf ENABLED=yes + systemctl is-active ufw（非特权探测）"
        return False, "ufw.conf 写着 ENABLED=yes，但 ufw 服务未运行"
    hint = err or out or "无输出"
    return False, "无法确认 ufw 状态（无 root，且 %s 不可读）: %s" % (conf, hint)


def _read_timezone():
    rc, out, _ = run(["timedatectl", "show", "-p", "Timezone", "--value"])
    if rc == 0 and out.strip():
        return out.strip(), "timedatectl"
    try:
        with open("/etc/timezone", "r", errors="replace") as fh:
            tz = fh.readline().strip()
        if tz:
            return tz, "/etc/timezone"
    except OSError:
        pass
    try:
        link = os.path.realpath("/etc/localtime")
        marker = "/zoneinfo/"
        if marker in link:
            return link.split(marker, 1)[1], "/etc/localtime"
    except OSError:
        pass
    return None, "timedatectl / /etc/timezone / /etc/localtime 都取不到"


def check_timezone():
    tz, source = _read_timezone()
    if tz == EXPECTED_TZ:
        return True, "时区 = %s（%s）" % (tz, source)
    if tz is None:
        return False, "无法读取系统时区：%s" % source
    return False, "时区 = %s（%s），要求 %s" % (tz, source, EXPECTED_TZ)


PREF_NAME = "media.peerconnection.enabled"
_PREF_RE = re.compile(
    r"""user_pref\(\s*["']%s["']\s*,\s*(true|false)\s*\)""" % re.escape(PREF_NAME),
    re.IGNORECASE,
)
_LOOSE_RE = re.compile(r"(true|false)", re.IGNORECASE)


def _pref_in_file(path):
    value = None
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                    continue
                if PREF_NAME not in stripped:
                    continue
                match = _PREF_RE.search(stripped)
                if match:
                    value = match.group(1).lower()
                    continue
                loose = _LOOSE_RE.search(stripped)
                if loose:
                    value = loose.group(1).lower()
    except OSError:
        return None
    return value


def _firefox_dirs():
    patterns = [
        os.path.expanduser("~/snap/firefox/common/.mozilla/firefox/*.default*"),
        os.path.expanduser("~/.mozilla/firefox/*.default*"),
    ]
    dirs = []
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            if os.path.isdir(path) and path not in dirs:
                dirs.append(path)
    return dirs


def check_firefox_webrtc():
    dirs = _firefox_dirs()
    if not dirs:
        return False, "找不到 Firefox 配置目录"
    userjs = [p for p in (os.path.join(d, "user.js") for d in dirs) if os.path.isfile(p)]
    found_true = []
    for path in userjs:
        value = _pref_in_file(path)
        if value == "false":
            return True, "%s = false（%s）" % (PREF_NAME, path)
        if value == "true":
            found_true.append(path)
    if found_true:
        return False, "%s = true，WebRTC 会泄漏内网/公网地址（%s）" % (
            PREF_NAME,
            ", ".join(found_true),
        )
    prefsjs = [p for p in (os.path.join(d, "prefs.js") for d in dirs) if os.path.isfile(p)]
    for path in prefsjs:
        value = _pref_in_file(path)
        if value == "false":
            return True, "%s = false（来自 prefs.js）" % PREF_NAME
        if value == "true":
            return False, "%s = true（来自 prefs.js），WebRTC 会泄漏地址" % PREF_NAME
    return False, "Firefox 配置里没有 %s 的明确取值" % PREF_NAME


def check_egress_ipinfo():
    try:
        status, body = http_get(IPINFO_URL, HTTP_TIMEOUT)
    except urllib.error.HTTPError as exc:
        return False, "%s 返回 HTTP %s" % (IPINFO_URL, exc.code)
    except urllib.error.URLError as exc:
        return False, "%s 请求失败: %s" % (IPINFO_URL, exc.reason)
    except Exception as exc:
        return False, "%s 请求异常: %s: %s" % (IPINFO_URL, type(exc).__name__, exc)
    if status != 200:
        return False, "%s 返回 HTTP %s" % (IPINFO_URL, status)
    try:
        data = json.loads(body)
    except ValueError:
        return False, "%s 返回的不是合法 JSON" % IPINFO_URL
    ip = str(data.get("ip", "")).strip()
    country = str(data.get("country", "")).strip().upper()
    try:
        ipaddress.ip_address(ip)
        valid_ip = True
    except ValueError:
        valid_ip = False
    if ip != EXPECTED_IP:
        return False, "出口 IP = %s，要求严格等于 %s（country=%s）" % (
            ip or "<空>",
            EXPECTED_IP,
            country or "?",
        )
    if not valid_ip:
        return False, "出口 IP 字段不是合法 IP: %r" % ip
    if country != EXPECTED_COUNTRY:
        return False, "出口 country = %s，要求 %s" % (country or "<空>", EXPECTED_COUNTRY)
    return True, "出口 IP = %s，country = %s" % (ip, country)


CHECKS = [
    ("1/5 singbox_tun 网卡", check_interface),
    ("2/5 ufw 防火墙", check_ufw),
    ("3/5 系统时区", check_timezone),
    ("4/5 Firefox WebRTC", check_firefox_webrtc),
    ("5/5 出口 IP / 国家", check_egress_ipinfo),
]


def run_all_checks():
    print(bold("== us-guard 启动前硬性自检 =="), flush=True)
    failures = 0
    for label, fn in CHECKS:
        try:
            ok, detail = fn()
        except Exception as exc:
            ok, detail = False, "检查内部异常: %s: %s" % (type(exc).__name__, exc)
        if ok:
            print("  %s %s  %s" % (green("[PASS]"), label, detail), flush=True)
        else:
            failures += 1
            print("  %s %s  %s" % (red("[FAIL]"), red(label), red(detail)), flush=True)
    if failures:
        msg = "自检未通过：%d/5 项失败，已阻断后续启动。" % failures
        log_err(red("!! " + msg))
        return False
    print(green("== 自检全部通过 (%d/5) ==" % len(CHECKS)), flush=True)
    return True


def check_egress_ipify():
    try:
        status, body = http_get(IPIFY_URL, WATCHDOG_IP_TIMEOUT)
    except urllib.error.URLError as exc:
        return False, "%s 请求失败: %s" % (IPIFY_URL, exc.reason)
    except Exception as exc:
        return False, "%s 请求异常: %s: %s" % (IPIFY_URL, type(exc).__name__, exc)
    if status != 200:
        return False, "%s 返回 HTTP %s" % (IPIFY_URL, status)
    ip = body.strip()
    if ip != EXPECTED_IP:
        return False, "IP = %r，要求严格等于 %s" % (ip[:64], EXPECTED_IP)
    return True, "IP = %s" % ip


def _kill_processes():
    results = []
    for pattern in ("firefox", "claude"):
        rc, _, err = run(["pkill", "-9", "-f", pattern], timeout=10.0)
        if rc == 0:
            results.append("%s: 已强杀" % pattern)
        elif rc == 1:
            results.append("%s: 无匹配进程" % pattern)
        elif rc == 127:
            results.append("%s: pkill 不可用" % pattern)
        else:
            results.append("%s: pkill 失败(rc=%d) %s" % (pattern, rc, err))
    return results


def _alert(message):
    log_err(red(message))
    if shutil.which("logger"):
        run(["logger", "-t", "us-guard", "-p", "user.crit", message], timeout=5.0)
    if shutil.which("notify-send"):
        run(["notify-send", "-u", "critical", "us-guard", message], timeout=5.0)


def trip(reason):
    banner = "!! 连续 %d 次检测失败，执行紧急止损: %s" % (FAIL_THRESHOLD, reason)
    print()
    print(red("=" * 72), flush=True)
    _alert(banner)
    for line in _kill_processes():
        _alert("   " + line)
    print(red("=" * 72), flush=True)


def watchdog(interval):
    fails = 0
    tripped = False
    log(cyan("== 看门狗启动：每 %.0f 秒检测 %s 在线 + %s ==" % (interval, IFACE, EXPECTED_IP)))
    while True:
        started = time.monotonic()
        iface_ok, iface_msg = check_interface()
        ip_ok, ip_msg = check_egress_ipify()
        if iface_ok and ip_ok:
            if fails or tripped:
                log(green("恢复正常：%s；%s" % (iface_msg, ip_msg)))
            else:
                log("[ok] %s；%s" % (iface_msg, ip_msg))
            fails = 0
            tripped = False
        else:
            fails += 1
            log_err(red("[fail %d/%d] %s；%s" % (
                fails, FAIL_THRESHOLD,
                iface_msg if not iface_ok else "网卡正常",
                ip_msg if not ip_ok else "IP 正常",
            )))
            if fails >= FAIL_THRESHOLD and not tripped:
                trip("%s / %s" % (iface_msg, ip_msg))
                tripped = True
                if not KEEP_RUNNING:
                    log_err(red("看门狗已退出（退出码 2）。排查隧道后再启动。"))
                    return 2
        elapsed = time.monotonic() - started
        time.sleep(max(0.0, interval - elapsed))


KEEP_RUNNING = False


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="guard.py",
        description="Ubuntu 隔离虚拟机网络与隐私守护：5 项硬性自检 + 断网看门狗。",
    )
    parser.add_argument("--check", action="store_true", help="只做 5 项自检，不进入看门狗")
    parser.add_argument("--interval", type=float, default=10.0, metavar="SEC", help="看门狗轮询间隔秒数（默认 10）")
    parser.add_argument("--keep-running", action="store_true", help="止损后继续监控（默认强杀后退出，退出码 2）")
    args = parser.parse_args(argv)
    if args.interval <= 0:
        parser.error("--interval 必须大于 0")
    return args


def main(argv=None):
    global KEEP_RUNNING
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if not sys.platform.startswith("linux"):
        log_err(red("!! guard.py 只支持 Ubuntu/Linux，当前平台: %s" % sys.platform))
        return 1
    if os.geteuid() == 0:
        log(yellow("提示：以 root 运行，pkill 会作用于所有用户的 firefox/claude 进程。"))
    if not run_all_checks():
        return 1
    if args.check:
        return 0
    KEEP_RUNNING = args.keep_running
    try:
        return watchdog(args.interval)
    except KeyboardInterrupt:
        log(yellow("收到 Ctrl-C，看门狗已停止。"))
        return 130


if __name__ == "__main__":
    sys.exit(main())
