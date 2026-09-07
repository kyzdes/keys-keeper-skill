"""Per-user background sync: launchd, Task Scheduler or a systemd user unit."""
from __future__ import annotations

import hashlib
import os
import plistlib
import re
import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape

from keys_keeper.operation_journal import _atomic_write_bytes


def _run(args):
    return subprocess.run(args, capture_output=True, timeout=30, check=False)


def configure(paths, enabled):
    identity = hashlib.sha256(str(paths.root.absolute()).encode()).hexdigest()[:12]
    name = "dev.keys-keeper.sync." + identity
    args = [sys.executable, "-m", "keys_keeper", "devices", "watch", "--home", str(paths.root.absolute())]
    if sys.platform == "darwin":
        target = Path.home() / "Library" / "LaunchAgents" / (name + ".plist")
        service = f"gui/{os.getuid()}/{name}"
        if enabled:
            log = paths.root / "personal-sync.log"
            value = {"Label": name, "ProgramArguments": args, "RunAtLoad": True,
                     "KeepAlive": {"SuccessfulExit": False}, "ThrottleInterval": 30,
                     "StandardOutPath": str(log), "StandardErrorPath": str(log)}
            _atomic_write_bytes(target, plistlib.dumps(value))
            loaded = _run(["launchctl", "print", service]).returncode == 0
            result = (_run(["launchctl", "kickstart", "-k", service]) if loaded else
                      _run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(target)]))
            ok = result.returncode == 0
        else:
            _run(["launchctl", "bootout", service])
            target.unlink(missing_ok=True)
            ok = True
    elif sys.platform == "win32":
        target = paths.root / "personal-sync-task.xml"
        if enabled:
            pythonw = Path(sys.executable).with_name("pythonw.exe")
            if pythonw.is_file():
                args[0] = str(pythonw)
            user = _run(["whoami", "/user", "/fo", "csv", "/nh"])
            if user.returncode != 0:
                return {"autostart": False, "error": "Could not identify the current Windows user"}
            sid = re.search(rb"S-1-[0-9-]+", user.stdout)
            if sid is None:
                return {"autostart": False, "error": "Could not identify the current Windows user"}
            account = sid.group().decode("ascii")
            xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{escape(account)}</UserId></LogonTrigger></Triggers>
<Principals><Principal id="User"><UserId>{escape(account)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure></Settings>
<Actions Context="User"><Exec><Command>{escape(args[0])}</Command><Arguments>{escape(subprocess.list2cmdline(args[1:]))}</Arguments></Exec></Actions></Task>'''
            _atomic_write_bytes(target, xml.encode("utf-16"))
            result = _run(["schtasks", "/Create", "/TN", name, "/XML", str(target), "/F"])
            ok = result.returncode == 0
            if ok:
                ok = _run(["schtasks", "/Run", "/TN", name]).returncode == 0
        else:
            _run(["schtasks", "/End", "/TN", name])
            ok = _run(["schtasks", "/Delete", "/TN", name, "/F"]).returncode == 0
    elif sys.platform.startswith("linux"):
        target = Path.home() / ".config" / "systemd" / "user" / (name + ".service")
        if enabled:
            # systemd has its own escaping rules, independent of shell quoting.
            command = " ".join('"' + a.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"' for a in args)
            _atomic_write_bytes(target, ("[Unit]\nDescription=Keys Keeper personal sync\n[Service]\nExecStart=" + command + "\nRestart=on-failure\nRestartSec=30\n[Install]\nWantedBy=default.target\n").encode())
            _run(["systemctl", "--user", "daemon-reload"])
            ok = _run(["systemctl", "--user", "enable", "--now", target.name]).returncode == 0
        else:
            _run(["systemctl", "--user", "disable", "--now", target.name])
            target.unlink(missing_ok=True)
            ok = True
    else:
        return {"autostart": False, "error": "Automatic startup is unavailable on this platform"}
    return {"autostart": bool(ok and enabled), **({} if ok else {"error": "Could not configure background sync; use Retry background sync"})}
