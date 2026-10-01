"""Small operational CLI; device enrollment lives in Settings → My computers."""
from __future__ import annotations

import json
from pathlib import Path

from keys_keeper.paths import Paths
from keys_keeper.personal_sync import PersonalSync


def command(args):
    paths = Paths(Path(args.home)) if getattr(args, "home", None) else Paths()
    manager = PersonalSync(paths)
    try:
        if args.devices_command == "watch":
            result = manager.watch(interval=args.interval, cycles=args.cycles)
        elif args.devices_command == "setup":
            result = manager.setup(endpoint=args.endpoint, admin_token_entry=args.admin_token_entry,
                                   name=args.name, all_keys=args.all_keys)
            result.update(manager.set_auto(True))
        elif args.devices_command == "autostart":
            result = manager.set_auto(args.mode == "on")
        else:
            result = getattr(manager, args.devices_command)()
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(json.dumps({"error": "Personal sync could not complete. Open Settings → My computers."}, ensure_ascii=False))
        return 1


def register(sub):
    parser = sub.add_parser("devices", help="personal VPS sync; add computers in Settings → My computers")
    commands = parser.add_subparsers(dest="devices_command", required=True)
    for name in ("status", "sync", "watch", "setup", "autostart"):
        item = commands.add_parser(name)
        item.add_argument("--home", help="explicit local vault directory")
        item.set_defaults(func=command)
        if name == "watch":
            item.add_argument("--interval", type=int, default=60)
            item.add_argument("--cycles", type=int, default=0)
        elif name == "setup":
            item.add_argument("--endpoint", required=True)
            item.add_argument("--admin-token-entry", required=True)
            item.add_argument("--name", required=True)
            item.add_argument("--all-keys", action="store_true")
        elif name == "autostart":
            item.add_argument("mode", choices=("on", "off"))
