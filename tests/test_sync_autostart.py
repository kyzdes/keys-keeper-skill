from __future__ import annotations

import plistlib
from types import SimpleNamespace
from xml.etree import ElementTree

from keys_keeper import sync_autostart
from keys_keeper.paths import Paths


def test_windows_task_preserves_paths_and_uses_current_user_sid(tmp_path, monkeypatch):
    calls = []
    def run(args):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout=b'"pc\\user","S-1-5-21-123-456-789-1001"\r\n')
    monkeypatch.setattr(sync_autostart, '_run', run)
    monkeypatch.setattr(sync_autostart.sys, 'platform', 'win32')
    monkeypatch.setattr(sync_autostart.sys, 'executable', str(tmp_path / 'Program Files' / 'python.exe'))
    paths = Paths(tmp_path / 'User & Data' / 'keys')
    assert sync_autostart.configure(paths, True) == {'autostart': True}
    root = ElementTree.fromstring((paths.root / 'personal-sync-task.xml').read_bytes())
    ns = {'t': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
    assert root.find('.//t:LogonType', ns).text == 'InteractiveToken'
    assert root.find('.//t:RunLevel', ns).text == 'LeastPrivilege'
    assert root.find('.//t:Principal/t:UserId', ns).text == 'S-1-5-21-123-456-789-1001'
    assert root.find('.//t:Arguments', ns).text.endswith('"' + str(paths.root) + '"')
    assert root.find('.//t:CalendarTrigger/t:ScheduleByDay/t:DaysInterval', ns).text == '1'
    assert root.find('.//t:ExecutionTimeLimit', ns).text == 'PT5M'
    assert root.find('.//t:RestartOnFailure', ns) is None
    assert '--cycles 1' in root.find('.//t:Arguments', ns).text
    assert not any('/Run' in c for c in calls)


def test_macos_launch_agent_reports_launch_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(sync_autostart.Path, 'home', classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(sync_autostart.sys, 'platform', 'darwin')
    monkeypatch.setattr(sync_autostart.os, 'getuid', lambda: 501, raising=False)
    monkeypatch.setattr(sync_autostart, '_run', lambda args: SimpleNamespace(returncode=1))
    paths = Paths(tmp_path / 'vault')
    result = sync_autostart.configure(paths, True)
    assert not result['autostart'] and result['error']
    target = next((tmp_path / 'Library' / 'LaunchAgents').glob('dev.keys-keeper.sync.*.plist'))
    value = plistlib.loads(target.read_bytes())
    assert value['ProgramArguments'][-1] == str(paths.root)
    assert 'KeepAlive' not in value
    assert value['RunAtLoad'] is False
    assert value['StartInterval'] == 86400
    assert value['ProgramArguments'][-4:-2] == ['--cycles', '1']


def test_macos_reconfiguration_replaces_loaded_agent_without_kickstart(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(sync_autostart.Path, 'home', classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(sync_autostart.sys, 'platform', 'darwin')
    monkeypatch.setattr(sync_autostart.os, 'getuid', lambda: 501, raising=False)
    monkeypatch.setattr(sync_autostart, '_run', lambda args: calls.append(args) or SimpleNamespace(returncode=0))
    assert sync_autostart.configure(Paths(tmp_path / 'vault'), True) == {'autostart': True}
    assert [command[1] for command in calls] == ['print', 'bootout', 'bootstrap']


def test_linux_uses_daily_timer_and_bounded_oneshot_service(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(sync_autostart.Path, 'home', classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(sync_autostart.sys, 'platform', 'linux')
    monkeypatch.setattr(sync_autostart, '_run', lambda args: calls.append(args) or SimpleNamespace(returncode=0))
    assert sync_autostart.configure(Paths(tmp_path / 'vault'), True) == {'autostart': True}
    base = tmp_path / '.config' / 'systemd' / 'user'
    service = next(base.glob('*.service')).read_text()
    timer = next(base.glob('*.timer')).read_text()
    assert 'Type=oneshot' in service and 'TimeoutStartSec=310' in service
    assert 'Restart=no' in service and '--cycles' in service
    assert 'OnActiveSec=24h' in timer and 'OnUnitActiveSec=24h' in timer
    assert calls[-1][-1].endswith('.timer')
