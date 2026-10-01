"""Isolated UI/server regressions: idle Settings never poll or unlock repeatedly."""
import json
import shutil
import subprocess
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest

from keys_keeper import crypto, operation_journal
from keys_keeper.paths import Paths
from keys_keeper.personal_sync import PersonalSync, _save_settings
from keys_keeper.project_client import ProjectClient
from keys_keeper.project_runtime import ProjectRuntime
from keys_keeper.project_sync import new_master_state
from keys_keeper.server import AdminServer


@pytest.fixture
def synthetic_admin(tmp_path, monkeypatch):
    paths = Paths(tmp_path / 'synthetic')
    monkeypatch.setattr(ProjectRuntime, '_profile_password', lambda *_args: 'synthetic-password')
    monkeypatch.setattr(ProjectClient, '_request', lambda *_args, **_kwargs: pytest.fail('unexpected relay request'))
    scope_id, vault_id = str(uuid4()), str(uuid4())
    data = new_master_state(scope_id, vault_id, 'https://relay.example')
    data['personal_vault'] = True
    item = {'id': scope_id, 'kind': 'master_scope', 'scope_id': scope_id, 'vault_id': vault_id,
            'device_id': data['device_id'], 'project': 'synthetic', 'environment': 'personal',
            'endpoint': data['endpoint'], 'status': 'active'}
    writer = ProjectRuntime(paths)
    writer.registry.put(item)
    writer.state(item).save(data)
    _save_settings(paths, {'version': 1, 'role': 'master', 'scope_id': scope_id,
                         'endpoint': data['endpoint'], 'auto': False, 'name': 'Synthetic', 'replica_id': None})
    server = AdminServer(paths=paths, port=0)
    server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, writer, item
    finally:
        server.stop()
        server._server.server_close()
        thread.join(timeout=5)


def _get(server, action):
    request = urllib.request.Request(f'http://127.0.0.1:{server.bound_port}/api/personal-sync/{action}')
    request.add_header('Sec-Keys-Token', server.token)
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status == 200
        return json.load(response)


def test_http_settings_retain_one_runtime_and_concurrent_reads_derive_once(synthetic_admin, monkeypatch):
    server, _writer, _item = synthetic_admin
    derives, writes = [], []
    real_derive = crypto._derive_key
    monkeypatch.setattr(crypto, '_derive_key', lambda password, salt: (derives.append(salt), real_derive(password, salt))[1])
    monkeypatch.setattr(operation_journal.OperationJournal, '_write_unlocked', lambda *_args: writes.append('write'))
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda action: _get(server, action), ['pending', 'status'] * 4))
    assert len(derives) == 1
    assert writes == []
    assert all(result.get('requests', []) == [] for result in results)
    assert len(server.project_runtime._states) == 1


def test_http_retained_runtime_reads_external_authenticated_state_changes(synthetic_admin, monkeypatch):
    server, writer, item = synthetic_admin
    assert _get(server, 'status')['pending'] == 0
    state = writer.state(item).load()
    state['outbox'] = [{'request_id': 'synthetic-request', 'status': 'accepted'}]
    writer.state(item).save(state)
    derives = []
    real_derive = crypto._derive_key
    monkeypatch.setattr(crypto, '_derive_key', lambda password, salt: (derives.append(salt), real_derive(password, salt))[1])
    assert _get(server, 'status')['pending'] == 1
    assert _get(server, 'status')['pending'] == 1
    assert len(derives) == 1


def test_http_retained_runtime_rejects_changed_ciphertext_instead_of_stale_state(synthetic_admin):
    server, writer, item = synthetic_admin
    assert _get(server, 'status')['pending'] == 0
    record = next(writer.state(item).paths.operations_dir.glob('*.enc'))
    original = record.read_bytes()
    altered = bytearray(original)
    altered[-1] ^= 1
    record.write_bytes(altered)
    with pytest.raises(urllib.error.HTTPError) as failure:
        _get(server, 'status')
    assert failure.value.code == 503
    record.write_bytes(original)
    assert _get(server, 'status')['pending'] == 0


def test_replica_child_runtime_is_bounded_shared_and_changes_with_replica_identity(tmp_path):
    paths = Paths(tmp_path)
    root = ProjectRuntime(paths)
    settings = {'version': 1, 'role': 'replica', 'scope_id': str(uuid4()),
                'endpoint': 'https://relay.example', 'auto': False,
                'name': 'Synthetic', 'replica_id': str(uuid4())}
    _save_settings(paths, settings)
    first = PersonalSync(paths, root).runtime()
    assert PersonalSync(paths, root).runtime() is first
    settings['replica_id'] = str(uuid4())
    _save_settings(paths, settings)
    second = PersonalSync(paths, root).runtime()
    assert second is not first and second.paths.root != first.paths.root
    assert root._personal_child_runtime is second
    (paths.root / 'personal-sync.json').unlink()
    assert PersonalSync(paths, root).runtime() is root
    assert root._personal_child_runtime is None


def test_pending_replica_status_exposes_only_expiry_and_expired_poll_skips_relay(tmp_path, monkeypatch):
    paths = Paths(tmp_path)
    monkeypatch.setattr(ProjectRuntime, '_profile_password', lambda *_args: 'synthetic-password')
    monkeypatch.setattr(ProjectClient, '_request', lambda *_args, **_kwargs: pytest.fail('expired pairing contacted relay'))
    scope_id, replica_id = str(uuid4()), str(uuid4())
    _save_settings(paths, {'version': 1, 'role': 'replica', 'scope_id': scope_id,
                         'endpoint': 'https://relay.example', 'auto': False,
                         'name': 'Synthetic', 'replica_id': replica_id})
    manager = PersonalSync(paths)
    runtime = manager.runtime()
    data = new_master_state(scope_id, str(uuid4()), 'https://relay.example')
    item = {'id': str(uuid4()), 'kind': 'replica', 'scope_id': scope_id, 'vault_id': data['vault_id'],
            'device_id': data['device_id'], 'project': 'synthetic', 'environment': 'personal',
            'endpoint': data['endpoint'], 'status': 'pending'}
    data.update(personal_pairing={'key': 'synthetic-private-marker'},
                enrollment={'request': {'synthetic': True}, 'invitation': {'payload': {'expires_at': 1000}}})
    runtime.registry.put(item)
    runtime.state(item).save(data)
    status = manager.status()
    assert status['pairing_expires_at'] == 1000
    assert 'synthetic-private-marker' not in json.dumps(status)
    assert manager.poll_worker() == {'status': 'expired'}
    assert manager.sync() == {'status': 'expired'}
    assert json.loads((paths.root / 'personal-sync-status.json').read_text())['status'] == 'expired'


def test_settings_browser_polls_only_active_visible_unexpired_pairing():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node.js required for browser timer behavior')
    harness = r"""
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
class Element {
  constructor(tag='div') { this.tag=tag; this.children=[]; this.textContent=''; this.events={}; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children=nodes; }
  setAttribute() {}
  get content() { return this.textContent+this.children.map(node=>node instanceof Element?node.content:node).join(''); }
}
const script=fs.readFileSync(process.argv[1], 'utf8');
async function create(status) {
  let now=1000000, next=0, reloads=0, reply='pending', pendingRequests=[];
  const elements=new Map(), timers=new Map(), calls=[], events={};
  const document={hidden:false, getElementById:id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);},
    createElement:tag=>new Element(tag),addEventListener:(event,fn)=>events[event]=fn};
  const context={document, Date:{now:()=>now}, Number, setTimeout:(fn,delay)=>{const id=++next;timers.set(id,{fn,at:now+delay});return id;},
    clearTimeout:id=>timers.delete(id), window:{addEventListener:(event,fn)=>events[event]=fn, location:{reload:()=>reloads++}, confirm:()=>true},
    fetch:async path=>{const action=path.split('/').pop();calls.push(action);return{ok:true,json:async()=>{
      if(action==='status')return status;
      if(action==='invite')return{code:'synthetic-code',expires_at:(now+20000)/1000};
      if(action==='pending')return{requests:pendingRequests};
      if(action==='poll')return{status:reply};
      if(action==='cancel'){status={configured:false,options:{count:0,token_entries:[],name:'Synthetic'}};}
      return{};
    }};}};
  vm.runInNewContext(script,context);
  const settle=()=>new Promise(resolve=>setImmediate(resolve));
  await settle();
  async function advance(ms) {const end=now+ms;while(true){let chosen;for(const [id,t]of timers)if(t.at<=end&&(!chosen||t.at<chosen[1].at))chosen=[id,t];if(!chosen)break;now=chosen[1].at;timers.delete(chosen[0]);await chosen[1].fn();await settle();}now=end;}
  function find(text) {function walk(node){if(node.textContent===text&&node.onclick)return node;for(const child of node.children)if(child instanceof Element){const match=walk(child);if(match)return match;}}for(const node of elements.values()){const match=walk(node);if(match)return match;}throw Error('missing button '+text);}
  return{calls,timers,document,advance,click:async text=>{await find(text).onclick();await settle();},
    hide:()=>{document.hidden=true;events.visibilitychange();},show:()=>{document.hidden=false;events.visibilitychange();},
    pagehide:()=>events.pagehide(),setReply:value=>reply=value,setRequests:value=>pendingRequests=value,reloads:()=>reloads};
}
(async()=>{
  const master={configured:true,state:'active',role:'master',name:'Synthetic',auto:false,devices:[],background:{autostart:true}};
  const idle=await create(master);await idle.advance(60000);assert.deepEqual(idle.calls,['status']);assert.equal(idle.timers.size,0);
  await idle.click('Sync now');assert.deepEqual(idle.calls,['status','sync','status']);await idle.advance(60000);assert.equal(idle.calls.length,3);
  const invite=await create(master);await invite.click('Add computer');await invite.advance(5000);assert.equal(invite.calls.filter(x=>x==='pending').length,1);
  invite.hide();await invite.advance(6000);assert.equal(invite.calls.filter(x=>x==='pending').length,1);
  invite.show();await invite.advance(5000);assert.equal(invite.calls.filter(x=>x==='pending').length,2);
  await invite.advance(10000);assert.equal(invite.timers.size,0);const expiredCalls=invite.calls.length;await invite.advance(60000);assert.equal(invite.calls.length,expiredCalls);
  const approval=await create(master);await approval.click('Add computer');approval.setRequests([{name:'Other',comparison_code:'1234',pair_id:'synthetic',fingerprint:'synthetic'}]);await approval.advance(5000);
  await approval.click('Codes match — approve computer');const approvedCalls=approval.calls.length;await approval.advance(60000);assert.equal(approval.calls.length,approvedCalls);assert.equal(approval.timers.size,0);
  const worker=await create({configured:true,state:'pending',role:'replica',pairing_expires_at:1020,comparison_code:'1234'});
  await worker.advance(5000);assert.deepEqual(worker.calls,['status','poll']);worker.setReply('active');await worker.advance(5000);assert.equal(worker.reloads(),1);assert.equal(worker.timers.size,0);
  const cancelled=await create({configured:true,state:'pending',role:'replica',pairing_expires_at:1020,comparison_code:'1234'});await cancelled.click('Cancel connection');await cancelled.advance(60000);assert.deepEqual(cancelled.calls,['status','cancel','status']);assert.equal(cancelled.timers.size,0);
  const expired=await create({configured:true,state:'pending',role:'replica',pairing_expires_at:999,comparison_code:'1234'});await expired.advance(60000);assert.deepEqual(expired.calls,['status']);
  const closed=await create(master);await closed.click('Add computer');closed.pagehide();await closed.advance(60000);assert.deepEqual(closed.calls,['status','invite']);assert.equal(closed.timers.size,0);
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
    script = Path(__file__).parents[1] / 'src/keys_keeper/static/personal-sync.js'
    subprocess.run([node, '-e', harness, str(script)], check=True, timeout=20)
