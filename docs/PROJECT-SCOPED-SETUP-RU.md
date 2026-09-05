# Проектная синхронизация: практическая настройка

Этот сценарий отделяет мастер-хранилище от рабочих профилей. Мастер хранит
полный каталог; рабочий получает только записи, которые явно назначены его
окружению. Папка, тег, имя проекта и совпадающий slug **не дают** доступ.
Новые записи по умолчанию `local_only`.

Команды ниже выводят только метаданные. Не вставляйте в чат, историю shell,
issue или вывод агента пароль восстановления, relay admin token, invite и
response bundles. Значения в угловых скобках (`<SCOPE_UUID>`) — шаблоны:
подставьте значение без скобок. UUID берите из `--json`, а не из имени или
slug.

## Роли и границы

| Роль | Где работает | Что делает |
| --- | --- | --- |
| Master | отдельный защищённый пользователь/хост | каталог, назначения, публикация, приглашения, отзыв и восстановление |
| Relay | отдельный VPS | хранит зашифрованные данные, подписанную policy и публичные метаданные; не получает plaintext секретов |
| Worker | отдельный пользователь/хост | читает выданный профиль; `contributor` может создать новую запись, но не изменить или удалить существующую |

Не используйте каталог master как домашний каталог worker и не запускайте relay
от root. Отзыв устройства закрывает будущий доступ к relay и запускает
переиздание scope; он не стирает уже полученные данные или ключевой материал.

## 1. Relay: private Docker service + TLS proxy

На relay-хосте получите исходники именно выбранного релизного тега, создайте
private файл окружения, не печатая токен:

```sh
git clone --branch v0.9.0 --depth 1 https://github.com/kyzdes/keys-keeper-skill.git
cd keys-keeper-skill/docs/syncd
umask 077
python3 - .env <<'PY'
import getpass
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
if path.exists() or path.is_symlink():
    raise SystemExit("refusing to replace an existing .env file")
token = getpass.getpass("New relay admin token (not echoed): ")
if len(token) < 16:
    raise SystemExit("token must contain at least 16 characters")
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(fd, ("KEYS_KEEPER_SYNC_ADMIN_TOKEN=" + token + "\n").encode("utf-8"))
    os.fsync(fd)
finally:
    os.close(fd)
PY
docker compose up -d --build
curl --fail --silent http://127.0.0.1:8787/healthz
```

`docs/syncd/compose.yml` публикует сервис только на `127.0.0.1:8787`.
`keys-keeper-syncd` не выпускает TLS-сертификат и не имеет команды, которая
выводит или передаёт admin token. Завершите HTTPS в доверенном reverse proxy.
Например, отдельный Caddy на том же хосте может проксировать только локальный
порт:

```caddyfile
relay.example.org {
    reverse_proxy 127.0.0.1:8787
}
```

Настройте DNS и сертификаты proxy по собственной процедуре, затем проверьте
публичный endpoint без токена:

```sh
curl --fail --silent https://relay.example.org/healthz
```

Передайте **то же** значение токена владельцу master через согласованный
защищённый канал. Не используйте чат, командную историю или лог Docker. На
master владелец помещает полученный токен во временный owner-only файл и
сохраняет его в backend без печати значения:

```sh
umask 077
if keys add project-relay-admin --type api_key --from-file /secure/inbox/relay-admin-token; then
  /bin/unlink /secure/inbox/relay-admin-token
else
  printf '%s\n' 'Token file was preserved; resolve the error before retrying.' >&2
fi
```

Не удаляйте `.env` relay до согласованной замены токена: сервис читает
`KEYS_KEEPER_SYNC_ADMIN_TOKEN` только из окружения процесса. Для резервной
копии relay используйте отдельную процедуру из
[PROJECT-RELAY-OPERATIONS.md](PROJECT-RELAY-OPERATIONS.md).

## 2. Master: verified backup and catalog migration

Сначала создайте защищённый файл пароля восстановления. Этот пример просит
пароль интерактивно, не показывает его и создаёт новый файл с правами `0600`:

```sh
umask 077
install -d -m 700 "$HOME/.local/share/keys-keeper/recovery"
python3 - "$HOME/.local/share/keys-keeper/recovery/password" <<'PY'
import getpass
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
if path.exists() or path.is_symlink():
    raise SystemExit("refusing to replace an existing recovery-password file")
value = getpass.getpass("Recovery password (stored locally, not echoed): ")
if len(value) < 12:
    raise SystemExit("password must contain at least 12 characters")
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(fd, value.encode("utf-8") + b"\n")
    os.fsync(fd)
finally:
    os.close(fd)
PY
```

Проверьте владельца и режим файла средствами ОС, не читая содержимое. Затем
одной командой создайте и проверьте encrypted backup, после чего включите
schema 3:

```sh
keys project-sync migrate \
  --out /secure/backups/master-before-catalog.kk3 \
  --password-file "$HOME/.local/share/keys-keeper/recovery/password"
```

Для каждого `--out` используйте новый путь в отдельном backup-каталоге, а не
путь recovery password, token или прежнего backup. Не используйте существующий
файл как destination: парольные файлы в примерах выше защищены от замены,
а backup остаётся важным артефактом восстановления и не должен быть перезаписан
по ошибке.

Миграция проверяет, что backup соответствует той же ревизии метаданных до
изменения. При ошибке не продолжайте с `keys projects init`: этот legacy
псевдоним намеренно направляет к `project-sync migrate`. После schema 3
`keys export`, `keys import` и legacy полный `keys sync` откажутся работать,
чтобы не потерять scope bindings и состояние доставки. Для старого хранилища
сначала создайте этот KK3 recovery backup; не обходите отказ ручным
редактированием metadata.

## 3. Master: папки, проект и точное назначение

Папки нужны только для локальной организации. Сначала получите stable IDs:

```sh
keys folders create Infrastructure --json
keys folders list --json
keys projects create payments Payments --json
keys projects list --json
keys projects scopes <PROJECT_UUID> --create --environment production --json
keys projects scopes <PROJECT_UUID> --json
```

Чтобы поместить существующую запись в папку, это не меняет grants:

```sh
keys folders assign-entry kk:<ENTRY_UUID> --folder <FOLDER_UUID> --json
```

Чтобы запись можно было назначить scope, сначала меняется её distribution, а
затем добавляется конкретное canonical entry ID:

```sh
keys projects distribution kk:<ENTRY_UUID> --distribution project_allowed --json
keys projects add kk:<ENTRY_UUID> --scope-id <SCOPE_UUID> --json
```

Одна canonical запись может быть назначена нескольким scope. Это всё ещё
несколько явных назначений; ни move папки, ни rename проекта не создают grant.
Если slug и environment неоднозначны, всегда используйте `--scope-id`.
Проверьте план до публикации:

```sh
keys project-sync preview --scope <SCOPE_UUID>
```

### Те же действия в локальном UI

После миграции на master откройте `keys serve` и страницу **Projects**. До
миграции страница показывает только инструкцию `project-sync migrate` и сама
ничего не меняет. В карточке **Folders** создайте папку через **New folder**,
выберите её и используйте **Move here** для нужной записи. Это только локальная
организация.

В **Projects & environments** создайте проект и добавьте environment. Выберите
environment в этой карточке, затем в **Scope membership** нажмите **Allow &
add** для private записи или **Add** для уже `project_allowed`. Первый вариант
просит подтверждение и меняет только локальные metadata, затем создаёт явное
назначение; он не доставляет секрет. Там же видно, в какие scopes уже назначена
canonical запись. Delivery произойдёт только после настройки scope и отдельной
синхронизации. UI показывает public status и может настроить endpoint с
существующей master token entry, но invite/join/approve/finish остаются
CLI-ceremony.

## 4. Master: включить delivery и создать профиль

Relay endpoint и сохранённая entry с token передаются по имени/ID, не значением
token:

```sh
keys project-sync init \
  --scope <SCOPE_UUID> \
  --endpoint https://relay.example.org \
  --admin-token-entry project-relay-admin
keys project-sync status --scope <SCOPE_UUID>
keys project-sync backup \
  --scope <SCOPE_UUID> \
  --out /secure/backups/master-after-init.kk3 \
  --password-file "$HOME/.local/share/keys-keeper/recovery/password"
```

Статус подтверждает только состояние master/relay и pending work; назначение не
означает, что секрет уже доставлен worker. Публикуйте только после проверки
scope и списка записей:

```sh
keys project-sync sync --scope <SCOPE_UUID>
```

Профили выбираются явно. На master это полезно для проверки и для скриптов:

```sh
keys project-sync profiles
keys --profile <PROFILE_UUID> list
keys --project payments --env production list
```

`--project` и `--env` указываются вместе; неизвестный или неоднозначный
селектор отклоняется до обращения к backend.

## 5. Worker: invite, verify, join, approve, finish

На master создайте короткоживущий invite. Это чувствительный файл: перенесите
его только выбранному человеку через подходящий защищённый канал и не
открывайте содержимое.

```sh
keys project-sync invite --scope <SCOPE_UUID> --out /secure/outbox/invite.json --ttl 900
```

Отдельно подтвердите с worker публичный fingerprint master. На чистом worker
он создаёт request и сверяет fingerprint, не доверяя значению из чата:

```sh
keys project-sync join \
  --invite /secure/inbox/invite.json \
  --fingerprint <MASTER_FINGERPRINT> \
  --role contributor \
  --out /secure/outbox/request.json
```

Верните `request.json` master через выбранный канал. Master сверяет публичный
fingerprint request, одобряет его и передаёт response worker:

```sh
keys project-sync approve \
  --request /secure/inbox/request.json \
  --fingerprint <WORKER_REQUEST_FINGERPRINT> \
  --out /secure/outbox/response.json
```

Worker завершает setup и делает первую синхронизацию:

```sh
keys project-sync finish --scope <SCOPE_UUID> --bundle /secure/inbox/response.json
keys project-sync status
keys project-sync sync
keys project-sync profiles
```

На worker выбранный replica profile может читать свою metadata и создавать
новую запись через разрешённый sink. `contributor` не может менять/удалять
полученные записи, заменять секрет, менять каталог или запускать legacy
full-vault writers:

```sh
printf '%s\n' "$NEW_VALUE" | keys add worker-created-key --stdin
keys project-sync sync
```

Не используйте эту строку в agent transcript: она показана для ручной shell
операции владельца, где `$NEW_VALUE` уже получен безопасным способом.
Worker не получает relay admin token и не использует его для `sync`.

## 6. Обычная работа, отзыв и background sync

Для контролируемой доставки master запускает `sync` по scope. Worker запускает
`sync` для выбранного profile. Перед отзывом сравните device ID и scope с
оператором; затем только master выполняет:

```sh
keys project-sync revoke --scope <SCOPE_UUID> --device <DEVICE_UUID>
keys project-sync sync --scope <SCOPE_UUID>
keys project-sync status --scope <SCOPE_UUID>
```

Ожидайте, пока status не перестанет сообщать pending rekey/publish work. Для
worker в выделенном OS-пользователе можно использовать foreground watch под
systemd:

```ini
[Service]
User=keys
Environment=KEYS_KEEPER_HOME=/var/lib/keys-keeper
ExecStart=/usr/local/bin/keys project-sync watch --scope <SCOPE_UUID> --interval 60
Restart=on-failure
RestartSec=15
```

Не направляйте этот сервис в директорию master.

## 7. Offline recovery and takeover

После сетевой ошибки сначала посмотрите public status и повторите ту же
операцию `sync`; не удаляйте profile/state/journal файлы и не создавайте
профиль заново:

```sh
keys project-sync status --scope <SCOPE_UUID>
keys project-sync sync --scope <SCOPE_UUID>
```

Чтобы восстановить потерянный master, используйте новый пустой root. Если
restore оборван, `--resume` принимает только тот же backup и тот же root:

```sh
keys project-sync restore \
  --file /secure/backups/master-after-init.kk3 \
  --root /secure/recovery-root \
  --password-file "$HOME/.local/share/keys-keeper/recovery/password"

keys project-sync restore \
  --file /secure/backups/master-after-init.kk3 \
  --root /secure/recovery-root \
  --password-file "$HOME/.local/share/keys-keeper/recovery/password" \
  --resume
```

Этот root остаётся `recovery-only`: обычные команды намеренно заблокированы.
После ручной проверки backup подготовьте **новый** owner-only файл с relay
admin token (не используйте старый invite/response) и выполните takeover:

```sh
KEYS_KEEPER_HOME=/secure/recovery-root keys project-sync recover-takeover \
  --file /secure/backups/master-after-init.kk3 \
  --root /secure/recovery-root \
  --endpoint https://relay.example.org \
  --admin-token-file /secure/recovery/relay-admin-token \
  --password-file "$HOME/.local/share/keys-keeper/recovery/password"
```

Takeover создаёт новую authority и fresh scopes, проверяет relay/local state и
не восстанавливает доверие к старым устройствам. После него заново проведите
ceremony invite/join/approve/finish для нужных workers. Не копируйте вручную
registry, state, journal или relay SQLite файлы между root.

## Первые безопасные проверки

1. Master: `keys project-sync preview --scope <SCOPE_UUID>` показывает только
   ожидаемые canonical entries.
2. Master: `keys project-sync status --scope <SCOPE_UUID>` не содержит pending
   ошибок после публикации.
3. Worker: `keys project-sync status` показывает активный профиль и тот же
   scope; `keys list` не показывает master-only записи.
4. Relay: `curl --fail --silent https://relay.example.org/healthz` проходит по
   TLS endpoint; этот health check не подтверждает доставку секретов.

Для форматов backup, relay backup, capacity и restore smoke используйте
[PROJECT-RELAY-OPERATIONS.md](PROJECT-RELAY-OPERATIONS.md). Для краткого
английского operational runbook — [PROJECT-SCOPED-SYNC.md](PROJECT-SCOPED-SYNC.md).
