# Temporary secret sinks

### Agent needs a temporary secret sink

Use a narrowly scoped temporary directory and an explicit file path. On POSIX:

1. Create it with `mktemp -d`, keep the returned path in a task-specific variable, and create only the exact file you need. Never target `$HOME`, `~`, a repository root, a glob, or an unresolved variable for cleanup.
2. Run `keys inject NAME --file "$exact_file" --as ENV_NAME`; the CLI creates/rewrites the sink with owner-only permissions. Do not `cat`, `sed`, `grep`, `source`, interpolate, or otherwise round-trip its contents into shell output. A dotenv assignment is not shell-escaped data.
3. Pass the file directly to the intended local tool, transfer it to one exact protected remote path, or use a fixed helper whose output contains status only. Verify path, owner/mode, non-empty status, and the downstream result — never the value.
4. Remove the exact file with `/bin/unlink "$exact_file"`, then remove the now-empty temporary directory with `rmdir`. Avoid broad `rm -f` / `rm -rf` cleanup patterns; agent policies often reject them and a loose variable makes them dangerous.

If the downstream tool accepts stdin but not an env file, do not improvise a value-printing pipeline. Stop and choose a sink-aware integration or ask the user.
