# keys-keeper-skill

Claude Code skill for [keys-keeper](https://github.com/kyzdes/keys-keeper) — a macOS Keychain-backed secrets manager that AI agents architecturally cannot leak from.

## Install via the marketplace (recommended)

```
/plugin marketplace add kyzdes/claude-skills
/plugin install keys-keeper@kyzdes-claude-skills
```

## Install standalone

```
/plugin install kyzdes/keys-keeper-skill
```

## Prerequisite

The `keys` CLI must be installed locally:

```
pipx install git+https://github.com/kyzdes/keys-keeper.git
```

The skill nudges agents toward output-safe commands (`copy`, `inject`, `resolve`) and away from anything that materializes plaintext into the transcript.

## License

MIT
# touched 1778123271
