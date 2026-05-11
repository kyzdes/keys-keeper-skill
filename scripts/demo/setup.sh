#!/usr/bin/env bash
# Seed an isolated keys-keeper demo state for screen recording.
#   bash scripts/demo/setup.sh
# Then in another shell: `source scripts/demo/env.sh && keys serve`
#
# Wipes anything previous in the demo state. Does NOT touch your real
# ~/.config/keys-keeper or login keychain.
set -euo pipefail

DEMO_HOME="$HOME/.config/keys-keeper-demo"
DEMO_KC="/tmp/kk-demo.keychain-db"
DEMO_SVC="keys-keeper-demo"
DEMO_PWD="demo"

# clean slate
echo "→ cleaning previous demo state"
rm -rf "$DEMO_HOME"
security delete-keychain "$DEMO_KC" 2>/dev/null || true
rm -f "$DEMO_KC"

# fresh keychain
echo "→ creating $DEMO_KC"
security create-keychain -p "$DEMO_PWD" "$DEMO_KC"
security unlock-keychain -p "$DEMO_PWD" "$DEMO_KC"
security set-keychain-settings -u "$DEMO_KC"   # never auto-locks during the recording

mkdir -p "$DEMO_HOME"

export KEYS_KEEPER_HOME="$DEMO_HOME"
export KEYS_KEEPER_TEST_KEYCHAIN="$DEMO_KC"
export KEYS_KEEPER_TEST_SERVICE="$DEMO_SVC"

KEYS="${KEYS_BIN:-$HOME/.local/bin/keys}"

# ── seed entries ─────────────────────────────────────────────────────────────
# Realistic-looking but obviously-fake values. The names mirror what a typical
# AI-tooling power user would have: a few LLM providers, a payments stack, a
# server linked to an SSH key, a domain, a CI token.

seed() {
  local name="$1" type="$2" value="$3"
  shift 3
  printf '%s' "$value" | "$KEYS" add "$name" --type "$type" --stdin "$@"
}

echo "→ seeding 10 entries"
seed openrouter-claude api_key "sk-or-v1-DEMO00000000000000000000000000claude" \
    --service openrouter --tag llm --tag personal --note "main Claude Code LLM key"
seed openrouter-roo    api_key "sk-or-v1-DEMO00000000000000000000000000roo000" \
    --service openrouter --tag llm
seed anthropic-direct  api_key "sk-ant-DEMO0000000000000000000000000direct" \
    --service anthropic --tag llm --tag work --note "direct API for CI scripts"
seed stripe-test       api_key "sk_test_DEMO00000000000000000000stripe_test" \
    --service stripe --tag payments --tag dev
seed stripe-live       api_key "sk_live_DEMO00000000000000000000stripe_live" \
    --service stripe --tag payments --tag prod --note "⚠ live key — careful"
seed github-token-cli  api_key "github_pat_DEMO000000000000000000000000token" \
    --service github --tag dev --tag personal --note "fine-grained, repo:write"
seed cf-api            api_key "DEMO00000000cloudflare000000token0000000" \
    --service cloudflare --tag infra --note "DNS + Workers"

# ssh_key with a fake PEM. Reuse the same fake bytes each time for simplicity.
PEM="-----BEGIN OPENSSH PRIVATE KEY-----
DEMOb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBSBu
DEMOZmFrZWZha2VmYWtlZmFrZWZha2VmYWtlZmFrZWZha2VmYWtlZmFrZWZha2VmYWtlZmFr
DEMOZmFrZWZha2VmYWtlZmFrZWZha2VmYWtlZmFrZWZha2VmYWtlZmFrZWZha2VmYWtlZmFr
-----END OPENSSH PRIVATE KEY-----"
printf '%s' "$PEM" | "$KEYS" add my-do-key --type ssh_key --stdin \
    --field "public_key=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5DEMOdokeyfake demo@host" \
    --field "comment=kuzdes@laptop" \
    --tag personal --tag do --note "main key for DO droplets"

"$KEYS" add do-prod-droplet --type server --from-file /dev/null \
    --field host=165.232.1.1 --field user=root --field port=22 --field auth=ssh_key \
    --ref ssh_key=my-do-key \
    --tag prod --tag do --note "main app server, prod stack"

"$KEYS" add mysite.com --type domain --from-file /dev/null \
    --field host=mysite.com --field registrar=cloudflare \
    --tag prod --note "primary domain"

# ── seed audit activity ──────────────────────────────────────────────────────
# A few harmless ops so /audit chart isn't a single bar.
echo "→ seeding audit activity"
"$KEYS" copy openrouter-claude > /dev/null
"$KEYS" inject openrouter-claude --file /tmp/demo-env --as OPENROUTER_API_KEY > /dev/null
"$KEYS" copy stripe-test > /dev/null
"$KEYS" inject github-token-cli --file /tmp/demo-env --as GITHUB_TOKEN > /dev/null
"$KEYS" copy openrouter-claude > /dev/null
"$KEYS" copy my-do-key > /dev/null
rm -f /tmp/demo-env
# clear the clipboard so the demo doesn't start with a real-looking value
printf '' | pbcopy

echo
echo "✓ demo state seeded:"
"$KEYS" list
echo
echo "next:"
echo "  in a fresh shell:  source scripts/demo/env.sh && keys serve"
echo "  to teardown later: bash scripts/demo/teardown.sh"
