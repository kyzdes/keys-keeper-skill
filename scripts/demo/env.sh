# source this in your recording shell to isolate keys-keeper from real data:
#   source scripts/demo/env.sh
#
# - KEYS_KEEPER_HOME     → ~/.config/keys-keeper-demo (separate config + audit dir)
# - KEYS_KEEPER_TEST_KEYCHAIN → /tmp/kk-demo.keychain-db (separate macOS keychain)
# - KEYS_KEEPER_TEST_SERVICE → keys-keeper-demo (separate keychain "service" namespace)
#
# Real ~/.config/keys-keeper/ + login keychain are untouched while these are set.
# Running `keys ...` in this shell hits the demo state. Open a fresh shell to go
# back to your real data.

export KEYS_KEEPER_HOME="$HOME/.config/keys-keeper-demo"
export KEYS_KEEPER_TEST_KEYCHAIN="/tmp/kk-demo.keychain-db"
export KEYS_KEEPER_TEST_SERVICE="keys-keeper-demo"
export KEYS_KEEPER_ALLOW_REVEAL=1   # makes `keys reveal` work for the act-1 contrast shot
echo "✓ demo env loaded — KEYS_KEEPER_HOME=$KEYS_KEEPER_HOME"
