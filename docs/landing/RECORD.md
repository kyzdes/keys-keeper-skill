# Demo · post-processing recipes

After you've stitched the 4 acts (see `SHOT-LIST.md`) into a single mp4, run these
ffmpeg pipelines to produce the assets the README, HN post, and Twitter thread need.

Assumptions:
- Source: `demo-source.mp4` (1920×1080, 60fps, H.264, no audio)
- All output assets land in `docs/landing/`
- ffmpeg installed: `brew install ffmpeg`

---

## 1. README — small mp4 (preferred over gif on GitHub)

GitHub renders `<video>` tags inline. mp4 is much smaller and sharper than gif at the
same visual quality. Target ≤2 MB so it autoplays on slow networks.

```bash
ffmpeg -i demo-source.mp4 \
  -vf "scale=1280:-2,fps=30" \
  -c:v libx264 -profile:v main -pix_fmt yuv420p \
  -crf 28 -preset slow \
  -movflags +faststart \
  -an \
  docs/landing/demo.mp4
```

Inspect size:

```bash
du -h docs/landing/demo.mp4    # aim for 1-2 MB
```

Embed in README (replace the TODO marker near the top):

```markdown
<video src="docs/landing/demo.mp4" controls autoplay loop muted playsinline></video>
```

GitHub's README renderer treats `<video>` from a relative path as a hosted video
once the repo is public. Alternative if it doesn't render: use a GIF (next).

---

## 2. README fallback — optimized gif

Two-pass palette gif. Same source, much bigger file but works everywhere
(Twitter timeline preview cards, HN comment readers, RSS aggregators).

```bash
# pass 1: compute optimal palette
ffmpeg -i demo-source.mp4 \
  -vf "fps=18,scale=900:-1:flags=lanczos,palettegen=stats_mode=diff" \
  -y docs/landing/.palette.png

# pass 2: encode with that palette + dithering
ffmpeg -i demo-source.mp4 -i docs/landing/.palette.png \
  -lavfi "fps=18,scale=900:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=sierra2_4a" \
  -y docs/landing/demo.gif

rm docs/landing/.palette.png
du -h docs/landing/demo.gif    # aim for 3-5 MB
```

Embed in README:

```markdown
![keys-keeper demo](docs/landing/demo.gif)
```

---

## 3. Twitter — square 1080×1080 mp4

Twitter / X favors square video for in-feed autoplay (1080×1080 ≤ 2:20, ≤512 MB).

```bash
ffmpeg -i demo-source.mp4 \
  -vf "scale=1080:-2,crop=1080:1080,fps=30" \
  -c:v libx264 -profile:v main -pix_fmt yuv420p \
  -crf 22 -preset slow \
  -movflags +faststart \
  -an \
  docs/landing/demo-twitter.mp4
```

(If your edit isn't square-friendly, render at 16:9 1280×720 instead — Twitter
autoplays both, square is just slightly stickier in-feed.)

---

## 4. HN Show post — link to README mp4

HN doesn't host video; just link to the README of the public repo. The mp4 you
embedded in step 1 will play inline on github.com when commenters click through.

In the Show HN post body, include:

> 30-second demo: <https://github.com/kyzdes/keys-keeper#readme> (mp4 inline)

---

## 5. Verify the result

After embedding the mp4 into README and pushing:

```bash
git add docs/landing/demo.mp4 README.md
git commit -m "docs: launch demo asset"
git push origin main

# open the README in a browser to verify the video renders
open https://github.com/kyzdes/keys-keeper#readme
```

GitHub usually takes a few seconds to transcode the inline preview. If it doesn't
play after 30s of waiting, fall back to the gif from step 2 — the markdown change
is one line.

---

## File budget summary

| Asset | Target size | Where it goes |
|---|---|---|
| `docs/landing/demo.mp4` | ≤ 2 MB | README hero (preferred) |
| `docs/landing/demo.gif` | ≤ 5 MB | README fallback / lobste.rs / dev.to |
| `docs/landing/demo-twitter.mp4` | ≤ 4 MB | Twitter / X first tweet of the thread |

Keep the `demo-source.mp4` (full quality master) on your local disk only — don't
commit it. Add it to `.gitignore`:

```
docs/landing/demo-source.mp4
```
