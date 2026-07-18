# Recording the demo GIF

Goal: a 60–90s screen capture, cut down to a ~20–30s GIF for the top of the
README (GIFs longer than ~30s get huge and nobody watches them). Keep the full
recording as an MP4 — it's reusable for dev.to, LinkedIn, and the launch post.

## Prep (2 minutes)

1. `docker compose -f demo/docker-compose.yml up` and wait for
   `Running the server in development mode`.
2. Browser profile with MetaMask (or Phantom) installed and **already unlocked**
   — unlocking mid-recording wastes 10 seconds and shows your password prompt.
3. Close extra tabs, bookmarks bar, and notifications. A clean window ~1280×800
   reads best after downscaling.
4. Do one full dry run first — the wallet popup position and timing surprise
   you the first time.

## Shot list

| # | Shot | Target duration |
| --- | --- | --- |
| 1 | Browser at `http://localhost:8080/realms/wallet-demo/account` → redirects to the wallet login page | 3–5s |
| 2 | Click connect / sign-in with wallet — MetaMask popup appears | 3–5s |
| 3 | The SIWE message visible in the popup (pause ½s so viewers see domain + nonce), click **Sign** | 5–8s |
| 4 | Redirect → logged-in Account Console, wallet-derived username visible | 4–6s |
| 5 | *(optional, for the long cut only)* repeat with Phantom/Solana | 15–20s |

Record with whatever you like (OBS, ScreenToGif, Xbox Game Bar `Win+Alt+R`).
Save as `demo/raw.mp4`.

## Convert to GIF (ffmpeg, two-pass palette)

```bash
# 1. Trim to the good part (adjust -ss start / -t length)
ffmpeg -ss 00:00:02 -t 25 -i demo/raw.mp4 -c copy demo/cut.mp4

# 2. High-quality GIF: palette pass + render pass
ffmpeg -i demo/cut.mp4 -vf "fps=12,scale=960:-1:flags=lanczos,palettegen=stats_mode=diff" demo/palette.png
ffmpeg -i demo/cut.mp4 -i demo/palette.png \
  -lavfi "fps=12,scale=960:-1:flags=lanczos,paletteuse=dither=bayer:bayer_scale=4" \
  demo/demo.gif
```

Aim for **< 10 MB** (GitHub renders READMEs slowly above that). If it's too
big: drop `fps=12` → `10`, or `scale=960` → `800`, or trim harder.

Also keep an MP4 export for posts (much smaller, better quality):

```bash
ffmpeg -i demo/cut.mp4 -vf "scale=1280:-2" -c:v libx264 -crf 23 -preset slow -an demo/demo.mp4
```

## Wire it into the README

Replace the static screenshot near the top of the root `README.md` with:

```markdown
![Wallet login demo — Keycloak login → Sign with MetaMask → logged in](demo/demo.gif)
```

Commit `demo/demo.gif` to the repo (don't use a GitHub user-attachments URL —
those aren't tied to the repo and can break).
