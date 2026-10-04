# DKG explainer video

[`dkg-explainer.mp4`](dkg-explainer.mp4) is a ~6 minute narrated walkthrough of the PedPop+ distributed key generation in [`crates/threshold-signatures`](../../../crates/threshold-signatures/docs/dkg.md), and how the node and contract drive it (`start_keygen`, `vote_pk`, per-domain keygen, resharing).

## Regenerating

The video is rendered from the files in [`source/`](source/):

- `script.py` — narration, one entry per chapter and beat (caption text and TTS text).
- `tts.py` — synthesizes `narration.wav` and `timeline.json` with [kokoro-onnx](https://github.com/thewh1teagle/kokoro-onnx) (voice `am_michael`; model files `kokoro-v1.0.onnx` and `voices-v1.0.bin` expected in `../voices/`).
- `scene.html` — deterministic SVG animation; `renderAt(t)` draws the frame at time `t`, synced to the beat timings.
- `render.mjs` — Playwright script: `node render.mjs stills` for one still per beat, `node render.mjs frames <start> <end>` for 30 fps JPEG frames.

```bash
python tts.py
node render.mjs frames 0 <total_frames>
ffmpeg -framerate 30 -i frames/%06d.jpg -i narration.wav -c:v libx264 -crf 20 -pix_fmt yuv420p -c:a aac -shortest dkg-explainer.mp4
```
