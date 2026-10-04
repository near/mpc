import json, numpy as np, soundfile as sf
from kokoro_onnx import Kokoro
from script import SCENES
k = Kokoro("../voices/kokoro-v1.0.onnx", "../voices/voices-v1.0.bin")
SR = 24000
LEAD, TAIL, SCENE_LEAD, SCENE_TAIL = 0.25, 0.45, 0.6, 0.5
audio = []; timeline = []; t = 0.0
def sil(s): return np.zeros(int(round(s*SR)), dtype=np.float32)
for si,(title,beats) in enumerate(SCENES):
    scene = {"title": title, "start": t, "beats": []}
    for bi,b in enumerate(beats):
        cap, say = (b if isinstance(b, tuple) else (b, None))
        say = say or cap
        s, sr = k.create(say, voice="am_michael", speed=1.0, lang="en-us"); assert sr == SR
        s = s.astype(np.float32)
        lead = LEAD + (SCENE_LEAD if bi == 0 else 0)
        tail = TAIL + (SCENE_TAIL if bi == len(beats)-1 else 0)
        seg = np.concatenate([sil(lead), s, sil(tail)])
        dur = len(seg)/SR
        scene["beats"].append({"start": t, "dur": dur, "speechStart": t+lead, "speechEnd": t+lead+len(s)/SR, "caption": cap})
        audio.append(seg); t += dur
    scene["end"] = t
    timeline.append(scene)
    print(si, title, round(t,1))
sf.write("narration.wav", np.concatenate(audio), SR)
json.dump({"total": t, "scenes": timeline}, open("timeline.json","w"), indent=1)
