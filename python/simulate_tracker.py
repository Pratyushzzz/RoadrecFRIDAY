"""Pretend to be a vehicle tracker: pushes a moving GPS position every few seconds.
  python simulate_tracker.py --api http://localhost:8000 --key dk_xxx
(stdlib only). The key comes from POST /vehicles/{id}/device-key."""
import argparse, json, math, time, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--api", default="http://localhost:8000"); ap.add_argument("--key", required=True)
ap.add_argument("--lat", type=float, default=28.6139); ap.add_argument("--lon", type=float, default=77.2090)
ap.add_argument("--every", type=float, default=3.0)
a = ap.parse_args()
lat, lon, hdg, v = a.lat, a.lon, 45.0, 8.0
while True:
    hdg = (hdg + 3) % 360
    lat += v * a.every * math.cos(math.radians(hdg)) / 111_320
    lon += v * a.every * math.sin(math.radians(hdg)) / (111_320 * math.cos(math.radians(lat)))
    body = json.dumps({"lat": lat, "lon": lon, "speed_mps": v, "heading_deg": hdg}).encode()
    req = urllib.request.Request(a.api + "/track/position", body, {"Content-Type": "application/json", "X-Device-Key": a.key})
    try:
        print(urllib.request.urlopen(req, timeout=10).status, f"{lat:.5f},{lon:.5f}")
    except Exception as e:
        print("push failed:", e)
    time.sleep(a.every)
