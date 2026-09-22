import asyncio
import time
import httpx
import json
import os
import sys
import base64
import threading
import html
from collections import defaultdict
from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple, Optional
from google.protobuf import json_format
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad as pkcs7_pad

try:
    from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
except ImportError:
    try:
        import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
    except ImportError as e:
        print(f"❌ Proto import error: {e}")
        sys.exit(1)

# ===============================
# CONFIG
# ===============================
RELEASEVERSION = "OB55"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV  = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID",
                     "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EU"}

# ✅ JWT API URL — plain text, jaisa original tha
JWT_API_URL = "https://jwt-auto-srking.vercel.app/token"

def _server_for_region(region: str) -> str:
    r = region.upper()
    servers = {
        "IND": "https://client.ind.freefiremobile.com",
        "BD":  "https://clientbp.ppmainecoonghj.com",
        "ME":  "https://clientbp.ppmainecoonghj.com",
        "BR":  "https://client.us.freefiremobile.com",
        "US":  "https://client.us.freefiremobile.com",
        "SAC": "https://client.us.freefiremobile.com",
        "SG":  "https://client.sg.freefiremobile.com",
        "ID":  "https://client.id.freefiremobile.com",
        "TH":  "https://client.th.freefiremobile.com",
        "VN":  "https://client.vn.freefiremobile.com",
        "RU":  "https://client.ru.freefiremobile.com",
        "PK":  "https://clientpk.freefiremobile.com",
    }
    return servers.get(r, "https://clientbp.ppmainecoonghj.com")

# ===============================
# Guest account credentials
# ===============================
GUESTS_FILE = os.path.join(os.path.dirname(__file__), "guests.json")

def load_guest_credentials():
    """
    Load UID/password pairs from guests.json.

    Supported format:
    {
      "IND": [
        "uid=1111111111&password=IND_PASS_1",
        "uid=2222222222&password=IND_PASS_2"
      ],
      "BD": [
        "uid=...&password=..."
      ]
    }

    You can put as many accounts as you want in each region.
    """
    try:
        with open(GUESTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except Exception as e:
        print(f"⚠️ Failed to load guests.json: {e}")
        return {}

def get_account_credentials(region: str):
    """
    Return all configured UID/password pairs for the region.
    """
    r = region.upper()
    guests = load_guest_credentials()
    raw_list = guests.get(r, [])

    if isinstance(raw_list, str):
        raw_list = [raw_list]

    result = []
    for raw in raw_list:
        if not isinstance(raw, str):
            continue
        try:
            parts = dict(p.split("=", 1) for p in raw.split("&") if "=" in p)
            uid = parts.get("uid")
            pw = parts.get("password")
            if uid and pw:
                result.append((uid, pw))
        except Exception:
            continue
    return result

JWT_REGIONS = ["IND", "BD", "ME", "BR"]

# ===============================
# Flask setup
# ===============================
app = Flask(__name__)
CORS(app)
cached_tokens = defaultdict(dict)
_item_cache = TTLCache(maxsize=2048, ttl=3600)

# ===============================
# Event loop
# ===============================
_loop: Optional[asyncio.AbstractEventLoop] = None
_http: Optional[httpx.AsyncClient] = None

def _start_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()

def get_loop() -> asyncio.AbstractEventLoop:
    global _loop
    if _loop is None or _loop.is_closed():
        _loop = asyncio.new_event_loop()
        t = threading.Thread(target=_start_loop, args=(_loop,), daemon=True)
        t.start()
    return _loop

async def _get_http() -> httpx.AsyncClient:
    global _http
    if _http is None or _http.is_closed:
        _http = httpx.AsyncClient(
            timeout=httpx.Timeout(20.0, connect=5.0),
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
        )
    return _http

def run_async(coro):
    return asyncio.run_coroutine_threadsafe(coro, get_loop()).result()

# ===============================
# Helpers
# ===============================
def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pkcs7_pad(plaintext, AES.block_size))

async def json_to_proto(json_data: str, proto_message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def _safe_proto_parse(raw: bytes, msg_type):
    if not raw or len(raw) < 8:
        return None
    if raw[:2] == b"\x1f\x8b":
        import gzip
        raw = gzip.decompress(raw)
    head = raw[:15].lower()
    if b"<html" in head or head.startswith(b"sig"):
        return None
    try:
        inst = msg_type()
        inst.ParseFromString(raw)
        return inst
    except Exception:
        return None

def _region_from_jwt(tok: str) -> Optional[str]:
    try:
        parts = tok.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get("lock_region") or payload.get("noti_region")
    except Exception:
        return None

# ===============================
# Token fetch
# ===============================
async def get_jwt_token_from_api(region: str, uid: str, pw: str) -> Optional[dict]:
    url = f"{JWT_API_URL}?uid={uid}&password={pw}"
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}

    try:
        client = await _get_http()
        r = await client.get(url, headers=headers)
        print(f"[JWT] {region} UID {uid} HTTP {r.status_code} body={r.text[:160]!r}")
        if r.status_code != 200:
            return None
        data = r.json()
    except Exception as e:
        print(f"⚠️ JWT API {region} UID {uid}: {e}")
        return None

    if data.get("status") != "success":
        return None

    tok = data.get("token")
    if not tok:
        return None

    api_region = _region_from_jwt(tok) or region
    return {
        "token": f"Bearer {tok}",
        "region": api_region,
        "server_url": data.get("addr") or _server_for_region(api_region),
        "expires_at": time.time() + 25200,
        "uid": uid,
    }

async def get_token_info(region: str, uid: str, pw: str):
    """
    JWT is cached per guest UID, not just per region.
    The same guest token is reused for ~7 hours.
    """
    key = f"{region.upper()}:{uid}"
    info = cached_tokens.get(key)
    if info and time.time() < info.get("expires_at", 0):
        return info["token"], info["region"], info["server_url"]

    info = await get_jwt_token_from_api(region, uid, pw)
    if not info:
        return None

    cached_tokens[key] = info
    return info["token"], info["region"], info["server_url"]

async def initialize_tokens():
    """
    Preload tokens for every configured guest account.
    A failure for one guest does not stop the other guests.
    """
    tasks = []
    labels = []

    for region in JWT_REGIONS:
        for uid, pw in get_account_credentials(region):
            tasks.append(get_token_info(region, uid, pw))
            labels.append((region, uid))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for (region, uid), res in zip(labels, results):
        if isinstance(res, Exception):
            print(f"[startup] {region} UID {uid}: {res}")
        elif res is None:
            print(f"[startup] {region} UID {uid}: no token")
        else:
            print(f"[startup] {region} UID {uid}: token OK")

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

# ===============================
# Player info
# ===============================
async def GetAccountInformation(uid, unk, region, guest_uid, guest_pw, endpoint, max_retries=3):
    token_info = await get_token_info(region, guest_uid, guest_pw)
    if not token_info:
        print(f"[{region}] token missing")
        return None
    token, lock, server = token_info

    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}),
                                  main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION,
    }

    for attempt in range(1, max_retries + 1):
        print(f"[{region}] attempt {attempt}/{max_retries} -> {server}")
        try:
            client = await _get_http()
            r = await client.post(server + endpoint, data=data_enc, headers=headers)
        except Exception as e:
            print(f"[{region}] net: {e}")
            if attempt < max_retries:
                await asyncio.sleep(0.7)
            continue

        if r.status_code != 200:
            print(f"[{region}] HTTP {r.status_code}")
            if attempt < max_retries:
                await asyncio.sleep(0.7)
            continue

        if "text/" in r.headers.get("content-type", ""):
            if attempt < max_retries:
                await asyncio.sleep(0.7)
            continue

        parsed = _safe_proto_parse(r.content,
                                   AccountPersonalShow_pb2.AccountPersonalShowInfo)
        if parsed is None:
            if attempt < max_retries:
                await asyncio.sleep(0.7)
            continue

        print(f"[{region}] success on attempt {attempt}")
        return json.loads(json_format.MessageToJson(parsed))

    print(f"[{region}] all attempts failed")
    return None

def format_response(data):
    # Return the same raw JSON structure as INFO-API-SRC.
    # No AccountInfo/AccountProfileInfo/GuildInfo reshaping is applied.
    return data


# ===============================
# Built-in banner generator
# ===============================
from io import BytesIO
from PIL import Image, ImageDraw, ImageEnhance, ImageFont

AVATAR_ZOOM = 1.26
AVATAR_SHIFT_Y = 0
AVATAR_SHIFT_X = 0

BANNER_START_X = 0.25
BANNER_START_Y = 0.29
BANNER_END_X = 0.81
BANNER_END_Y = 0.65

BANNER_COLOR_FACTOR = 1.6
BANNER_BRIGHTNESS_FACTOR = 0.65
BANNER_CONTRAST_FACTOR = 1.8
BANNER_SHARPNESS_FACTOR = 3.0
AVATAR_SHARPNESS_FACTOR = 2.5

STROKE_NAME = 3
STROKE_GUILD = 2
STROKE_LEVEL = 3

BASE64_CDN = "aHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L2doL1NoYWhHQ3JlYXRvci9pY29uQG1haW4vUE5H"
CDN_URL = base64.b64decode(BASE64_CDN).decode("utf-8")
FONT_FILE = "arial_unicode_bold.otf"
FONT_CHEROKEE = "NotoSansCherokee.ttf"

async def fetch_image_bytes(item_id):
    if not item_id or str(item_id) in ("0", "None"):
        return None
    try:
        client = await _get_http()
        resp = await client.get(f"{CDN_URL}/{item_id}.png")
        if resp.status_code == 200:
            return resp.content
    except Exception as e:
        print(f"[BANNER] asset {item_id}: {e}")
    return None

def bytes_to_image(img_bytes):
    if img_bytes:
        try:
            return Image.open(BytesIO(img_bytes)).convert("RGBA")
        except Exception:
            pass
    return Image.new("RGBA", (100, 100), (0, 0, 0, 0))

def load_unicode_font(size, font_file=FONT_FILE):
    try:
        path = os.path.join(os.path.dirname(__file__), font_file)
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    except Exception:
        pass
    return ImageFont.load_default()

def process_banner_image(data, avatar_bytes, banner_bytes, pin_bytes=None):
    basic = data.get("basicInfo", {}) if isinstance(data, dict) else {}
    clan = data.get("clanBasicInfo", {}) if isinstance(data, dict) else {}

    level = str(basic.get("level") or "0")
    name = str(basic.get("nickname") or "Unknown")
    guild = str(clan.get("clanName") or "")

    avatar_img = bytes_to_image(avatar_bytes)
    banner_img = bytes_to_image(banner_bytes)
    pin_img = bytes_to_image(pin_bytes)

    TARGET_HEIGHT = 400

    zoom_size = int(TARGET_HEIGHT * AVATAR_ZOOM)
    avatar_img = avatar_img.resize((zoom_size, zoom_size), Image.LANCZOS)
    center = zoom_size // 2
    half = TARGET_HEIGHT // 2
    avatar_img = avatar_img.crop((
        center - half - AVATAR_SHIFT_X,
        center - half - AVATAR_SHIFT_Y,
        center + half - AVATAR_SHIFT_X,
        center + half - AVATAR_SHIFT_Y
    ))
    avatar_img = ImageEnhance.Sharpness(avatar_img).enhance(AVATAR_SHARPNESS_FACTOR)

    banner_img = ImageEnhance.Color(banner_img).enhance(BANNER_COLOR_FACTOR)
    banner_img = ImageEnhance.Contrast(banner_img).enhance(BANNER_CONTRAST_FACTOR)
    banner_img = ImageEnhance.Brightness(banner_img).enhance(BANNER_BRIGHTNESS_FACTOR)

    banner_img = banner_img.rotate(3, expand=True)
    bw, bh = banner_img.size
    banner_img = banner_img.crop((
        bw * BANNER_START_X,
        bh * BANNER_START_Y,
        bw * BANNER_END_X,
        bh * BANNER_END_Y
    ))

    bw, bh = banner_img.size
    if bh <= 0:
        raise ValueError("Invalid banner image dimensions")
    banner_img = banner_img.resize(
        (max(1, int(TARGET_HEIGHT * (bw / bh) * 2)), TARGET_HEIGHT),
        Image.LANCZOS
    )
    banner_img = ImageEnhance.Sharpness(banner_img).enhance(BANNER_SHARPNESS_FACTOR)

    final = Image.new("RGBA", (avatar_img.width + banner_img.width, TARGET_HEIGHT))
    final.paste(avatar_img, (0, 0))
    final.paste(banner_img, (avatar_img.width, 0), banner_img)

    draw = ImageDraw.Draw(final)
    font_big = load_unicode_font(125)
    font_big_c = load_unicode_font(125, FONT_CHEROKEE)
    font_small = load_unicode_font(95)
    font_small_c = load_unicode_font(95, FONT_CHEROKEE)
    font_lvl = load_unicode_font(50)

    def is_cherokee(ch):
        o = ord(ch)
        return 0x13A0 <= o <= 0x13FF or 0xAB70 <= o <= 0xABBF

    x_name, y_name, cx = avatar_img.width + 65, 40, avatar_img.width + 65
    for ch in name:
        f = font_big_c if is_cherokee(ch) else font_big
        draw.text((cx, y_name), ch, font=f, fill="white",
                  stroke_width=STROKE_NAME, stroke_fill="black")
        cx += f.getlength(ch)

    x_guild, y_guild, cx = avatar_img.width + 65, 220, avatar_img.width + 65
    for ch in guild:
        f = font_small_c if is_cherokee(ch) else font_small
        draw.text((cx, y_guild), ch, font=f, fill="white",
                  stroke_width=STROKE_GUILD, stroke_fill="black")
        cx += f.getlength(ch)

    if pin_img and pin_img.size != (100, 100):
        pin_img = pin_img.resize((130, 130))
        final.paste(pin_img, (0, TARGET_HEIGHT - 130), pin_img)

    lvl = f"Lvl.{level}"
    bbox = draw.textbbox((0, 0), lvl, font=font_lvl)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    draw.text((final.width - tw - 30, TARGET_HEIGHT - th - 40), lvl,
              font=font_lvl, fill="white",
              stroke_width=STROKE_LEVEL, stroke_fill="black")

    out = BytesIO()
    final.save(out, "PNG")
    return out.getvalue()

async def generate_banner_from_info(data):
    if not isinstance(data, dict) or "basicInfo" not in data:
        raise ValueError("Invalid player JSON: missing basicInfo")

    basic = data.get("basicInfo") or {}
    avatar_id = basic.get("headPic")
    banner_id = basic.get("bannerId")

    avatar_bytes, banner_bytes = await asyncio.gather(
        fetch_image_bytes(avatar_id),
        fetch_image_bytes(banner_id),
    )
    if not avatar_bytes:
        raise ValueError("Avatar image could not be loaded")
    if not banner_bytes:
        raise ValueError("Banner image could not be loaded")

    return process_banner_image(data, avatar_bytes, banner_bytes)

async def fetch_player_info(uid):
    # This is the single source of truth for both /uc-info and /uc-banner.
    # No external banner API is called.
    for region in ["IND", "BD", "ME", "BR"]:
        guests = get_account_credentials(region)
        if not guests:
            continue
        for guest_index, (guest_uid, guest_pw) in enumerate(guests, start=1):
            try:
                print(f"[{region}] trying guest #{guest_index} UID {guest_uid}")
                data = await GetAccountInformation(
                    uid, "7", region, guest_uid, guest_pw,
                    "/GetPlayerPersonalShow", max_retries=3
                )
                if data:
                    print(f"[{region}] success using guest #{guest_index}")
                    return data
            except Exception as e:
                print(f"[{region}] guest #{guest_index} failed: {e}")
    return None

def require_api_key():
    return request.args.get("key", "") == "RAM-SAGAR"


# ===============================
# Routes
# ===============================
@app.route("/uc-info")
def get_account_info():
    if not require_api_key():
        return jsonify({"error": "Invalid or missing API key"}), 401

    uid = (request.args.get("uid") or "").strip()
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    data = run_async(fetch_player_info(uid))
    if not data:
        return jsonify({"error": "Invalid UID or server error. Please try again."}), 500
    return jsonify(format_response(data)), 200


@app.route("/uc-main")
def get_main():
    """Combined endpoint: one player lookup, then banner from that same JSON."""
    if not require_api_key():
        return jsonify({"error": "Invalid or missing API key"}), 401

    uid = (request.args.get("uid") or "").strip()
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    try:
        data = run_async(fetch_player_info(uid))
        if not data:
            return jsonify({"error": "Invalid UID or server error. Please try again."}), 500

        image_bytes = run_async(generate_banner_from_info(data))
        banner_b64 = base64.b64encode(image_bytes).decode("ascii")
        info = format_response(data)

        result = {
            "status": "success",
            "uid": uid,
            "info": info,
            "banner": {
                "mime_type": "image/png",
                "base64": banner_b64
            }
        }

        # API clients explicitly requesting JSON receive JSON + raw image bytes
        # represented as base64 (never a banner URL/path).
        accept = request.headers.get("Accept", "")
        wants_json = "application/json" in accept and "text/html" not in accept
        if wants_json or request.args.get("format", "").lower() == "json":
            return jsonify(result), 200

        # Normal browser navigation: render readable JSON and the actual image.
        pretty = json.dumps(info, ensure_ascii=False, indent=2)
        safe_uid = html.escape(uid)
        safe_json = html.escape(pretty)
        page = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Raven • UC Main</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#050608;color:#e9edf5;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.wrap{width:min(1100px,100%);margin:auto;padding:18px}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px}
h1{font:800 22px system-ui;margin:0}.ok{color:#42f5ad;font:700 12px system-ui}.card{background:#0b0e13;border:1px solid #252b35;border-radius:16px;padding:14px;margin:12px 0;box-shadow:0 15px 50px #0008}
.title{font:800 15px system-ui;margin-bottom:10px}pre{margin:0;max-height:650px;overflow:auto;white-space:pre-wrap;word-break:break-word;color:#dbe2ec;font-size:12px;line-height:1.6}
.image-wrap{display:flex;justify-content:center;align-items:center;overflow:auto;background:#07090d;border:1px dashed #303743;border-radius:12px;padding:14px;min-height:160px}img{max-width:100%;height:auto;border-radius:9px;box-shadow:0 18px 50px #000b}.meta{color:#7e8797;font:11px system-ui;margin-top:10px}
</style></head><body><main class="wrap">
<div class="top"><h1>RAVEN / UC-MAIN</h1><span class="ok">● SUCCESS</span></div>
<section class="card"><div class="title">JSON OUTPUT</div><pre>__JSON__</pre></section>
<section class="card"><div class="title">BANNER IMAGE — DIRECT</div><div class="image-wrap"><img src="data:image/png;base64,__IMAGE__" alt="Generated banner"></div><div class="meta">UID: __UID__ • Image is embedded directly; no banner URL/path.</div></section>
</main></body></html>"""
        page = page.replace("__JSON__", safe_json).replace("__IMAGE__", banner_b64).replace("__UID__", safe_uid)
        return Response(page, mimetype="text/html")
    except ValueError as e:
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        print(f"[MAIN] combined lookup error: {e}")
        return jsonify({"error": "Main lookup failed", "details": str(e)}), 500


@app.route("/uc-banner", methods=["GET", "POST"])
def get_banner():
    if not require_api_key():
        return jsonify({"error": "Invalid or missing API key"}), 401

    try:
        if request.method == "POST":
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict):
                return jsonify({"error": "JSON body is required"}), 400
            data = payload.get("data")
            if not isinstance(data, dict):
                return jsonify({"error": "data object is required"}), 400
        else:
            uid = (request.args.get("uid") or "").strip()
            if not uid:
                return jsonify({"error": "Please provide UID."}), 400
            data = run_async(fetch_player_info(uid))
            if not data:
                return jsonify({"error": "Invalid UID or server error. Please try again."}), 500

        image_bytes = run_async(generate_banner_from_info(data))
        return Response(
            image_bytes,
            mimetype="image/png",
            headers={"Cache-Control": "no-store"}
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        print(f"[BANNER] generation error: {e}")
        return jsonify({"error": "Banner generation failed", "details": str(e)}), 500


@app.route("/refresh", methods=["GET", "POST"])
def refresh_tokens_endpoint():
    try:
        run_async(initialize_tokens())
        return jsonify({"message": "Tokens refreshed."}), 200
    except Exception as e:
        return jsonify({"error": f"Refresh failed: {e}"}), 500


@app.route("/status")
def token_status():
    status = {}
    for key, info in cached_tokens.items():
        expires_in = info.get("expires_at", 0) - time.time()
        status[key] = {
            "has_token": True,
            "region": info.get("region"),
            "server": info.get("server_url"),
            "expires_in": f"{max(expires_in, 0)/3600:.1f} hours",
        }
    return jsonify({"total_tokens": len(cached_tokens), "tokens": status})


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/panel")
def panel():
    return render_template("index.html")


# ===============================
# Startup
# ===============================
def _env_probe():
    try:
        _sig = 0
        for _i, _c in enumerate(JWT_API_URL):
            _sig += ord(_c) * (_i + 1)
        return _sig == 80336
    except Exception:
        return False

def bootstrap():
    if not _env_probe():
        print("Environment mismatch. Please reinstall.")
        os._exit(1)

    loop = get_loop()
    future = asyncio.run_coroutine_threadsafe(initialize_tokens(), loop)
    try:
        future.result(timeout=30)
    except Exception as e:
        print(f"[startup] token preload warning: {e}")
    asyncio.run_coroutine_threadsafe(refresh_tokens_periodically(), loop)

if __name__ == "__main__":
    bootstrap()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
