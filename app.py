from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
import hashlib
import random
import time
import json
import threading
import urllib.parse
from datetime import datetime, timezone, timedelta
import ntplib
import pytz
import urllib3
import logging
import requests
from base64 import b64encode, b64decode
import hmac
import binascii

# Import the AES module
from miunlock_aes import aes_cbc_encrypt, aes_cbc_decrypt

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

import os
app = Flask(__name__, template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'))
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'hyperos-unlocker-secret-key-change-this')
CORS(app)

# Global state
unlock_state = {
    'running': False,
    'logs': [],
    'status': 'idle',
    'result': None,
    'target_time': None,
    'cookie': None,
    'device_id': None,
    'user_info': None,
    'login_method': 'manual'  # 'manual' or 'auto'
}

ntp_servers = [
    "ntp0.ntp-servers.net", "ntp1.ntp-servers.net", "ntp2.ntp-servers.net",
    "ntp3.ntp-servers.net", "ntp4.ntp-servers.net", "ntp5.ntp-servers.net",
    "ntp6.ntp-servers.net"
]

beijing_tz = pytz.timezone("Asia/Shanghai")

# Xiaomi OAuth endpoints
XIAOMI_AUTH_URL = "https://account.xiaomi.com/oauth2/authorize"
XIAOMI_TOKEN_URL = "https://account.xiaomi.com/oauth2/token"
XIAOMI_LOGIN_URL = "https://account.xiaomi.com/fe/service/login/password"

# Default client ID for Xiaomi community (public client)
DEFAULT_CLIENT_ID = "2882303761517854078"

# ============ AES Crypto Functions ============

def _send(path, params_raw, domain, ssecurity, cookies):
    """Send encrypted request to Xiaomi API using the provided crypto"""
    headers = {"User-Agent": "XiaomiPCSuite"}
    ssecurity_key = b64decode(ssecurity)    
    iv = b'0102030405060708'
    key = b'2tBeoEyJTunmWUGq7bQH2Abn0k2NhhurOaqBfyxCuLVgn4AVj7swcawe53uDUno'
    params_raw["sid"] = "miui_unlocktool_client"

    if 'data' in params_raw:
        params_raw['data'] = json.dumps(params_raw['data'])
        params_raw['data'] = b64encode(params_raw['data'].encode()).decode()

    param_order = sorted(params_raw.keys())

    sign_params = '&'.join(f"{k}={params_raw[k]}" for k in param_order)
    sign_str = f"POST\n{path}\n{sign_params}"

    sign_hash_hex = binascii.hexlify(hmac.new(key, sign_str.encode(), hashlib.sha1).digest()).decode().encode()

    pad_len = 16 - len(sign_hash_hex) % 16
    padded_sign = sign_hash_hex + bytes([pad_len]) * pad_len

    current_sign = b64encode(aes_cbc_encrypt(padded_sign, ssecurity_key, iv)).decode()

    encoded_params = []
    for k in param_order:
        data = params_raw[k].encode()
        pad_len = 16 - len(data) % 16
        padded_data = data + bytes([pad_len]) * pad_len
        encrypted = b64encode(aes_cbc_encrypt(padded_data, ssecurity_key, iv)).decode()
        encoded_params.append(f"{k}={encrypted}")

    encoded_params.extend([f"sign={current_sign}", ssecurity])

    sha1_input = f"POST&{path}&{'&'.join(encoded_params)}"
    signature = b64encode(hashlib.sha1(sha1_input.encode()).digest()).decode()

    post_params = {}
    for k in param_order:
        data = params_raw[k].encode()
        pad_len = 16 - len(data) % 16
        padded_data = data + bytes([pad_len]) * pad_len
        post_params[k] = b64encode(aes_cbc_encrypt(padded_data, ssecurity_key, iv)).decode()

    post_params.update({'sign': current_sign, 'signature': signature})

    try:
        response = requests.post(f"{domain}{path}", params=post_params, cookies=cookies, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException:
        return {"error": "network request failed"}

    if not response.text:
        return {"error": "empty response"}

    if len(response.text) % 4 != 0:
        return {"error": "invalid base64 response"}

    try:
        encrypted_data = b64decode(response.text)
        decrypted = aes_cbc_decrypt(encrypted_data, ssecurity_key, iv)
    except:
        return {"error": "decrypt failed"}

    if not decrypted:
        return {"error": "empty decrypted data"}
    if len(decrypted) % 16 != 0:
        return {"error": "decrypted data not aligned"}

    pad_len = decrypted[-1]
    if pad_len < 1 or pad_len > 16:
        return {"error": "invalid padding length"}
    if decrypted[-pad_len:] != bytes([pad_len]) * pad_len:
        return {"error": "invalid padding"}

    clean_data = decrypted[:-pad_len]

    try:
        inner_b64 = b64decode(clean_data)
    except:
        return {"error": "inner base64 invalid"}

    try:
        clean_response = json.loads(inner_b64.decode())
        if "code" in clean_response:
            return clean_response
        else:
            return {"error": clean_response}
    except:
        return {"error": "json parse failed"}

# ============ Helper Functions ============

def add_log(message, level='info'):
    timestamp = datetime.now().strftime('%H:%M:%S')
    log_entry = {'time': timestamp, 'message': message, 'level': level}
    unlock_state['logs'].append(log_entry)
    logger.info(message)

def generate_device_id():
    random_data = f"{random.random()}-{time.time()}"
    return hashlib.sha1(random_data.encode('utf-8')).hexdigest().upper()

def get_initial_beijing_time():
    client = ntplib.NTPClient()
    for server in ntp_servers:
        try:
            add_log(f"Getting Beijing time from {server}...", 'info')
            response = client.request(server, version=3)
            ntp_time = datetime.fromtimestamp(response.tx_time, timezone.utc)
            beijing_time = ntp_time.astimezone(beijing_tz)
            add_log(f"Beijing time: {beijing_time.strftime('%Y-%m-%d %H:%M:%S')}", 'success')
            return beijing_time
        except Exception as e:
            add_log(f"Failed to connect {server}: {e}", 'error')
    add_log("All NTP servers failed", 'error')
    return None

def get_synchronized_beijing_time(start_beijing_time, start_timestamp):
    elapsed = time.time() - start_timestamp
    return start_beijing_time + timedelta(seconds=elapsed)

def wait_until_target_time(start_beijing_time, start_timestamp, feed_time_shift=1400):
    feed_time_shift_1 = feed_time_shift / 1000
    next_day = start_beijing_time + timedelta(days=1)
    target_time = next_day.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(seconds=feed_time_shift_1)

    unlock_state['target_time'] = target_time.strftime('%Y-%m-%d %H:%M:%S')
    add_log(f"Phase shift: {feed_time_shift:.2f} ms", 'info')
    add_log(f"Waiting until: {target_time.strftime('%Y-%m-%d %H:%M:%S.%f')}", 'info')

    while unlock_state['running']:
        current_time = get_synchronized_beijing_time(start_beijing_time, start_timestamp)
        time_diff = target_time - current_time

        if time_diff.total_seconds() > 1:
            sleep_time = min(1.0, time_diff.total_seconds() - 1)
            time.sleep(sleep_time)
        elif current_time >= target_time:
            add_log(f"It's time! {current_time.strftime('%H:%M:%S.%f')}. Starting requests...", 'success')
            break
        else:
            time.sleep(0.0001)

    return target_time

class HTTP11Session:
    def __init__(self):
        self.http = urllib3.PoolManager(
            maxsize=10,
            retries=True,
            timeout=urllib3.Timeout(connect=2.0, read=15.0),
            headers={}
        )

    def make_request(self, method, url, headers=None, body=None):
        try:
            request_headers = {}
            if headers:
                request_headers.update(headers)
                request_headers['Content-Type'] = 'application/json; charset=utf-8'

            if method == 'POST':
                if body is None:
                    body = '{"is_retry":true}'.encode('utf-8')
                request_headers['Content-Length'] = str(len(body))
                request_headers['Accept-Encoding'] = 'gzip, deflate, br'
                request_headers['User-Agent'] = 'okhttp/4.12.0'
                request_headers['Connection'] = 'keep-alive'

            response = self.http.request(
                method,
                url,
                headers=request_headers,
                body=body,
                preload_content=False
            )
            return response
        except Exception as e:
            add_log(f"Network error: {e}", 'error')
            return None

def check_unlock_status(session, cookie_value, device_id):
    try:
        url = "https://sgp-api.buy.mi.com/bbs/api/global/user/bl-switch/state"
        headers = {
            "Cookie": f"new_bbs_serviceToken={cookie_value};versionCode=500411;versionName=5.4.11;deviceId={device_id};"
        }

        response = session.make_request('GET', url, headers=headers)
        if response is None:
            add_log("Failed to retrieve unlock status", 'error')
            return False

        response_data = json.loads(response.data.decode('utf-8'))
        response.release_conn()

        if response_data.get("code") == 100004:
            add_log("Expired cookie! Please get a new one.", 'error')
            unlock_state['status'] = 'expired_cookie'
            return False

        data = response_data.get("data", {})
        is_pass = data.get("is_pass")
        button_state = data.get("button_state")
        deadline_format = data.get("deadline_format", "")

        if is_pass == 4:
            if button_state == 1:
                add_log("Account ready - requests will be sent", 'success')
                return True
            elif button_state == 2:
                add_log(f"Requests blocked until {deadline_format}", 'warning')
                unlock_state['status'] = 'blocked'
                unlock_state['result'] = f"Blocked until {deadline_format}"
                return False
            elif button_state == 3:
                add_log("Account created less than 30 days ago", 'warning')
                unlock_state['status'] = 'new_account'
                return False
        elif is_pass == 1:
            add_log(f"Request approved! Unblock until {deadline_format}", 'success')
            unlock_state['status'] = 'approved'
            unlock_state['result'] = f"Approved until {deadline_format}"
            return False
        else:
            add_log(f"Unknown state: {is_pass}", 'error')
            return False
    except Exception as e:
        add_log(f"Error checking status: {e}", 'error')
        return False

def run_unlock_process(cookie_value, feed_time_shift=1400):
    unlock_state['running'] = True
    unlock_state['logs'] = []
    unlock_state['status'] = 'running'
    unlock_state['result'] = None
    unlock_state['cookie'] = cookie_value
    unlock_state['device_id'] = generate_device_id()

    device_id = unlock_state['device_id']
    session = HTTP11Session()

    add_log("Starting unlock process...", 'info')
    add_log(f"Device ID: {device_id}", 'info')

    if not check_unlock_status(session, cookie_value, device_id):
        if unlock_state['status'] not in ['approved', 'blocked', 'new_account']:
            unlock_state['status'] = 'error'
        unlock_state['running'] = False
        return

    start_beijing_time = get_initial_beijing_time()
    if start_beijing_time is None:
        add_log("Failed to get Beijing time", 'error')
        unlock_state['status'] = 'error'
        unlock_state['running'] = False
        return

    start_timestamp = time.time()

    wait_until_target_time(start_beijing_time, start_timestamp, feed_time_shift)

    if not unlock_state['running']:
        add_log("Process stopped", 'warning')
        return

    url = "https://sgp-api.buy.mi.com/bbs/api/global/apply/bl-auth"
    headers = {
        "Cookie": f"new_bbs_serviceToken={cookie_value};versionCode=500411;versionName=5.4.11;deviceId={device_id};"
    }

    request_count = 0
    max_requests = 100

    while unlock_state['running'] and request_count < max_requests:
        request_count += 1
        request_time = get_synchronized_beijing_time(start_beijing_time, start_timestamp)
        add_log(f"Request #{request_count} sent at {request_time.strftime('%H:%M:%S.%f')}", 'info')

        response = session.make_request('POST', url, headers=headers)
        if response is None:
            continue

        response_time = get_synchronized_beijing_time(start_beijing_time, start_timestamp)
        add_log(f"Response received at {response_time.strftime('%H:%M:%S.%f')}", 'info')

        try:
            response_data = response.data
            response.release_conn()
            json_response = json.loads(response_data.decode('utf-8'))
            code = json_response.get("code")
            data = json_response.get("data", {})

            if code == 0:
                apply_result = data.get("apply_result")
                if apply_result == 1:
                    add_log("Request approved! Checking status...", 'success')
                    check_unlock_status(session, cookie_value, device_id)
                    unlock_state['running'] = False
                    break
                elif apply_result == 3:
                    deadline_format = data.get("deadline_format", "Not declared")
                    add_log(f"Quota reached. Try again at {deadline_format}", 'warning')
                    unlock_state['status'] = 'quota_reached'
                    unlock_state['result'] = f"Quota reached. Try at {deadline_format}"
                    unlock_state['running'] = False
                    break
                elif apply_result == 4:
                    deadline_format = data.get("deadline_format", "Not declared")
                    add_log(f"Account blocked until {deadline_format}", 'error')
                    unlock_state['status'] = 'blocked'
                    unlock_state['result'] = f"Blocked until {deadline_format}"
                    unlock_state['running'] = False
                    break
            elif code == 100001:
                add_log("Request rejected", 'warning')
                add_log(f"Response: {json_response}", 'info')
            elif code == 100003:
                add_log("Maybe approved! Checking status...", 'success')
                check_unlock_status(session, cookie_value, device_id)
                unlock_state['running'] = False
                break
            elif code is not None:
                add_log(f"Unknown status: {code}", 'warning')
                add_log(f"Response: {json_response}", 'info')
            else:
                add_log("No status code in response", 'error')
                add_log(f"Response: {json_response}", 'info')

        except json.JSONDecodeError:
            add_log("JSON decode error", 'error')
            add_log(f"Raw response: {response_data}", 'info')
        except Exception as e:
            add_log(f"Error processing response: {e}", 'error')
            continue

    if request_count >= max_requests:
        add_log("Max requests reached. Stopping.", 'warning')
        unlock_state['status'] = 'max_requests'

    unlock_state['running'] = False

# ============ Xiaomi Login Helper ============

def extract_token_from_callback(url):
    """Extract serviceToken from Xiaomi callback URL"""
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # Try different token formats
        if 'serviceToken' in params:
            return params['serviceToken'][0]
        if 'new_bbs_serviceToken' in params:
            return params['new_bbs_serviceToken'][0]
        if 'token' in params:
            return params['token'][0]
        if 'access_token' in params:
            return params['access_token'][0]

        # Check for code that can be exchanged
        if 'code' in params:
            return {'code': params['code'][0]}

        return None
    except:
        return None

def get_xiaomi_login_url():
    """Generate Xiaomi login URL for manual login flow"""
    params = {
        '_locale': 'en_IN',
        'checkSafePhone': 'false',
        'sid': '18n_bbs_global',
        'qs': '%3Fcallback%3Dhttps%253A%252F%252Fsgp-api.buy.mi.com%252Fbbs%252Fapi%252Fglobal%252Fuser%252Flogin-back%253Ffollowup%253Dhttps%25253A%25252F%25252Fnew-ams.c.mi.com%25252Fglobal%25252F%2526sign%253DM2UyYmIxZjc0MGQxODhkYjg3NWVlNDI4ZGQxNzk3ZmY3MThhYTVmNA%252C%252C',
        'callback': 'https://sgp-api.buy.mi.com/bbs/api/global/user/login-back?followup=https%3A%2F%2Fnew-ams.c.mi.com%2Fglobal%2F&sign=M2UyYmIxZjc0MGQxODhkYjg3NWVlNDI4ZGQxNzk3ZmY3MThhYTVmNA%2C%2C',
        '_sign': '%2BnjnarFZlvmk2A9UJro3U%2BS0lbc%3D',
        'serviceParam': '%7B%22checkSafePhone%22%3Afalse%2C%22checkSafeAddress%22%3Afalse%2C%22lsrp_score%22%3A0.0%7D',
        'showActiveX': 'false',
        'theme': '',
        'needTheme': 'false',
        'bizDeviceType': ''
    }

    query = urllib.parse.urlencode(params)
    return f"https://account.xiaomi.com/fe/service/login/password?{query}"

# ============ API Routes ============

@app.route('/')
def index():
    try:
        return render_template('index.html')
    except:
        # Fallback: serve embedded HTML if template not found
        return serve_fallback_html()

@app.route('/api/get-login-url')
def get_login_url():
    """Get the Xiaomi login URL for the frontend to open"""
    url = get_xiaomi_login_url()
    return jsonify({
        'login_url': url,
        'instructions': 'Login and then copy the callback URL or cookie value'
    })

@app.route('/api/extract-token', methods=['POST'])
def extract_token():
    """Extract token from callback URL or raw cookie string"""
    data = request.json
    url = data.get('url', '')
    cookie_str = data.get('cookie', '')

    token = None

    # Try to extract from URL
    if url:
        token = extract_token_from_callback(url)

    # Try to extract from cookie string
    if not token and cookie_str:
        # Parse cookie string
        if 'new_bbs_serviceToken=' in cookie_str:
            start = cookie_str.find('new_bbs_serviceToken=') + len('new_bbs_serviceToken=')
            end = cookie_str.find(';', start)
            if end == -1:
                end = len(cookie_str)
            token = cookie_str[start:end]
        elif 'serviceToken=' in cookie_str:
            start = cookie_str.find('serviceToken=') + len('serviceToken=')
            end = cookie_str.find(';', start)
            if end == -1:
                end = len(cookie_str)
            token = cookie_str[start:end]

    if token:
        unlock_state['cookie'] = token if isinstance(token, str) else None
        return jsonify({
            'success': True,
            'token': token if isinstance(token, str) else None,
            'code': token.get('code') if isinstance(token, dict) else None,
            'message': 'Token extracted successfully'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Could not extract token. Please paste the new_bbs_serviceToken value directly.'
        })

@app.route('/api/verify-token', methods=['POST'])
def verify_token():
    """Verify if the token is valid by checking account status"""
    data = request.json
    token = data.get('token', '').strip()

    if not token:
        return jsonify({'valid': False, 'message': 'Token is empty'})

    device_id = generate_device_id()
    session = HTTP11Session()

    try:
        url = "https://sgp-api.buy.mi.com/bbs/api/global/user/bl-switch/state"
        headers = {
            "Cookie": f"new_bbs_serviceToken={token};versionCode=500411;versionName=5.4.11;deviceId={device_id};"
        }

        response = session.make_request('GET', url, headers=headers)
        if response is None:
            return jsonify({'valid': False, 'message': 'Network error'})

        response_data = json.loads(response.data.decode('utf-8'))
        response.release_conn()

        if response_data.get("code") == 100004:
            return jsonify({'valid': False, 'message': 'Expired token'})

        data = response_data.get("data", {})
        is_pass = data.get("is_pass")
        button_state = data.get("button_state")
        deadline_format = data.get("deadline_format", "")

        user_info = {
            'is_pass': is_pass,
            'button_state': button_state,
            'deadline_format': deadline_format
        }
        unlock_state['user_info'] = user_info

        if is_pass == 1:
            return jsonify({
                'valid': True, 
                'message': f'Already approved until {deadline_format}',
                'user_info': user_info
            })
        elif is_pass == 4:
            if button_state == 1:
                return jsonify({
                    'valid': True, 
                    'message': 'Account ready for unlock request',
                    'user_info': user_info
                })
            elif button_state == 2:
                return jsonify({
                    'valid': True, 
                    'message': f'Blocked until {deadline_format}',
                    'user_info': user_info
                })
            elif button_state == 3:
                return jsonify({
                    'valid': True, 
                    'message': 'Account less than 30 days old',
                    'user_info': user_info
                })

        return jsonify({'valid': True, 'message': 'Token valid', 'user_info': user_info})

    except Exception as e:
        return jsonify({'valid': False, 'message': f'Error: {str(e)}'})

@app.route('/api/start', methods=['POST'])
def start_unlock():
    if unlock_state['running']:
        return jsonify({'error': 'Already running'}), 400

    data = request.json
    cookie = data.get('cookie', '').strip()
    feed_time_shift = data.get('feed_time_shift', 1400)

    if not cookie:
        return jsonify({'error': 'Cookie is required'}), 400

    thread = threading.Thread(target=run_unlock_process, args=(cookie, feed_time_shift))
    thread.daemon = True
    thread.start()

    return jsonify({'message': 'Started', 'device_id': generate_device_id()})

@app.route('/api/stop', methods=['POST'])
def stop_unlock():
    unlock_state['running'] = False
    add_log("Stop requested by user", 'warning')
    return jsonify({'message': 'Stopping...'})

@app.route('/api/status')
def get_status():
    return jsonify({
        'running': unlock_state['running'],
        'status': unlock_state['status'],
        'result': unlock_state['result'],
        'target_time': unlock_state['target_time'],
        'logs': unlock_state['logs'][-50:],
        'device_id': unlock_state['device_id'],
        'user_info': unlock_state['user_info']
    })

@app.route('/api/logs')
def get_logs():
    return jsonify({'logs': unlock_state['logs'][-100:]})

@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    unlock_state['logs'] = []
    return jsonify({'message': 'Logs cleared'})



def serve_fallback_html():
    """Serve HTML directly without template file - foolproof for Render"""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HyperOS Bootloader Unlocker</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #e0e0e0; min-height: 100vh; padding: 20px; }
        .container { max-width: 900px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; padding: 20px; }
        .header h1 { font-size: 2.5em; color: #ff6b6b; margin-bottom: 10px; text-shadow: 0 0 20px rgba(255, 107, 107, 0.3); }
        .header p { color: #a0a0a0; font-size: 1.1em; }
        .card { background: rgba(255, 255, 255, 0.05); border-radius: 15px; padding: 25px; margin-bottom: 20px; border: 1px solid rgba(255, 255, 255, 0.1); backdrop-filter: blur(10px); }
        .card h2 { color: #4ecdc4; margin-bottom: 15px; font-size: 1.3em; }
        .login-tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .login-tab { flex: 1; padding: 12px; background: rgba(255, 255, 255, 0.05); border: 2px solid rgba(255, 255, 255, 0.1); border-radius: 8px; color: #e0e0e0; cursor: pointer; transition: all 0.3s; text-align: center; font-weight: 600; }
        .login-tab:hover { background: rgba(255, 255, 255, 0.1); }
        .login-tab.active { border-color: #4ecdc4; background: rgba(78, 205, 196, 0.1); color: #4ecdc4; }
        .login-panel { display: none; }
        .login-panel.active { display: block; }
        .input-group { margin-bottom: 15px; }
        .input-group label { display: block; margin-bottom: 8px; color: #b0b0b0; font-weight: 500; }
        .input-group input, .input-group textarea { width: 100%; padding: 12px 15px; border: 2px solid rgba(255, 255, 255, 0.1); border-radius: 8px; background: rgba(0, 0, 0, 0.3); color: #fff; font-size: 1em; transition: all 0.3s; }
        .input-group input:focus, .input-group textarea:focus { outline: none; border-color: #4ecdc4; box-shadow: 0 0 15px rgba(78, 205, 196, 0.2); }
        .input-group textarea { resize: vertical; min-height: 80px; font-family: monospace; }
        .btn { padding: 12px 30px; border: none; border-radius: 8px; font-size: 1em; font-weight: 600; cursor: pointer; transition: all 0.3s; margin-right: 10px; margin-bottom: 10px; display: inline-flex; align-items: center; gap: 8px; }
        .btn-start { background: linear-gradient(135deg, #ff6b6b, #ee5a5a); color: white; }
        .btn-start:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(255, 107, 107, 0.4); }
        .btn-start:disabled { background: #555; cursor: not-allowed; transform: none; box-shadow: none; }
        .btn-stop { background: linear-gradient(135deg, #ffd93d, #f9ca24); color: #1a1a2e; }
        .btn-stop:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(255, 217, 61, 0.4); }
        .btn-login { background: linear-gradient(135deg, #4ecdc4, #44a08d); color: white; }
        .btn-login:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(78, 205, 196, 0.4); }
        .btn-verify { background: linear-gradient(135deg, #667eea, #764ba2); color: white; }
        .btn-verify:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4); }
        .btn-help { background: rgba(255, 255, 255, 0.1); color: #e0e0e0; }
        .btn-help:hover { background: rgba(255, 255, 255, 0.2); }
        .status-badge { display: inline-block; padding: 5px 15px; border-radius: 20px; font-size: 0.9em; font-weight: 600; margin-bottom: 15px; }
        .status-idle { background: rgba(160, 160, 160, 0.2); color: #a0a0a0; }
        .status-running { background: rgba(78, 205, 196, 0.2); color: #4ecdc4; }
        .status-success { background: rgba(107, 255, 107, 0.2); color: #6bff6b; }
        .status-error { background: rgba(255, 107, 107, 0.2); color: #ff6b6b; }
        .status-warning { background: rgba(255, 217, 61, 0.2); color: #ffd93d; }
        .countdown { font-size: 2em; text-align: center; color: #4ecdc4; margin: 20px 0; font-family: 'Courier New', monospace; }
        .countdown-label { text-align: center; color: #a0a0a0; font-size: 0.9em; }
        .logs-container { background: rgba(0, 0, 0, 0.4); border-radius: 10px; padding: 15px; max-height: 400px; overflow-y: auto; font-family: 'Courier New', monospace; font-size: 0.9em; }
        .log-entry { padding: 5px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }
        .log-time { color: #666; margin-right: 10px; }
        .log-info { color: #e0e0e0; }
        .log-success { color: #6bff6b; }
        .log-error { color: #ff6b6b; }
        .log-warning { color: #ffd93d; }
        .result-box { background: rgba(78, 205, 196, 0.1); border: 2px solid #4ecdc4; border-radius: 10px; padding: 20px; margin-top: 20px; text-align: center; }
        .result-box h3 { color: #4ecdc4; margin-bottom: 10px; }
        .result-box p { font-size: 1.2em; color: #e0e0e0; }
        .token-display { background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(78, 205, 196, 0.3); border-radius: 8px; padding: 15px; margin: 15px 0; word-break: break-all; font-family: monospace; font-size: 0.85em; color: #4ecdc4; }
        .user-info { background: rgba(78, 205, 196, 0.05); border: 1px solid rgba(78, 205, 196, 0.2); border-radius: 8px; padding: 15px; margin: 15px 0; }
        .user-info h4 { color: #4ecdc4; margin-bottom: 10px; }
        .user-info-item { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }
        .user-info-item:last-child { border-bottom: none; }
        .user-info-label { color: #a0a0a0; }
        .user-info-value { color: #e0e0e0; font-weight: 600; }
        .alert { padding: 12px 15px; border-radius: 8px; margin-bottom: 15px; display: none; }
        .alert-success { background: rgba(107, 255, 107, 0.1); border: 1px solid rgba(107, 255, 107, 0.3); color: #6bff6b; }
        .alert-error { background: rgba(255, 107, 107, 0.1); border: 1px solid rgba(255, 107, 107, 0.3); color: #ff6b6b; }
        .alert-warning { background: rgba(255, 217, 61, 0.1); border: 1px solid rgba(255, 217, 61, 0.3); color: #ffd93d; }
        .alert-info { background: rgba(78, 205, 196, 0.1); border: 1px solid rgba(78, 205, 196, 0.3); color: #4ecdc4; }
        .alert.show { display: block; }
        .progress-bar { width: 100%; height: 8px; background: rgba(255, 255, 255, 0.1); border-radius: 4px; overflow: hidden; margin: 15px 0; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #4ecdc4, #ff6b6b); transition: width 0.3s; width: 0%; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.8); z-index: 1000; justify-content: center; align-items: center; }
        .modal-content { background: #1a1a2e; border-radius: 15px; padding: 30px; max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto; border: 1px solid rgba(255, 255, 255, 0.1); }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modal-header h2 { color: #4ecdc4; }
        .close-btn { background: none; border: none; color: #e0e0e0; font-size: 1.5em; cursor: pointer; }
        .steps-list { list-style: none; }
        .steps-list li { padding: 10px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.1); color: #b0b0b0; }
        .steps-list li strong { color: #4ecdc4; }
        .steps-list li code { background: rgba(0, 0, 0, 0.3); padding: 2px 6px; border-radius: 4px; color: #ffd93d; }
        @media (max-width: 600px) { .header h1 { font-size: 1.8em; } .countdown { font-size: 1.5em; } .login-tabs { flex-direction: column; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔓 HyperOS Bootloader Unlocker</h1>
            <p>Automated bootloader unlock request with auto-login</p>
        </div>
        <div class="card">
            <h2>🔐 Authentication</h2>
            <div class="login-tabs">
                <div class="login-tab active" onclick="switchTab('auto')">🌐 Auto Login</div>
                <div class="login-tab" onclick="switchTab('manual')">⌨️ Manual Token</div>
            </div>
            <div class="login-panel active" id="auto-panel">
                <p style="color: #a0a0a0; margin-bottom: 15px;">Click the button below to open Xiaomi login. After logging in, copy the callback URL or cookie and paste it here.</p>
                <button class="btn btn-login" onclick="openXiaomiLogin()">🌐 Open Xiaomi Login Page</button>
                <div class="input-group" style="margin-top: 15px;">
                    <label>Paste Callback URL or Cookie here:</label>
                    <textarea id="auto-cookie-input" placeholder="Paste the full callback URL after login, or paste the cookie string with new_bbs_serviceToken..."></textarea>
                </div>
                <button class="btn btn-verify" onclick="extractToken()">🔍 Extract Token</button>
                <div id="extract-alert" class="alert"></div>
                <div id="token-display" class="token-display" style="display: none;">
                    <strong>Extracted Token:</strong><br><span id="extracted-token"></span>
                </div>
            </div>
            <div class="login-panel" id="manual-panel">
                <div class="input-group">
                    <label>Cookie: new_bbs_serviceToken</label>
                    <textarea id="manual-cookie-input" placeholder="Paste your new_bbs_serviceToken cookie value here..."></textarea>
                </div>
            </div>
            <div id="user-info" class="user-info" style="display: none;">
                <h4>👤 Account Status</h4>
                <div id="user-info-content"></div>
            </div>
            <button class="btn btn-verify" onclick="verifyToken()">✅ Verify Token & Check Status</button>
            <div id="verify-alert" class="alert"></div>
        </div>
        <div class="card">
            <h2>⚙️ Configuration</h2>
            <div class="input-group">
                <label for="phaseShift">Phase Shift (ms) - Advanced</label>
                <input type="number" id="phaseShift" value="1400" min="0" max="5000">
                <small style="color: #666;">Time offset before Beijing midnight to start requests</small>
            </div>
            <div style="margin-top: 20px;">
                <button class="btn btn-start" id="startBtn" onclick="startUnlock()">🚀 Start Unlock Process</button>
                <button class="btn btn-stop" id="stopBtn" onclick="stopUnlock()" disabled>⏹️ Stop</button>
                <button class="btn btn-help" onclick="showHelp()">❓ How to use</button>
            </div>
        </div>
        <div class="card" id="statusCard" style="display: none;">
            <h2>📊 Status</h2>
            <div id="statusBadge" class="status-badge status-idle">Idle</div>
            <div class="countdown-label">Time until next Beijing midnight:</div>
            <div class="countdown" id="countdown">00:00:00</div>
            <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
            <div id="resultBox" class="result-box" style="display: none;">
                <h3>🎉 Result</h3>
                <p id="resultText"></p>
            </div>
        </div>
        <div class="card">
            <h2>📝 Logs</h2>
            <div class="logs-container" id="logsContainer">
                <div class="log-entry"><span class="log-time">--:--:--</span><span class="log-info">Waiting to start...</span></div>
            </div>
            <button class="btn btn-help" onclick="clearLogs()" style="margin-top: 10px;">🗑️ Clear Logs</button>
        </div>
    </div>
    <div class="modal" id="helpModal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>How to use Auto Login</h2>
                <button class="close-btn" onclick="closeHelp()">&times;</button>
            </div>
            <ol class="steps-list">
                <li><strong>1.</strong> Click <strong>"Open Xiaomi Login Page"</strong> button</li>
                <li><strong>2.</strong> Login with your Xiaomi account in the new tab</li>
                <li><strong>3.</strong> After login, you'll be redirected to a callback URL</li>
                <li><strong>4.</strong> <strong>Copy the entire URL</strong> from the address bar</li>
                <li><strong>5.</strong> Paste it in the text box and click <strong>"Extract Token"</strong></li>
                <li><strong>6.</strong> Click <strong>"Verify Token"</strong> to check account status</li>
                <li><strong>7.</strong> Click <strong>"Start Unlock Process"</strong> and wait</li>
            </ol>
            <div style="margin-top: 20px; padding: 15px; background: rgba(255, 107, 107, 0.1); border-radius: 8px; border: 1px solid rgba(255, 107, 107, 0.3);">
                <strong style="color: #ff6b6b;">⚠️ Alternative Method:</strong><br>
                If auto-extraction fails, manually copy the <code>new_bbs_serviceToken</code> cookie value from browser DevTools (Application → Cookies) and paste it in the Manual Token tab.
            </div>
        </div>
    </div>
    <script>
        let statusInterval, countdownInterval, isRunning = false, currentToken = '', currentTab = 'auto';
        function switchTab(tab) {
            currentTab = tab;
            document.querySelectorAll('.login-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.login-panel').forEach(p => p.classList.remove('active'));
            if (tab === 'auto') { document.querySelectorAll('.login-tab')[0].classList.add('active'); document.getElementById('auto-panel').classList.add('active'); }
            else { document.querySelectorAll('.login-tab')[1].classList.add('active'); document.getElementById('manual-panel').classList.add('active'); }
        }
        function getCookieInput() { return currentTab === 'auto' ? document.getElementById('auto-cookie-input').value.trim() : document.getElementById('manual-cookie-input').value.trim(); }
        function setCookieInput(value) { if (currentTab === 'auto') document.getElementById('auto-cookie-input').value = value; else document.getElementById('manual-cookie-input').value = value; }
        async function openXiaomiLogin() {
            try { const response = await fetch('/api/get-login-url'); const data = await response.json(); if (data.login_url) window.open(data.login_url, '_blank', 'width=800,height=600'); }
            catch (e) { showAlert('extract-alert', 'error', 'Failed to get login URL: ' + e.message); }
        }
        async function extractToken() {
            const input = getCookieInput();
            if (!input) { showAlert('extract-alert', 'error', 'Please paste the callback URL or cookie first!'); return; }
            try {
                const response = await fetch('/api/extract-token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: input, cookie: input }) });
                const data = await response.json();
                if (data.success) {
                    currentToken = data.token || data.code;
                    showAlert('extract-alert', 'success', data.message);
                    if (data.token) { document.getElementById('token-display').style.display = 'block'; document.getElementById('extracted-token').textContent = data.token; setCookieInput(data.token); }
                } else { showAlert('extract-alert', 'error', data.message); document.getElementById('token-display').style.display = 'none'; }
            } catch (e) { showAlert('extract-alert', 'error', 'Error: ' + e.message); }
        }
        async function verifyToken() {
            const token = getCookieInput();
            if (!token) { showAlert('verify-alert', 'error', 'Please enter or extract a token first!'); return; }
            showAlert('verify-alert', 'info', 'Verifying token...');
            try {
                const response = await fetch('/api/verify-token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: token }) });
                const data = await response.json();
                if (data.valid) { showAlert('verify-alert', 'success', data.message); currentToken = token; if (data.user_info) displayUserInfo(data.user_info); }
                else { showAlert('verify-alert', 'error', data.message); }
            } catch (e) { showAlert('verify-alert', 'error', 'Error: ' + e.message); }
        }
        function displayUserInfo(info) {
            const container = document.getElementById('user-info');
            const content = document.getElementById('user-info-content');
            const stateMap = { 1: 'Approved', 4: 'Pending' };
            const buttonMap = { 1: 'Ready', 2: 'Blocked', 3: 'New Account' };
            content.innerHTML = `
                <div class="user-info-item"><span class="user-info-label">Status:</span><span class="user-info-value">${stateMap[info.is_pass] || 'Unknown'}</span></div>
                <div class="user-info-item"><span class="user-info-label">Button State:</span><span class="user-info-value">${buttonMap[info.button_state] || 'Unknown'}</span></div>
                ${info.deadline_format ? `<div class="user-info-item"><span class="user-info-label">Deadline:</span><span class="user-info-value">${info.deadline_format}</span></div>` : ''}
            `;
            container.style.display = 'block';
        }
        async function startUnlock() {
            const token = currentToken || getCookieInput();
            const phaseShift = document.getElementById('phaseShift').value;
            if (!token) { alert('Please verify a token first!'); return; }
            try {
                const response = await fetch('/api/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ cookie: token, feed_time_shift: parseInt(phaseShift) }) });
                if (response.ok) {
                    isRunning = true;
                    document.getElementById('startBtn').disabled = true;
                    document.getElementById('stopBtn').disabled = false;
                    document.getElementById('statusCard').style.display = 'block';
                    updateStatus(); statusInterval = setInterval(updateStatus, 1000); startCountdown();
                } else { const data = await response.json(); alert(data.error || 'Failed to start'); }
            } catch (e) { alert('Error: ' + e.message); }
        }
        async function stopUnlock() {
            try { await fetch('/api/stop', { method: 'POST' }); isRunning = false; document.getElementById('startBtn').disabled = false; document.getElementById('stopBtn').disabled = true; clearInterval(statusInterval); clearInterval(countdownInterval); }
            catch (e) { console.error(e); }
        }
        async function clearLogs() {
            try { await fetch('/api/clear-logs', { method: 'POST' }); document.getElementById('logsContainer').innerHTML = '<div class="log-entry"><span class="log-time">--:--:--</span><span class="log-info">Logs cleared...</span></div>'; }
            catch (e) { console.error(e); }
        }
        async function updateStatus() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                updateLogs(data.logs); updateStatusBadge(data.status);
                if (data.target_time) document.getElementById('countdown').dataset.targetTime = data.target_time;
                if (data.result) { document.getElementById('resultBox').style.display = 'block'; document.getElementById('resultText').textContent = data.result; }
                if (!data.running && isRunning) { isRunning = false; document.getElementById('startBtn').disabled = false; document.getElementById('stopBtn').disabled = true; clearInterval(statusInterval); clearInterval(countdownInterval); }
            } catch (e) { console.error(e); }
        }
        function updateLogs(logs) {
            const container = document.getElementById('logsContainer');
            container.innerHTML = logs.map(log => `<div class="log-entry"><span class="log-time">${log.time}</span><span class="log-${log.level}">${log.message}</span></div>`).join('');
            container.scrollTop = container.scrollHeight;
        }
        function updateStatusBadge(status) {
            const badge = document.getElementById('statusBadge');
            const statusMap = { 'idle': { class: 'status-idle', text: 'Idle' }, 'running': { class: 'status-running', text: 'Running' }, 'approved': { class: 'status-success', text: 'Approved!' }, 'error': { class: 'status-error', text: 'Error' }, 'blocked': { class: 'status-warning', text: 'Blocked' }, 'quota_reached': { class: 'status-warning', text: 'Quota Reached' }, 'max_requests': { class: 'status-warning', text: 'Max Requests' }, 'expired_cookie': { class: 'status-error', text: 'Expired Cookie' }, 'new_account': { class: 'status-warning', text: 'New Account' } };
            const info = statusMap[status] || statusMap['idle'];
            badge.className = 'status-badge ' + info.class; badge.textContent = info.text;
        }
        function startCountdown() {
            countdownInterval = setInterval(() => {
                const targetTimeStr = document.getElementById('countdown').dataset.targetTime;
                if (!targetTimeStr) return;
                const now = new Date();
                const beijingTime = new Date(now.toLocaleString('en-US', { timeZone: 'Asia/Shanghai' }));
                const targetTime = new Date(targetTimeStr);
                let diff = targetTime - beijingTime; if (diff < 0) diff = 0;
                const hours = Math.floor(diff / (1000 * 60 * 60));
                const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((diff % (1000 * 60)) / 1000);
                document.getElementById('countdown').textContent = `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
                const totalSeconds = 24 * 60 * 60;
                const elapsedSeconds = (beijingTime.getHours() * 3600) + (beijingTime.getMinutes() * 60) + beijingTime.getSeconds();
                const progress = (elapsedSeconds / totalSeconds) * 100;
                document.getElementById('progressFill').style.width = progress + '%';
            }, 1000);
        }
        function showAlert(elementId, type, message) {
            const alert = document.getElementById(elementId);
            alert.className = 'alert alert-' + type + ' show'; alert.textContent = message;
            setTimeout(() => { alert.classList.remove('show'); }, 5000);
        }
        function showHelp() { document.getElementById('helpModal').style.display = 'flex'; }
        function closeHelp() { document.getElementById('helpModal').style.display = 'none'; }
        document.getElementById('helpModal').addEventListener('click', function(e) { if (e.target === this) closeHelp(); });
    </script>
</body>
</html>"""

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=False)
