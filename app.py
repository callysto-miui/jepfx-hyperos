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

app = Flask(__name__)
app.secret_key = 'hyperos-unlocker-secret-key-change-this'
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
    return render_template('index.html')

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=False)
