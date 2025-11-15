#!/usr/bin/env python3
import json, os, time, subprocess, logging, hashlib
from datetime import datetime
import pytz

COWRIE_JSON = '/opt/cowrie-env/var/log/cowrie/cowrie.json'
CUSTOM_JSON = '/opt/ids-project/custom_attacks.json'
CSV_FILE = '/opt/ids-project/alerts.csv'
SESSION_DB = '/opt/ids-project/.seen_sessions'
BLOCK_THRESHOLD = 4
CHAIN = "COWRIE_BLOCK"
IST = pytz.timezone('Asia/Kolkata')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === LOAD PERSISTENT STATE ===
seen_sessions = set()
ip_counter = {}
blocked_ips = set()

if os.path.exists(SESSION_DB):
    with open(SESSION_DB, 'r') as f:
        seen_sessions = set(line.strip() for line in f if line.strip())

def save_sessions():
    with open(SESSION_DB, 'w') as f:
        f.write('\n'.join(seen_sessions))

def ensure_chain():
    try:
        subprocess.run(['iptables', '-L', CHAIN, '-n'], capture_output=True, check=True)
    except:
        subprocess.run(['iptables', '-N', CHAIN], check=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '2222', '-j', CHAIN], check=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '2223', '-j', CHAIN], check=True)
        logger.info("COWRIE_BLOCK chain created")

def block_ip(ip):
    if ip in ['127.0.0.1', '::1', '13.51.233.254']: return
    try:
        result = subprocess.run(['iptables', '-L', CHAIN, '-n'], capture_output=True, text=True)
        if ip in result.stdout: return
        subprocess.run(['iptables', '-A', CHAIN, '-s', ip, '-j', 'DROP'], check=True)
        blocked_ips.add(ip)
        logger.info(f"IP_BLOCKED → {ip}")
        with open('/var/log/cowrie_block.log', 'a') as f:
            f.write(f"{datetime.now(IST).isoformat()} BLOCKED {ip}\n")
    except Exception as e:
        logger.error(f"BLOCK_FAILED → {ip} | {e}")

def unblock_ip(ip):
    try:
        subprocess.run(['iptables', '-D', CHAIN, '-s', ip, '-j', 'DROP'], check=True)
        blocked_ips.discard(ip)
        # === RESET COUNTER & SESSIONS ===
        if ip in ip_counter:
            del ip_counter[ip]
        # Remove all sessions from this IP
        sessions_to_remove = [s for s in seen_sessions if s.startswith(f"cust_{hashlib.md5(ip.encode()).hexdigest()[:8]}") or ip in s]
        for s in sessions_to_remove:
            seen_sessions.discard(s)
        save_sessions()
        logger.info(f"IP_UNBLOCKED → {ip} | Counter reset")
    except Exception as e:
        logger.warning(f"UNBLOCK_FAILED → {ip} | {e}")

ensure_chain()

# === MONITOR IPTABLES FOR UNBLOCKS ===
last_iptables = ""
cowrie_pos = 0
custom_pos = 0

while True:
    try:
        # === CHECK IPTABLES FOR UNBLOCKS ===
        current_iptables = subprocess.run(['iptables', '-L', CHAIN, '-n'], capture_output=True, text=True).stdout
        if current_iptables != last_iptables:
            current_ips = {line.split()[3] for line in current_iptables.splitlines() if line.startswith('DROP')}
            for ip in list(blocked_ips):
                if ip not in current_ips:
                    unblock_ip(ip)
            last_iptables = current_iptables

        # === COWRIE LOG ===
        if os.path.exists(COWRIE_JSON):
            with open(COWRIE_JSON, 'r') as f:
                f.seek(cowrie_pos)
                lines = f.readlines()
                if lines:
                    for line in lines:
                        try:
                            data = json.loads(line.strip())
                            sess = data.get('session')
                            if sess in seen_sessions: continue
                            if data.get('eventid') in ['cowrie.login.failed', 'cowrie.login.success']:
                                seen_sessions.add(sess); save_sessions()
                                ip = data.get('src_ip', 'unknown')
                                if ip in blocked_ips: continue
                                ip_counter[ip] = ip_counter.get(ip, 0) + 1
                                logger.info(f"COWRIE ATTEMPT → {ip} | Count: {ip_counter[ip]}")
                                if ip_counter[ip] >= BLOCK_THRESHOLD:
                                    block_ip(ip)
                        except: continue
                    cowrie_pos = f.tell()

        # === CUSTOM LOG ===
        if os.path.exists(CUSTOM_JSON):
            with open(CUSTOM_JSON, 'r') as f:
                f.seek(custom_pos)
                lines = f.readlines()
                if lines:
                    for line in lines:
                        try:
                            data = json.loads(line.strip())
                            ip = data.get('src_ip')
                            if not ip or ip in blocked_ips: continue
                            fake_sess = f"cust_{hashlib.md5(ip.encode()).hexdigest()[:8]}_{int(time.time())}"
                            if fake_sess in seen_sessions: continue
                            if data.get('event') == 'login_attempt':
                                seen_sessions.add(fake_sess); save_sessions()
                                ip_counter[ip] = ip_counter.get(ip, 0) + 1
                                logger.info(f"CUSTOM ATTEMPT → {ip} | Count: {ip_counter[ip]}")
                                if ip_counter[ip] >= BLOCK_THRESHOLD:
                                    block_ip(ip)
                        except: continue
                    custom_pos = f.tell()

        time.sleep(1)
    except Exception as e:
        logger.error(f"SCRIPT CRASH: {e}")
        time.sleep(5)
