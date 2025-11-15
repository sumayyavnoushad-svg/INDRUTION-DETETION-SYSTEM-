#!/usr/bin/env python3
import socket
import threading
import paramiko
import logging
import json
import hashlib
import smtplib
from email.message import EmailMessage
from datetime import datetime
import pytz
import os
import csv

# === CONFIG ===
HOST_KEY = paramiko.RSAKey.generate(2048)
LOG_FILE = '/opt/ids-project/custom_attacks.json'
CSV_FILE = '/opt/ids-project/alerts.csv'
GMAIL_USER = 'ajassumayya77@gmail.com'
GMAIL_APP = 'sexryvkckiouoxhe'
ALERT_TO = 'sumayyavnoushad@gmail.com'
IST = pytz.timezone('Asia/Kolkata')

# Ensure files exist
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)
if not os.path.exists(LOG_FILE):
    open(LOG_FILE, 'a').close()
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, 'a') as f:
        csv.writer(f).writerow(['Timestamp','Src_IP','Session_ID','Payload_MD5','Flagged'])

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

class HoneypotSSH(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.username = None
        self.password = None
        self.commands = []

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        self.log_attack("login_attempt")
        self.send_email("Login Attempt")
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode(errors='ignore').strip()
        self.commands.append(cmd)
        self.log_attack("command", cmd)
        channel.send(f"bash: {cmd}: command not found\r\n")
        return True

    def log_attack(self, event_type, extra=None):
        try:
            log_entry = {
                "timestamp": datetime.now(IST).isoformat(),
                "src_ip": self.client_ip,
                "username": self.username or "?",
                "password": self.password or "?",
                "event": event_type,
                "command": extra or ""
            }
            # Write to JSON
            with open(LOG_FILE, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            # Write to CSV (for dashboard)
            session_id = f"cust_{hashlib.md5(self.client_ip.encode()).hexdigest()[:8]}"
            md5hash = hashlib.md5(json.dumps(log_entry).encode()).hexdigest()
            with open(CSV_FILE, 'a') as f:
                csv.writer(f).writerow([
                    datetime.now(IST).isoformat(),
                    self.client_ip,
                    session_id,
                    md5hash,
                    "Malicious"
                ])
        except Exception as e:
            logging.error(f"LOG FAILED: {e}")

    def send_email(self, action):
        try:
            msg = EmailMessage()
            msg['From'] = GMAIL_USER
            msg['To'] = ALERT_TO
            msg['Subject'] = f'CUSTOM HONEYPOT: {action} from {self.client_ip}'
            body = f"""
CUSTOM HONEYPOT ALERT
IP: {self.client_ip}
User: {self.username or '?'}
Pass: {self.password or '?'}
Action: {action}
Time: {datetime.now(IST).strftime('%Y-%m-%d %H:%M:%S IST')}
"""
            msg.set_content(body)
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10) as server:
                server.login(GMAIL_USER, GMAIL_APP)
                server.send_message(msg)
        except Exception as e:
            logging.error(f"EMAIL FAILED: {e}")

def handle_client(client_socket, addr):
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        server = HoneypotSSH(addr[0])
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is None:
            return
        server.event.wait(10)
        if not server.event.is_set():
            return
        channel.send("\r\nWelcome to Ubuntu 20.04 (Fake Shell)\r\n$ ")
        while True:
            try:
                command = channel.recv(1024).decode(errors='ignore').strip()
                if not command or command in ['exit', 'quit', 'logout']:
                    break
                server.commands.append(command)
                server.log_attack("command", command)
                channel.send(f"\r\n$ ")
            except:
                break
        channel.close()
    except Exception as e:
        logging.error(f"CLIENT ERROR: {e}")
    finally:
        try:
            client_socket.close()
        except:
            pass

def start_honeypot():
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', 2223))
        server_socket.listen(100)
        logging.info("Custom Honeypot STARTED on port 2223")
        while True:
            client_socket, addr = server_socket.accept()
            logging.info(f"Connection from {addr[0]}")
            threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True).start()
    except Exception as e:
        logging.critical(f"HONEYPOT CRASH: {e}")
        raise

if __name__ == '__main__':
    start_honeypot()
