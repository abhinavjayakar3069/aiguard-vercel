from http.server import BaseHTTPRequestHandler
import json
import os
import smtplib
from email.message import EmailMessage


def send_security_mail(subject, body):
    sender_email = os.environ.get("SENDER_EMAIL")
    app_password = os.environ.get("APP_PASSWORD")

    if not sender_email or not app_password:
        # Email not configured -> skip silently, don't crash the request
        return

    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = sender_email

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, app_password)
        server.send_message(msg)
        server.quit()
    except Exception:
        # Don't leak SMTP errors back to the client
        pass


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(content_length) if content_length else b'{}'

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {}

        ip = data.get("ip", "unknown")
        pwd = data.get("password", "")
        failed_count = int(data.get("failed_count", 0))

        admin_password = os.environ.get("ADMIN_PASSWORD", "")

        if pwd and pwd == admin_password:
            attempt_type, status, action = "Success", "Safe", "Authorized"
            send_security_mail("Alert: Authorized Login", f"Successful login from IP: {ip}")
        else:
            attempt_type, status = "Failed", "Suspicious"
            action = "Blocked" if failed_count >= 5 else "Warning"
            if action == "Blocked":
                send_security_mail("CRITICAL ALERT: IP Blocked", f"IP {ip} has been BLOCKED due to multiple failed attempts.")

        response = {
            "attempt_type": attempt_type,
            "status": status,
            "action": action,
        }

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
