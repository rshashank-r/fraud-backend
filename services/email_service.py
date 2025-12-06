from flask_mail import Mail, Message
import random
import os
import threading
from datetime import datetime

# --- HELPER: HTML WRAPPER ---
def generate_otp(length=6):
    return "".join([str(random.randint(0, 9)) for _ in range(length)])

def get_email_style():
    return """
    <style>
        body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f4f7; color: #555; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
        .header { background: #000; padding: 20px; text-align: center; }
        .header h1 { color: #fff; margin: 0; font-size: 20px; letter-spacing: 1px; }
        .content { padding: 30px; }
        .alert-box { background: #fff5f5; border-left: 4px solid #e53e3e; padding: 15px; margin-bottom: 20px; border-radius: 4px; }
        .info-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .info-table td { padding: 8px; border-bottom: 1px solid #eee; }
        .label { font-weight: bold; color: #333; width: 140px; }
        .footer { background: #f9f9f9; padding: 15px; text-align: center; font-size: 12px; color: #999; }
        .otp-code { font-size: 32px; font-weight: bold; color: #e53e3e; letter-spacing: 5px; text-align: center; margin: 20px 0; }
        .btn { display: inline-block; padding: 10px 20px; background: #e53e3e; color: #fff; text-decoration: none; border-radius: 5px; font-weight: bold; }
    </style>
    """

def create_html_email(title, body_content, details=None):
    style = get_email_style()
    rows = ""
    if details:
        for key, value in details.items():
            if value:
                rows += f"<tr><td class='label'>{key}</td><td>{value}</td></tr>"
    
    return f"""
    <html>
    <head>{style}</head>
    <body>
        <div class="container">
            <div class="header">
                <h1>FraudGuard Security</h1>
            </div>
            <div class="content">
                <h2>{title}</h2>
                {body_content}
                {f'<table class="info-table">{rows}</table>' if details else ''}
            </div>
            <div class="footer">
                &copy; {datetime.now().year} FraudGuard Inc. | Secure & Real-time
            </div>
        </div>
    </body>
    </html>
    """

# --- 1. OTP EMAIL (Unified) ---
def send_email_otp(app_instance, recipient, otp_code, context="LOGIN", extra_info=""):
    """
    Sends OTP for Login or Transaction verification.
    If context != "LOGIN", it is treated as 'amount' and extra_info as 'receiver'.
    """
    try:
        with app_instance.app_context():
            mail = Mail(app_instance)
            
            if context == "LOGIN":
                subject = "🔐 Account Verification Code"
                title = "Verify Your Login"
                body = f"<p>A login attempt was detected. Use the code below to complete your sign-in.</p><div class='otp-code'>{otp_code}</div>"
                details = {"Type": "Login Verification", "Time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            else:
                # Transaction context (context=amount, extra_info=receiver)
                amount = context
                receiver = extra_info
                
                subject = f"🔐 Verify Transaction: ₹{amount}"
                title = "Confirm Transaction"
                body = f"<p>Did you attempt to send <b>₹{amount}</b> to <b>{receiver}</b>?</p><div class='otp-code'>{otp_code}</div>"
                details = {
                    "Amount": f"₹{amount}",
                    "Receiver": receiver,
                    "Time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }

            msg = Message(subject, sender=os.environ.get('MAIL_USERNAME', 'no-reply@fraudguard.com'), recipients=[recipient])
            msg.html = create_html_email(title, body, details)
            mail.send(msg)
            print(f"✅ OTP Email Sent to {recipient}")
    except Exception as e:
        print(f"❌ Failed to send OTP email: {e}")

# --- 2. CRITICAL FRAUD ALERT ---
def send_fraud_alert(app_instance, recipient, tx_details):
    try:
        with app_instance.app_context():
            mail = Mail(app_instance)
            msg = Message(
                f"🚨 FRAUD ALERT: blocked ₹{tx_details.get('amount')}",
                sender=os.environ.get('MAIL_USERNAME', 'no-reply@fraudguard.com'),
                recipients=[recipient]
            )
            
            body = """
            <div class='alert-box'>
                <b>Transaction Blocked</b><br/>
                We prevented a suspicious transaction on your account.
            </div>
            """
            
            details = {
                "Amount": f"₹{tx_details.get('amount')}",
                "Status": "BLOCKED",
                "Reason": tx_details.get('reason'),
                "Risk Score": f"{tx_details.get('risk_score'):.2f} / 1.00",
                "Location": tx_details.get('location', 'Unknown'),
                "Time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            msg.html = create_html_email("Security Alert", body, details)
            mail.send(msg)
    except Exception as e:
        print(f"❌ Failed to send Fraud Alert: {e}")

# --- 3. NEW DEVICE ALERT ---
def send_new_device_alert(app_instance, recipient, ip_address, device_fingerprint, location="Unknown"):
    try:
        with app_instance.app_context():
            mail = Mail(app_instance)
            msg = Message(
                'New Device Login Detected',
                sender=os.environ.get('MAIL_USERNAME', 'no-reply@fraudguard.com'),
                recipients=[recipient]
            )
            body = "<p>A new device successfully logged into your FraudGuard account.</p>"
            details = {
                "IP Address": ip_address,
                "Location": location,
                "Device": device_fingerprint[:20] + "...",
                "Time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            msg.html = create_html_email("New Login", body, details)
            mail.send(msg)
    except Exception as e:
        print(f"❌ Failed to send Device Alert: {e}")

# --- 3a. LOGIN SUCCESS EMAIL ---
def send_login_success_email(app_instance, recipient, ip_address, location="Unknown"):
    try:
        with app_instance.app_context():
            mail = Mail(app_instance)
            msg = Message(
                '✅ Successful Login Alert',
                sender=os.environ.get('MAIL_USERNAME', 'no-reply@fraudguard.com'),
                recipients=[recipient]
            )
            body = """
            <p>You have successfully logged in to your FraudGuard account.</p>
            <p style='color: #666; font-size: 13px;'>If this was you, no action is needed.</p>
            """
            details = {
                "Status": "Success",
                "IP Address": ip_address,
                "Location": location,
                "Time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            msg.html = create_html_email("Login Detected", body, details)
            mail.send(msg)
            print(f"✅ Login Email Sent to {recipient}")
    except Exception as e:
        print(f"❌ Failed to send Login Email: {e}")

# --- 4. GENERIC SECURITY ALERT ---
def send_security_alert(app_instance, recipient, subject, ip_address, location="Unknown"):
    try:
        with app_instance.app_context():
            mail = Mail(app_instance)
            
            is_good = "Successful" in subject
            color = "#2f855a" if is_good else "#e53e3e"
            
            body = f"""
            <div style='background-color: {color}; color: white; padding: 10px; border-radius: 4px; text-align: center; margin-bottom: 20px;'>
                <b>{subject}</b>
            </div>
            """
            
            details = {
                "Event": subject,
                "IP Address": ip_address,
                "Location": location,
                "Time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            msg = Message(subject, sender=os.environ.get('MAIL_USERNAME', 'no-reply@fraudguard.com'), recipients=[recipient])
            msg.html = create_html_email("Activity Notification", body, details)
            mail.send(msg)
    except Exception as e:
        print(f"❌ Failed to send Security Alert: {e}")
