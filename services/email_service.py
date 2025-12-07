import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from flask import current_app
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

# --- BREVO HELPER ---
def send_brevo_email(app_instance, to_email, subject, html_content):
    """
    Sends an email using Brevo (Sendinblue) API.
    """
    try:
        with app_instance.app_context():
            # Configure API key
            configuration = sib_api_v3_sdk.Configuration()
            configuration.api_key['api-key'] = current_app.config.get('BREVO_API_KEY')

            api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
            
            sender = {"name": "FraudGuard Security", "email": os.environ.get('MAIL_USERNAME', 'no-reply@fraudguard.com')}
            to = [{"email": to_email}]
            
            send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                to=to,
                sender=sender,
                subject=subject,
                html_content=html_content
            )

            api_response = api_instance.send_transac_email(send_smtp_email)
            print(f"✅ Email sent to {to_email}. Message ID: {api_response.message_id}")
            return True
    except ApiException as e:
        print(f"❌ Brevo API Exception: {e}")
        return False
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False

# --- 1. OTP EMAIL (Unified) ---
def send_email_otp(app_instance, recipient, otp_code, context="LOGIN", extra_info=""):
    """
    Sends OTP for Login or Transaction verification.
    """
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

    html_content = create_html_email(title, body, details)
    send_brevo_email(app_instance, recipient, subject, html_content)

# --- 2. CRITICAL FRAUD ALERT ---
def send_fraud_alert(app_instance, recipient, tx_details):
    subject = f"🚨 FRAUD ALERT: blocked ₹{tx_details.get('amount')}"
    
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

    html_content = create_html_email("Security Alert", body, details)
    send_brevo_email(app_instance, recipient, subject, html_content)

# --- 3. NEW DEVICE ALERT ---
def send_new_device_alert(app_instance, recipient, ip_address, device_fingerprint, location="Unknown"):
    subject = 'New Device Login Detected'
    body = "<p>A new device successfully logged into your FraudGuard account.</p>"
    details = {
        "IP Address": ip_address,
        "Location": location,
        "Device": device_fingerprint[:20] + "...",
        "Time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    html_content = create_html_email("New Login", body, details)
    send_brevo_email(app_instance, recipient, subject, html_content)

# --- 3a. LOGIN SUCCESS EMAIL ---
def send_login_success_email(app_instance, recipient, ip_address, location="Unknown"):
    subject = '✅ Successful Login Alert'
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
    html_content = create_html_email("Login Detected", body, details)
    send_brevo_email(app_instance, recipient, subject, html_content)

# --- 4. GENERIC SECURITY ALERT ---
def send_security_alert(app_instance, recipient, subject, ip_address, location="Unknown"):
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
    
    html_content = create_html_email("Activity Notification", body, details)
    send_brevo_email(app_instance, recipient, subject, html_content)

# --- 5. DETAILED TRANSACTION ALERT ---
def send_detailed_transaction_alert(app_instance, recipient, tx_data):
    """
    Sends a comprehensive email for ANY transaction status (Success, Failed, Blocked).
    tx_data expected keys: 
    - status: SUCCESS | FAILED | BLOCKED
    - amount: float
    - reason: str
    - location: str
    - receiver: str
    - time: str
    """
    status = tx_data.get('status', 'PENDING')
    amount = tx_data.get('amount')
    reason = tx_data.get('reason', 'N/A')
    
    # Determine Style
    if status == 'SUCCESS':
        subject = f"✅ Transaction Successful: ₹{amount}"
        color = "#2f855a" # Green
        title = "Transaction Approved"
        intro = f"Your transfer of <b>₹{amount}</b> to <b>{tx_data.get('receiver', 'Unknown')}</b> was successful."
    elif status == 'BLOCKED':
        subject = f"🚨 Transaction BLOCKED: ₹{amount}"
        color = "#e53e3e" # Red
        title = "Security Block"
        intro = "We blocked a transaction due to security concerns."
    else: # FAILED / ERROR
        subject = f"❌ Transaction Failed: ₹{amount}"
        color = "#dd6b20" # Orange
        title = "Transaction Failed"
        intro = "Your transaction could not be processed."

    # Build Body
    body = f"""
    <div style='background-color: {color}; color: white; padding: 15px; border-radius: 6px; text-align: center; margin-bottom: 25px;'>
        <b style='font-size: 18px;'>{title}</b><br/>
        <span style='font-size: 14px;'>{reason}</span>
    </div>
    <p>{intro}</p>
    """

    # Details Table
    details = {
        "Status": status,
        "Amount": f"₹{amount}",
        "Receiver": tx_data.get('receiver'),
        "Reason": reason,
        "Location": tx_data.get('location', 'Unknown'),
        "Time": tx_data.get('time', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    }

    html_content = create_html_email(title, body, details)
    send_brevo_email(app_instance, recipient, subject, html_content)
