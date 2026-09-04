import resend
from config import RESEND_API_KEY, RESEND_FROM, OTP_EXPIRY_MINUTES

resend.api_key = RESEND_API_KEY

def send_otp_email(to_email: str, name: str, otp: str) -> bool:
    try:
        resend.Emails.send({
            "from": RESEND_FROM,
            "to": [to_email],
            "subject": f"Your AERO-FIT verification code: {otp}",
            "html": f"""
                <div style="font-family: -apple-system, Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px;">
                    <h2 style="color:#0A1628; margin-bottom: 4px;">AERO<span style="color:#2A5FD4;">-FIT</span></h2>
                    <p style="color:#3A5A8A; font-size: 15px;">Hi {name or 'there'},</p>
                    <p style="color:#3A5A8A; font-size: 15px;">
                        Use the code below. It expires in {OTP_EXPIRY_MINUTES} minutes.
                    </p>
                    <div style="background:#F0F6FF; border-radius:12px; padding:18px; text-align:center; margin: 20px 0;">
                        <span style="font-size: 32px; font-weight: 800; letter-spacing: 6px; color:#0A1628;">{otp}</span>
                    </div>
                    <p style="color:#8AAAD0; font-size: 13px;">
                        If you didn't request this, you can safely ignore this email.
                    </p>
                </div>
            """,
        })
        return True
    except Exception as e:
        print(f"⚠️  Failed to send OTP email to {to_email}: {e}", flush=True)
        return False