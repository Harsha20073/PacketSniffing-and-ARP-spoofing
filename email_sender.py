import smtplib
from email.message import EmailMessage
import os


# -------------------------
# CONFIGURATION
# -------------------------

SENDER_EMAIL = "your_email@gmail.com"
APP_PASSWORD = "your_16_character_app_password"

RECEIVER_EMAIL = "your_email@gmail.com"


# -------------------------
# SEND REPORT
# -------------------------

def send_session_report(total, tcp, udp, icmp, arp, alerts):

    msg = EmailMessage()

    msg["Subject"] = "NetSentinel Session Report"

    msg["From"] = SENDER_EMAIL

    msg["To"] = RECEIVER_EMAIL


    body = f"""
NetSentinel Monitoring Completed

Statistics

Total Packets : {total}

TCP : {tcp}

UDP : {udp}

ICMP : {icmp}

ARP : {arp}

ARP Alerts : {alerts}

Packet Log and Session Report are attached.
"""

    msg.set_content(body)


    attachments = [
        "packet_log.csv",
        "session_report.txt"
    ]


    for file in attachments:

        if os.path.exists(file):

            with open(file, "rb") as f:

                data = f.read()

            msg.add_attachment(
                data,
                maintype="application",
                subtype="octet-stream",
                filename=file
            )


    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465
    ) as smtp:

        smtp.login(
            SENDER_EMAIL,
            APP_PASSWORD
        )

        smtp.send_message(msg)

    print("Email sent successfully.")
