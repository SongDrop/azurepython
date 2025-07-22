import os
import sys
from dotenv import load_dotenv
load_dotenv()

import html_email
import html_email_send

RECIPIENT_EMAILS = 'gabzlabs420@gmail.com,gabz@songdrop.band'

def print_info(msg):
    print(f"[INFO] {msg}")

def print_error(msg):
    print(f"[ERROR] {msg}")

def print_success(msg):
    print(f"[SUCCESS] {msg}")

def main():
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port_str = os.environ.get('SMTP_PORT')
    smtp_user = os.environ.get('SMTP_USER')
    smtp_password = os.environ.get('SMTP_PASS')
    sender_email = os.environ.get('SENDER_EMAIL')
    recipient_emails_str = RECIPIENT_EMAILS
    if not recipient_emails_str:
        print_error("RECIPIENT_EMAILS environment variable is not set.")
        sys.exit(1)
    recipient_emails = [e.strip() for e in recipient_emails_str.split(',')]

    # Validate and convert smtp_port safely
    try:
        smtp_port = int(smtp_port_str)
    except (ValueError, TypeError):
        print_error(f"Invalid SMTP_PORT value: {smtp_port_str}")
        sys.exit(1)

    # Dummy values for required email content parameters
    vm_name = "TestVM"
    public_ip = "192.0.2.1"  # example IP for testing
    WINDOWS_IMAGE_PASSWORD = "TestPassword123!"

    # Build the HTML content using your html_email.HTMLEmail function/class
    html_content = html_email.HTMLEmail(
        ip_address=public_ip,
        background_image_url="https://i.postimg.cc/pr1NB01Y/nvidia.jpg",
        title=f"{vm_name} - Playstation2",
        main_heading=f"{vm_name} - Playstation2",
        main_description="Your virtual machine is ready to play games.",
        youtube_embed_src="https://youtu.be/D0wfOPLns5s",
        image_left_src="",
        image_right_src="",
        logo_src="https://i.postimg.cc/y8sL6yDj/ps2logo.png",
        company_src="https://i.postimg.cc/wTGBg048/pal.png",
        discord_widget_src="https://discord.com/widget?id=1363815250742480927&theme=dark",
        windows_password=WINDOWS_IMAGE_PASSWORD,
        credentials_sunshine="Username: <strong>sunshine</strong><br>Password: <strong>sunshine</strong>",
        form_description="Fill our form, so we can match your team with investors/publishers",
        form_link="https://forms.gle/QgFZQhaehZLs9sySA"
    )

    try:
        print_info("Sending test email via SMTP...")
        html_email_send.send_html_email_smtp(
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_user=smtp_user,
            smtp_password=smtp_password,
            sender_email=sender_email,
            recipient_emails=recipient_emails,
            subject=f"Test Email from {vm_name}",
            html_content=html_content,
            use_ssl=(smtp_port == 465),
            use_tls=(smtp_port != 465)
        )
        print_success("Test email sent successfully!")
    except Exception as e:
        print_error(f"Failed to send test email: {e}")


if __name__ == "__main__":
    main()