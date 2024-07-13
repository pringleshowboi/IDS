import smtplib
from email.mime.text import MIMEText

def send_alert(message):
    # Set up the email details
    from_email = "your_email@example.com"  # Change to your email
    to_email = "admin@example.com"  # Change to the recipient's email
    subject = "Intrusion Alert"
    body = f"ALERT: {message}"
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email
    
    # Send the email
    with smtplib.SMTP('smtp.example.com', 587) as server:  # Change to your SMTP server
        server.starttls()
        server.login(from_email, 'your_password')  # Change to your email password
        server.sendmail(from_email, to_email, msg.as_string())
