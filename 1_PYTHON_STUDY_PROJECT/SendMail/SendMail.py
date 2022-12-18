    
import smtplib
import ssl

def SendEMail_MailRu():
    sender = "andtokm@yandex.ru";
    receivers = ["andtokm@yandex.ru"]
    sender_email = "andtokm@yandex.ru";
    password = "ziudjagaggggggggg";
    
    message = """From: From Person <from@fromdomain.com>
                 To: To Person <to@todomain.com>
                 Subject: SMTP e-mail test
                 This is a test e-mail message."""
    
    # Create a secure SSL context
    context = ssl.create_default_context()
    
    try:
        server = smtplib.SMTP('smtp.yandex.ru', 465);
        server.starttls(context=context) # Secure the connection
        server.ehlo() # Can be omitted
        server.login(sender_email, password)
        server.sendmail(sender, receivers, message)         
        print("Successfully sent email");
    except Exception:
        print("Error: unable to send email");


if __name__ == '__main__':
    SendEMail_MailRu();
    
   
    