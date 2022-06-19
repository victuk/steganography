# Import smtplib for the actual sending function
import smtplib, ssl
from os.path import basename
import os
from email import encoders

# Import the email modules we'll need
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.utils import COMMASPACE, formatdate
from email.mime.base import MIMEBase
import textwrap
from email.mime.image import MIMEImage

# def send_mail(send_from, send_to, subject, text, files=None,
#               server="127.0.0.1"):
#     assert isinstance(send_to, list)

#     msg = MIMEMultipart()
#     msg['From'] = send_from
#     msg['To'] = COMMASPACE.join(send_to)
#     msg['Date'] = formatdate(localtime=True)
#     msg['Subject'] = subject

#     text = MIMEText("test")
#     msg.attach(text)
#     image = MIMEImage(img_data, name=os.path.basename(files))
#     msg.attach(image)

#     smtp = smtplib.SMTP(server)
#     smtp.sendmail(send_from, send_to, msg.as_string())
#     smtp.close()

def sendMail(sendFrom, to, subject, message):
    

    message = textwrap.dedent('''\
        From: %s
        To: %s
        Subject: %s
        %s
    '''% (sendFrom, to, subject, message))

    # 'hjytgacydyifxyar'
    # context = ssl.create_default_context()
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)

    # server.starttls(context=context) # Secure the connection
    server.login('victorp3tr@gmail.com', 'aidmgsqcyofsbxlo')
    server.sendmail(sendFrom, to, message)
    server.quit()

def sendMailTwo(sendFrom, to, subject, message):

    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = sendFrom
    msg['To'] = to

    text = MIMEText(message)
    msg.attach(text)
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)

    # server.starttls(context=context) # Secure the connection
    server.login('victorp3tr@gmail.com', 'aidmgsqcyofsbxlo')
    server.sendmail(sendFrom, to, msg.as_string())
    server.quit()

def sendMailWithAttachment(sendFrom, to, subject, message, attachmentURL):
    
    with open(attachmentURL, 'rb') as f:
        img_data = f.read()

    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = sendFrom
    msg['To'] = to

    text = MIMEText(message)
    msg.attach(text)
    image = MIMEImage(img_data, name=os.path.basename(attachmentURL))
    msg.attach(image)
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)

    # server.starttls(context=context) # Secure the connection
    server.login('victorp3tr@gmail.com', 'aidmgsqcyofsbxlo')
    server.sendmail(sendFrom, to, msg.as_string())
    server.quit()

def sendMailWithFile(sendFrom, to, subject, message, attachmentURL):
    
    # with open(attachmentURL, 'rb') as f:
    #     img_data = f.read()

    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = sendFrom
    msg['To'] = to

    text = MIMEText(message)
    msg.attach(text)
    # image = MIMEImage(img_data, name=os.path.basename(attachmentURL))
    # msg.attach(image)

    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)

    filename = attachmentURL[7:]

    attachment = open(attachmentURL, "rb")

    part = MIMEBase('application', 'octet-stream')
    part.set_payload((attachment).read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', "attachment; filename= %s" % filename)

    msg.attach(part)

    # server.starttls(context=context) # Secure the connection
    server.login('victorp3tr@gmail.com', 'aidmgsqcyofsbxlo')
    server.sendmail(sendFrom, to, msg.as_string())
    server.quit()
