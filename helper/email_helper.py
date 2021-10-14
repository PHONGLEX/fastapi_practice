from fastapi import (
    FastAPI, 
    BackgroundTasks, 
    UploadFile, File, 
    Form, 
    Query,
    Body,
    Depends
)
from fastapi_mail import FastMail, MessageSchema,ConnectionConfig
from helper.config import config


conf = ConnectionConfig(
    MAIL_USERNAME = config['EMAIL'],
    MAIL_PASSWORD = config['PASSWORD'],
    MAIL_FROM = config['EMAIL'],
    MAIL_PORT = 587,
    MAIL_SERVER = "smtp.gmail.com",
    MAIL_TLS = True,
    MAIL_SSL = False,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = True
)

async def send_mail(data):

    message = MessageSchema(
        subject=data['subject'],
        recipients=data['to'],
        body=data['body'],
        subtype="html"
        )

    fm = FastMail(conf)
    await fm.send_message(message)