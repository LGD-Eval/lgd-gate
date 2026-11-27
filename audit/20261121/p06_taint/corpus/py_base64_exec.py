import base64
payload = base64.b64decode("cHJpbnQoMSk=")
exec(payload)
