from fastapi import FastAPI, Request, Response

from dotenv import dotenv_values
import os, subprocess, multiprocessing
from cryptography.hazmat.primitives.ciphers.aead import A
from cryptography.hazmat.primitives.hashes import SHA3_512, SHA3_384
import json


settings=dotenv_values("../.env") # < env path is outside html
DEVELOPMENT=settings['ENVIRONMENT']=='dev'
version=subprocess.check_output("git describe --tags --abbrev=0".split(" ")).decode().strip()
app=FastAPI(title='NyrakonAPI',version=version)
errors={
    'unauth':Response(content="", status_code=403, media_type="application/xml"),
    'untrusted':Response(content="untrusted.", status_code=403, media_type="application/xml")
}
@app.get("/index.html") # > apache indexes / as /index.html
def root():
    return {"STATUS":"OK","VERSION":version}

class Session():
    def __init__(self, access_code, session_key, trusted=False):
        self.owner=access_code
        self.data=session_key
        self.trusted=trusted
        pass

if not os.path.exists(settings['regiploc']):
    with open(settings['regiploc'],'x') as f:
        pass
already_registered_ips:list[str]=[] # nobody should need more than 1 account, if already secure + privacy oriented
with open(settings['regiploc'],'r') as f:
    already_registered_ips=f.readlines()

raw_sessionlist:list[str]=[] # < to not have to iterate through sessions one by one
active_sessions:list[Session]=[] # < for more precise authentication

@app.middleware("http")
async def acesmiddleware(req:Request,callnext):
    if req.url.path.startswith("/secure"):
        # handle session tokens
        S=req.cookies.get("session","")
        if not S: return errors["unauth"]
        if not (S in raw_sessionlist): return errors['unauth']
        relatedsession=None
        for session in active_sessions:
            if session.data==S: relatedsession=session
        if not relatedsession.trusted: DEVELOPMENT and errors['untrusted'] or errors['unauth']
        response=await callnext(req)
        return response
    else:
        response=await callnext(req)
        return response

@app.get("/register")
def registration(request: Request):
    request.client.host    

@app.get("/secure/{id}")
def getaccdata(id):
    