from fastapi import FastAPI
from dotenv import dotenv_values
import os, subprocess
settings=dotenv_values("../.env") # < env path is outside html
version=subprocess.check_output("git describe --tags --abbrev=0".split(" ")).decode().strip()
app=FastAPI(title='NyrakonAPI',version=version)
<<<<<<< HEAD
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
errors={
    'unauth':Response(content="", status_code=401, media_type="text/html"),
    'unanswered_sec_que':Response(content="you have unanswered security questions", status_code=401, media_type="text/html"),
    'untrusted':Response(content="untrusted.", status_code=401, media_type="text/html"),
    'too many registrations':Response(content="you already registered an account using this IP. delete the other account first.", status_code=406, media_type="text/html"),
    'using other token':Response(content="are you using someone else's token?", status_code=401, media_type="text/html"),
    'new device':Response(content="it seems you're logging on from a new device.", status_code=401, media_type="text/html"),
    'limit':Response(content="either hit rate limit or limitation on this resource.", status_code=406, media_type="text/html"),
    'session expired':Response(content="your session has expired. login again.", status_code=401, media_type="text/html"),
    'too many devices':Response(content="too many devices.", status_code=401, media_type="text/html"),
    'badrecovery':Response(content="For security-related purposes, your account is currently locked. Contact support for further assistance.", status_code=406, media_type="text/html"),
    #'rate limit':Response(content='',status_code=403,media_type='text/html')
}
errors['unauth'].delete_cookie("session")
errors['using other token'].delete_cookie("session")
errors['session expired'].delete_cookie("session")
################# Basic API func
@app.get("/index.html") # > apache indexes / as /index.html
=======

@app.get("/index.html")
>>>>>>> parent of ea86be8 (testing ACES live.)
def root():
    return {"STATUS":"OK"}