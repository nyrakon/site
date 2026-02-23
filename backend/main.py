from typing import Dict, List, Optional

from fastapi import FastAPI, Request, Response

from dotenv import dotenv_values
import os, subprocess, multiprocessing
import cryptography.hazmat.primitives.hashes as hashes
import json
from dataclasses import dataclass, asdict, field
import orjson, datetime, secrets
settings=dotenv_values("../.env") # < env path is outside html
sessionexpiry=int(settings['session_token_expiry'])
settings['ratelimit_expiry']=int(settings['ratelimit_expiry'])
settings['device_limit']=int(settings['device_limit'])
DEVELOPMENT=settings['ENVIRONMENT']=='dev'
version=subprocess.check_output("git describe --tags --abbrev=0".split(" ")).decode().strip()
app=FastAPI(title='NyrakonAPI',version=version)
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
def root():
    return {"STATUS":"OK","VERSION":version}


################# ACES/Secure management
db:list=[] # main server has around ~100 gb of storage. it should be enough for >1 million users.
if not os.path.exists(settings['dbloc']):
    with open(settings['dbloc'],'xb') as f: f.write(orjson.dumps({}))
with open(settings['dbloc'],'r') as f: 
    #data=json.load(f)
    data=orjson.loads(f.read())
    db=data


if not os.path.exists(settings['regiploc']):
    with open(settings['regiploc'],'x') as f:
        pass
already_registered_ips:list[str]=[] # nobody should need more than 1 account, if already secure + privacy oriented
with open(settings['regiploc'],'r') as f:
    already_registered_ips=f.readlines()

def save_data():
    with open(settings['dbloc'],'wb') as f: f.write(orjson.dumps(db))
    with open(settings['regiploc'],'w') as f: f.write("\n".join(already_registered_ips))

@dataclass
class Session:
    owner: str  # access_code / account id
    originip: str
    metadata: str
    trusted: bool = False
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    primary_session: bool = False
    data: Optional[str] = None  # will hold JSON session key

    def __post_init__(self):
        # only generate self.data if not passed (for deserialization)
        if not self.data:
            tempdata = {
                "ownerid": self.owner,
                "unique_id": secrets.token_urlsafe(512)
            }
            self.data = json.dumps(tempdata)

active_sessions:dict[str,Session]={} # data > session for lookup

def genfuzzyscore(a:str,b:str):
    a=sum([ord(c) for c in a])
    b=sum([ord(c) for c in b])
    result=a/b # not enough
    result2=b/a
    # ^ if A or B is longer than eachother then it may produce a score > 1.
    # so making result2 and doing subtraction otherwise should fix that.
    return abs(result-result2)

@dataclass
class Account():
    registrating_ip: str
    src_metadata: Optional[str] = None
    access_code: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    sessions: List['Session'] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    preferences: Dict[str, bool] = field(default_factory=lambda: {'allow_other_ips': False})
    security_questions: Dict[str, str] = field(default_factory=dict)
    recovery_key_pub: Optional[str] = None#field(default_factory="")
    locked: bool = False # < locked typically means someone that is untrusted tried using someone's recovery key
    # and thus for security reasons, locking the account down should be done to avoid user data acquisition.

    def trust_session(self,sess:Session):
        sess.trusted=True
        self.sessions[self.sessions.index(sess)]=sess
    def new_session(self,req:Request):
        if req.headers.get("X-Forwarded-For","").__len__()==0:
            if not DEVELOPMENT: raise Exception("Can't make new account because the underlying frontend doesn't forward IPs.")
        sess=Session(
            self.access_code,
            req.headers.get("X-Forwarded-For",req.client.host),
            metadata=self.src_metadata,
            trusted=False
        )
        if len(self.sessions)==0: sess.primary_session=True
        self.sessions.append(sess)
        active_sessions[sess.data]=sess
        return sess
    def del_session(self,sess:Session):
        self.sessions.remove(sess)
        active_sessions.pop(sess.data)
    def new_recoverykey(self) -> tuple[bytes,bytes]:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        private_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        privk_raw=private_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.OpenSSH,serialization.NoEncryption())

        pubk_raw=private_key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        pubk_raw:bytes
        self.recovery_key_pub=pubk_raw.decode("utf-8",errors="ignore")
        del private_key
        return privk_raw, pubk_raw


def calc_metadata(req: Request) -> str:
    # Headers to exclude (lowercase)
    excluded_headers = {
        "cookie",
        "referer",
        "origin",
        "content-length",
        "connection",
        "host",
        "upgrade-insecure-requests",
    }
    headers = []
    for key, value in req.headers.items():
        key_lower = key.lower()
        # Skip excluded headers
        if key_lower in excluded_headers:
            continue
        # Skip sec-* headers (browser temporary/security context headers)
        if key_lower.startswith("sec-"):
            continue
        headers.append(f"{key_lower}:{value.strip().lower()}")
    headers.sort()
    return "|".join(headers)
print("METADATA CHECK.")
metadata_thres=0.075
def devprint(*args,**kwargs):
    if DEVELOPMENT: print(*args,**kwargs)

rate_limit={}
@app.middleware("http")
async def acesmiddleware(req:Request,callnext):
    if len(rate_limit.keys())>10_000_000: rate_limit.clear()
    # this middleware verifies session tokens and ensures they are authentic.
    # so to implement ACES, all you really need is to handle signup/logout/recovery.
    # what we aim to do primarily is to limit informative messages so that hopefully the attacker gives up, due to lack of information of what is occuring.
    # so that they cannot iteratively understand what ACES is doing behind the scenes.
    source_ip=req.headers.get("X-Forwarded-For",req.client.host)
    if 'secure' in req.url.path:
        if not source_ip in rate_limit: rate_limit[source_ip]={'amount':0,'time':datetime.datetime.now(),'resets':0}
    if req.url.path.startswith("/secure"):
        # ratelimit checks in memory. SAY you want this persistent. If you store it in storage, that assumes you have storage to spend
        # not only on the database itself, but other databases, like keeping track of registered ips, installed applications/software,
        # ratelimit database. AND THEN you need the memory to load all of these into memory to keep persistent, otherwise you may be wasting I/O
        # per request on this endpoint.
        # even if you did extreme optimization, like say, we keep it persistent, but we do a 'rolling context' kind of persistence,
        # where old values are deleted from the persistent ratelimit database or anything else,
        # you risk multiple users + possible abuse so rotating ips, running this up to the limit, and technically they could go on indefinitely.
        # OR iterative seeking, so seeking only a portion of the database, basically the same risk vector.
        # it's pretty useless to keep this persistent.

        # ^ amount is keeping track of failure attempts, time to reset the failure attempts, and 'resets' specifically is for keeping track of
        # how many times we reset this ip's failure attempts. 'resets' is for let's say we want to reset someone's failure attempts on a 
        # successful login so that a normal user who hasn't logged in in a while, can use the service with minimal issue.
        # but if it's an attacker, 'resets' is there to prevent people from abusing this feature.
        if rate_limit[source_ip]['amount']>=3:
            # rate limit the person if they're deliberately tripping the system
            # a normal person shouldn't be able to trip the system unless their session expired.
            now=datetime.datetime.now()
            diff=now-rate_limit[source_ip]['time']
            if not (rate_limit[source_ip]['resets']>=2): 
                diff:datetime.timedelta
                if diff.total_seconds()>=settings['ratelimit_expiry']:
                    rate_limit[source_ip]['amount']=0
                    rate_limit[source_ip]['resets']+=1
            else:
                # this means resets>=3 and thus, we are NOT expiring this rate limit. 
                pass
            return errors['limit'] 
        
        # handle session tokens
        S=req.cookies.get("session","") # < get session
        if S.__len__()==0: devprint("no session cookie"); rate_limit[source_ip]['amount']+=1; return errors["unauth"] # < if no session
        if not (S in active_sessions): devprint("session cookie not actually a real session"); rate_limit[source_ip]['amount']+=1; return errors['unauth']
        # ^ since every session has a unique id, if the session doesn't match exactly then it's likely a counterfeit session.
        if not (S in active_sessions): devprint("the actual session doesn't exist"); rate_limit[source_ip]['amount']+=1; return errors['unauth']
        relatedsession=active_sessions[S]
        relatedsession:Session

        if not (relatedsession.owner in db): devprint("no account associated with this session"); rate_limit[source_ip]['amount']+=1; return errors['unauth']
        relatedaccount=db[relatedsession.owner]
        relatedaccount:Account

        if relatedaccount.locked: devprint("someoen tried USING the account while account is locked");  return errors['badrecovery'] # < concurrency related check

        # if this session has lasted over the expiry, remove it.
        now=datetime.datetime.now(datetime.UTC)
        sessionsdate=datetime.datetime.fromisoformat(relatedsession.created_at)
        if (now-sessionsdate).total_seconds()>=sessionexpiry:
            relatedaccount.sessions.remove(relatedsession)
            
        # check account preferences
        if (not relatedaccount.preferences['allow_other_ips']):
            if relatedsession.originip!=req.headers.get("X-Forwarded-For",req.client.host): rate_limit[source_ip]['amount']+=1; devprint("IP mismatch: ",relatedsession.originip,req.headers.get("X-Forwarded-For",req.client.host)); return errors['unauth']

        # if this session's not trusted, remove it.
        if not relatedsession.trusted: devprint("session not trusted"); return DEVELOPMENT and errors['untrusted'] or errors['unauth']
        
        # metadata. basically doing a sort of fuzzy matching. instead of using a library,
        # things are primitively based off of numbers or bits. why do we need a library for this?
        currmeta=calc_metadata(req)
        sessionmeta=relatedsession.metadata
        score=genfuzzyscore(currmeta,sessionmeta)
        devprint(score,currmeta,sessionmeta)
        if (score>metadata_thres):
            rate_limit[source_ip]['amount']+=1;
            # there's basically an attacker
            devprint("you're an attacker!")
            return errors['using other token']

        if len(req.url.path.split("/"))>=3: # accessing a sub directive of /secure/ID/X and thus need to implement
            # id A can only access id A, and not id B, even though they're likely both authenticated.
            requested_id=req.url.path.split("/")[2]
            if requested_id!=relatedaccount.access_code:
                devprint("someone tried using another person's id.")
                account.sessions.clear()
                return errors['using other token'] 
            
        # allow access
        response=await callnext(req)
        return response
    else:
        response=await callnext(req)
        return response
    
from pydantic import BaseModel
# for any req body we want to get easily

class AccountDetails(BaseModel):
    id: str
    recovery_secret: bytes
    # recovery code not implemented yet
@app.get("/register_secure")
def registration(request: Request,response: Response):
    srcip=request.headers.get("X-Forwarded-For",request.client.host)
    if srcip in already_registered_ips: devprint("too many registrations"); return errors["too many registrations"]
    already_registered_ips.append(srcip)
    newacc=Account(srcip,calc_metadata(request))
    db[newacc.access_code]=newacc
    sess=newacc.new_session(request)
    sess.trusted=True

    # generate a recovery key. this is used to re-gain access to the account, if locked out by any means.
    privkey,_=newacc.new_recoverykey()
    resp=AccountDetails(id=newacc.access_code,recovery_secret=privkey)
    del privkey,_

    save_data()
    response.set_cookie("session",sess.data,sessionexpiry,sessionexpiry)
    return resp

class LoginPayload(BaseModel):
    account_id: str
    security_questions: dict[str,str]=None
@app.post("/login_secure")
def login(req:Request,payload:LoginPayload):
    # TODO: make db vectorized and O1 instead of On
    if not (payload.account_id in db): return errors['unauth']
    acc=db[payload.account_id]
    acc:Account
    # this is the related account that this person is trying to login to.
    source_ip=req.headers.get("X-Forwarded-For",req.client.host)
    print("acc match")
    #if len(acc.sessions)>=settings['device_limit']: return errors['limit']
    othercheck=True
    firstcheck=False
    secondcheck=False
    if acc.preferences['allow_other_ips']: firstcheck=True
    else: 
        if source_ip!=acc.registrating_ip: devprint("ip mismatch"); return errors['unauth']
        firstcheck=True

    # handle mfa
    if acc.security_questions.values().__len__()>0: # there are security questions
        if not payload.security_questions: devprint("payload has no security questions"); return errors['unauth']
        reqanswers=[]
        for req_answer in payload.security_questions.values():
            # security answers should be hashed.
            dig=hashes.Hash(hashes.SHA3_256)
            dig.update(req_answer.encode('utf-8'))
            reqanswers.append(dig.finalize().decode('utf-8', errors='ignore'))
        actualanswers=acc.security_questions.values()
        if len(actualanswers)>len(reqanswers):
            devprint("account's answers are longer than how many answers your payload gave")
            return errors['unanswered_sec_que']
        totalright=0
        for i,answer in enumerate(reqanswers):
            # what we're doing is
            # if A[K] == B[K], then K is correct.
            if answer==actualanswers[i]: totalright+=1
        if not (totalright==(len(actualanswers))):
            othercheck=False
    
    # look if there's someone already logged in.
    primarysessionfound=False
    for session in acc.sessions:
        if session.primary_session: primarysessionfound=True


    if len(acc.sessions)>=settings['device_limit']: devprint("too many devices for this account."); return errors['too many devices']
    if acc.locked: devprint("someoen tried logging in while account is locked"); return errors['badrecovery']
    # if this is a new device, make it have to be manually trusted.
    if genfuzzyscore(calc_metadata(req),acc.src_metadata)>metadata_thres:
        secondcheck=True
    else:
        rate_limit[source_ip]['resets']+=1
        rate_limit[source_ip]['amount']=0
        devprint("made untrusted session since new device!")
        sess=acc.new_session(req) # untrusted at the moment. needs to explicitly be set as 'trusted'.
        sess.primary_session=False
        # even if 2 people are on the same exact machine/ip, this one needs to be trusted.
        if not primarysessionfound: 
            # nobody else is logged in. security question(s) may have been answered. account take-over.
            sess.primary_session=True; sess.trusted=True
        res=Response() # 200
        res.set_cookie("session",sess.data,max_age=sessionexpiry,expires=sessionexpiry,samesite='strict')
        return res
    
    # if this is legit, or if all checks passed, login for full access. 
    # (mfa might be needed if you're allowing other ips to login or if you have a dynamic ip.)
    if othercheck and secondcheck and firstcheck:
        rate_limit[source_ip]['resets']+=1
        rate_limit[source_ip]['amount']=0
        sess=acc.new_session(req)
        if not primarysessionfound:
            devprint("made trusted session")
            sess.trusted=True
            sess.primary_session=True
        else:
            devprint("made untrusted session since new device!")
            sess.trusted=False
        res=Response() # 200
        res.set_cookie("session",sess.data,max_age=sessionexpiry,expires=sessionexpiry,samesite='strict')
        return res
    
    return errors['unauth']

class RecoveryPayload(BaseModel):
    id:str
    signature:bytes
@app.post("/recover_secure")
def recoveracc(payload:RecoveryPayload, req:Request):
    if not (payload.id in db): devprint("during recovery, someone tried recovering a nonexistent account"); return errors['unauth']
    source_ip=req.headers.get("X-Forwarded-For",req.client.host)
    related_acc=db[payload.id]
    related_acc:Account

    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    pub=serialization.load_pem_public_key(related_acc.recovery_key_pub.encode("utf-8",errors="ignore"))
    try:
        pub.verify(payload.signature,payload.id.encode("utf-8",errors="ignore"),            padding.PSS(
            mgf=padding.MGF1(hashes.SHA3_256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA3_256())
        for sess in related_acc.sessions:
            if sess.data in active_sessions: active_sessions.pop(sess.data)
        related_acc.sessions.clear()
        if (source_ip!=related_acc.registrating_ip) or (genfuzzyscore(calc_metadata(req),related_acc.src_metadata)<=metadata_thres):
            related_acc.locked=True
            devprint("possible attacker acquired someones recovery key. locked it down."); 
            return errors['badrecovery']
        priv,_=related_acc.new_recoverykey()
        del priv,_
        return AccountDetails(id=related_acc.access_code,recovery_secret=priv)
    except Exception as e:
        print("yes")
        devprint(e)
        return errors['unauth']

# basic info, secured by the middleware
class AccountInfo(BaseModel):
    preferences:dict
    sessions:list[Session]
@app.get("/secure/{id}")
def getaccdata(id):
    accountdata=db[id]
    accountdata:Account
    return AccountInfo(preferences=accountdata.preferences,sessions=accountdata.sessions)

class TrustSesssionPayload(BaseModel):
    session_data:str
    make_primary:Optional[bool]
@app.post("/secure/{id}/trust_session")
def trust_session(id,payload:TrustSesssionPayload,request:Request):
    current_session=active_sessions[request.cookies.get("session")]
    current_session:Session
    if (not current_session.primary_session) and (not current_session.trusted):
        return errors['untrusted']
    
    accountdata=db[id]
    accountdata:Account
    for s in accountdata.sessions:
        if s.data==payload.session_data:
            # found the data to trust
            s.trusted=True
            if payload.make_primary: s.primary_session=True
            return Response("trusted",media_type="text/html")
    return Response("no session exists with that data",media_type="text/html",status_code=406)

@app.post("/secure/{id}/remove_session")
def remove_session(id,payload:TrustSesssionPayload,request:Request):
    current_session=active_sessions[request.cookies.get("session")]
    current_session:Session
    if (not current_session.primary_session) and (not current_session.trusted):
        return errors['untrusted']

    accountdata=db[id]
    accountdata:Account
    for s in accountdata.sessions:
        if s.data==payload.session_data:
            accountdata.sessions.pop(accountdata.sessions.index(s))
            return Response()
    return Response("no session exists with that data",media_type="text/html",status_code=406)


# re-acknowledge sessions with pre-existing accounts
for key in db:
    accountdata=db[key]
    account=Account(**accountdata)
    db[key]=account
    print(account.src_metadata)
    #print(account)
    account.sessions.clear()
    #for i,sessiondata in enumerate(account.sessions): # < uncomment for user convenience
        #session=Session(**sessiondata)
        #account.sessions[i]=session
#
        #if not session in active_sessions:
            #active_sessions.append(session)
            #raw_sessionlist.append(session.data)
save_data()