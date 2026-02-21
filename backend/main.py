from fastapi import FastAPI
from dotenv import dotenv_values
import os, subprocess
settings=dotenv_values("../.env") # < env path is outside html
version=subprocess.check_output("git describe --tags --abbrev=0".split(" ")).decode().strip()
app=FastAPI(title='NyrakonAPI',version=version)

@app.get("/")
def root():
    return {"STATUS":"OK"}