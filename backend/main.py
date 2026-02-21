from fastapi import FastAPI
from dotenv import dotenv_values
settings=dotenv_values("../.env") # < env path is outside html
app=FastAPI(title='NyrakonAPI')