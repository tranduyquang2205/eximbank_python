import requests
import json
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
from eximbank import EXIMBANK
import sys
import traceback
from api_response import APIResponse


app = FastAPI()
@app.get("/")
def read_root():
    return {"Hello": "World"}
class LoginDetails(BaseModel):
    username: str
    password: str
    account_number: str
@app.post('/login', tags=["login"])
def login_api(input: LoginDetails):
    try:
        eximbank = EXIMBANK(input.username, input.password, input.account_number)
        response = eximbank.do_login()
        return APIResponse.json_format(response)
    except Exception as e:
        response = str(e)
        print(traceback.format_exc())
        print(sys.exc_info()[2])
        return APIResponse.json_format(response)
class ConfirmDetails(BaseModel):
    username: str
    password: str
    account_number: str
    otp: str
@app.post('/confirm', tags=["confirm"])
def confirm_api(input: ConfirmDetails):
    try:
        eximbank = EXIMBANK(input.username, input.password, input.account_number)
        verify_otp = eximbank.verify_otp(input.otp)
        return APIResponse.json_format(verify_otp)
    except Exception as e:
        response = str(e)
        print(traceback.format_exc())
        print(sys.exc_info()[2])
        return APIResponse.json_format(response)
@app.post('/get_balance', tags=["get_balance"])
def get_balance_api(input: LoginDetails):
    try:
        eximbank = EXIMBANK(input.username, input.password, input.account_number)
        balance = eximbank.get_balance(input.account_number)
        return APIResponse.json_format(balance)
    except Exception as e:
        response = str(e)
        print(traceback.format_exc())
        print(sys.exc_info()[2])
        return APIResponse.json_format(response)
    
class Transactions(BaseModel):
    username: str
    password: str
    account_number: str
    from_date: str
    to_date: str
    
@app.post('/get_transactions', tags=["get_transactions"])
def get_transactions_api(input: Transactions):
    try:
        eximbank = EXIMBANK(input.username, input.password, input.account_number)
        transaction = eximbank.get_transactions(input.account_number,input.from_date,input.to_date)
        return APIResponse.json_format(transaction)
    except Exception as e:
        response = str(e)
        print(traceback.format_exc())
        print(sys.exc_info()[2])
        return APIResponse.json_format(response)


if __name__ == "__main__":
    uvicorn.run(app ,host='0.0.0.0', port=3000)