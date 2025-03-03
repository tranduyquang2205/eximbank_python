import requests
import json
import random
import base64
import string
import time
from datetime import datetime
import uuid

def random_number_string(length):
    return ''.join(random.choices(string.digits, k=length))
class EXIMBANK:
    def __init__(self, username, password, account_number,proxy_list=None):
        
        self.proxy_list = proxy_list
        if self.proxy_list:
            self.random_proxy_info = random.choice(self.proxy_list)
            proxy_host, proxy_port, proxy_username, proxy_password = self.random_proxy_info.split(':')
            self.proxies = {
                'http': f'http://{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}',
                'https': f'http://{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}'
            }
        else:
            self.proxies = None
        self.file = f"db/users/{username}.txt"
        self.cookies_file = f"db/cookies/{account_number}.json"
        self.session = requests.Session()
        self.captcha_key = '9bf19cdde5b4a2823228da8203e11950'
        self.key_anticaptcha = "f3a44e66302c61ffec07c80f4732baf3"
        self.url = {
            "getCaptcha": "https://edigi.eximbank.com.vn/ib/captcha/",
            "auth": "https://edigi.eximbank.com.vn/ib/",
            "process": "https://edigi.eximbank.com.vn/ib/process"
        }
        self.lang = 'vi'
        self.timeout = 60
        self.DT = "WINDOWS"
        self.E = str(uuid.uuid4())
        self.OV = "124.0.0.0"
        self.PM = "Edge"
        self.app_version = "2.4.1.15"
        self.captcha_token = ""
        self.captcha_value = ""
        self.username = username
        self.password = password
        self.account_number = account_number
        self.session_id = ""
        self.mobile_id = ""
        self.client_id = 0
        self.cif = ""
        self.token = ""
        self.access_token = ""
        self.auth_token = ""
        self.is_login = False
        self.time_login = time.time()
        self.otp_token = ""
        self.n_login = 0

        if not self.file_exists():
            self.username = username
            self.password = password
            self.account_number = account_number
            self.client_id = 0
            self.E = str(uuid.uuid4())
            self.otp_token = ""
            self.save_data()
        else:
            self.parse_data()
            self.username = username
            self.password = password
            self.account_number = account_number
            self.save_data()
    def save_cookies(self,cookie_jar):
        with open(self.cookies_file, 'w') as f:
            json.dump(cookie_jar.get_dict(), f)
    def load_cookies(self):
        try:
            with open(self.cookies_file, 'r') as f:
                cookies = json.load(f)
                self.cookies = cookies
                return
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            return requests.cookies.RequestsCookieJar()
    def file_exists(self):
        try:
            with open(self.file, "r"):
                return True
        except FileNotFoundError:
            return False

    def save_data(self):
        data = {
            "username": self.username,
            "password": self.password,
            "account_number": self.account_number,
            "session_id": self.session_id,
            "mobile_id": self.mobile_id,
            "client_id": self.client_id,
            "cif": self.cif,
            "token": self.token,
            "access_token": self.access_token,
            "E": self.E,
            "auth_token": self.auth_token,
            "otp_token": self.otp_token,
            'time_login': self.time_login,
            'is_login': self.is_login,
        }
        with open(self.file, "w") as file:
            json.dump(data, file)

    def parse_data(self):
        with open(self.file, "r") as file:
            data = json.load(file)
            self.username = data["username"]
            self.password = data["password"]
            self.account_number = data["account_number"]
            self.session_id = data["session_id"]
            self.mobile_id = data["mobile_id"]
            self.client_id = data["client_id"]
            self.token = data["token"]
            self.access_token = data["access_token"]
            self.auth_token = data["auth_token"]
            self.cif = data["cif"]
            self.E = data["E"]
            self.otp_token = data["otp_token"]
            self.time_login = data.get("time_login", "")
            self.is_login = data.get("is_login", "")

    def do_login(self):
        self.n_login += 1
        solve_captcha = self.solve_captcha()
        if not solve_captcha["success"]:
            return solve_captcha
        params = {
            "DT": self.DT,
            "E": self.E,
            "OV": self.OV,
            "PM": self.PM,
            "ATS": datetime.now().strftime("%y%m%d%H%M%S"),
            "captchaToken": self.captcha_token,
            "captchaValue": self.captcha_value,
            "clientId": self.client_id,
            "mid": 1,
            "authMethod": "SMS",
            "pin": self.password,
            "username": self.username,
        }
        result = self.curl_post(self.url["auth"], params)
        if result["code"] == '00':
            if "data" in result and 'accessKey' in result['data'] and result['data']['accessKey']:
                data = result
                self.session_id = data["sessionId"]
                self.access_token = data["accessToken"]
                self.is_login = True
                self.time_login = time.time()
                self.save_data()
                if "loginType" in result and result["loginType"] == '1':
                    self.save_data()
                    return {
                    'code': 200,
                    'success': True,
                    'message': 'Đăng nhập thành công',
                    "data": result if result else "",
                }
            else:
                if "data" in result and  "loginType" in result["data"] and result["data"]["loginType"] == '3':
                    print('Vui lòng nhập mã xác thực từ điện thoại')
                    # self.token = result["token"]
                    self.otp_token = result['data']["otpToken"]
                    self.is_login = True
                    self.time_login = time.time()
                    self.save_data()
                    return {
                        'code': 302,
                        'success': True,
                        'message': 'Vui lòng nhập OTP',
                        'data': result if result else "",

                    }
                elif "loginType" in result and result["loginType"] == '8':
                    print('Vui lòng xác thực từ điện thoại')
                    self.token = result["token"]
                    self.is_login = True
                    self.time_login = time.time()
                    self.save_data()
                    check_confirm = self.check_confirm_loop()
                    if check_confirm["success"]:
                        return {
                            'code': 200,
                            'success': True,
                            'message': 'Xác thực đăng nhập thành công',
                            "data": check_confirm['data'] if check_confirm and 'data' in check_confirm else "",
                        }

                    else:
                        return check_confirm
        elif result["code"] == '96':
            if self.n_login < 5:
                return self.do_login()
            return {
                'code': 422,
                "success": False,
                "message": result["des"],
                "data": result if result else "",
            } 
        else:
            return {
                'code': 500,
                "success": False,
                "message": result["des"],
                "data": result if result else "",
            }
    def re_login(self):
        solve_captcha = self.solve_captcha()
        if not solve_captcha["success"]:
            return solve_captcha
        params = {
            "DT": self.DT,
            "E": self.E,
            "OV": self.OV,
            "PM": self.PM,
            "ATS": datetime.now().strftime("%y%m%d%H%M%S"),
            "authMethod": "SMS",
            "clientId": self.client_id,
            "getByGroup": False,
            "isCache": None,
            "maxRequestInCache": False,
            "mid": 7,
        }
        result = self.curl_post(self.url["auth"], params)
        if result["code"] == '00':
            self.time_login = time.time()
            self.save_data()
            result['success'] = True
        return result
    def verify_otp(self, otp):
        params = {
            "DT": self.DT,
            "E": self.E,
            "OV": self.OV,
            "PM": self.PM,
            "ATS": datetime.now().strftime("%y%m%d%H%M%S"),
            "clientId": self.client_id,
            "mid": 2,
            "loginType":"3",
            "authMethod": "SMS",
            "otp": otp,
            "otpToken": self.otp_token,
        }
        res = self.curl_post(self.url["auth"], params)
        if res["code"] == "00":
            self.session_id = ""
            self.access_key = res['data']["accessKey"]
            self.cif = res['data']["cif"]
            self.access_token = ""
            self.client_id = 0
            self.is_login = True
            self.time_login = time.time()
            self.save_data()

            return {"code":200,"success": True, "message": res["des"] if 'des' in res else res, "data": res}
        else:
            return {"code":400,"success": False, "message": res["des"] if 'des' in res else res, "data": res}

    def check_confirm(self):
        data = {
        "user": self.username,
        "token": self.token,
        "mid": 30,
        "DT": self.DT,
        "E": self.E,
        "OV": self.OV,
        "PM": self.PM,
        "appVersion": self.app_version,
        "clientId": self.username
        }
        res = self.curl_post(self.url["auth"], data)
        
        return res
    def trust_device(self):
        

        data = {
            "user": self.username,
            "clientId": self.client_id,
            "location": "",
            "otp": "",
            "mid": 56,
            "DT": self.DT,
            "E": self.E,
            "OV": self.OV,
            "PM": self.PM,
            "appVersion": self.app_version,
            "token": self.token,
        }
        res = self.curl_post(self.url["auth"], data)
    def check_confirm_loop(self):
        i = 1
        while True:
            if i >= 10:
                return {"code":408,"success": False, "message": "Quá thời hạn xác thực, vui lòng thử lại!"}
            check_confirm = self.check_confirm()
            if check_confirm['code'] == '00':
                self.session_id = check_confirm["sessionId"]
                self.access_key = check_confirm["accessKey"]
                self.cif = check_confirm["cif"]
                self.access_token = check_confirm["accessToken"]
                self.client_id = check_confirm["clientId"]
                self.is_login = True
                self.time_login = time.time()
                self.save_data()
                return {"code":200,"success": True, "message": check_confirm["des"], "data": check_confirm}       
            else:
                time.sleep(5)
            i += 1
    def get_transactions(self, acc_no,from_date,to_date):
            if not self.is_login or time.time() - self.time_login > 10:
                login = self.re_login()
                if 'success' not in login or not login['success']:
                    return login
            params = {
                "DT": self.DT,
                "E": self.E,
                "OV": self.OV,
                "PM": self.PM,
                "ATS": datetime.now().strftime("%y%m%d%H%M%S"),
                "clientId": self.client_id,
                "authMethod": "SMS",
                "mid": 13,
                "isCache": False,
                "maxRequestInCache": False,
                "fromDate": from_date,
                "toDate":to_date,
                "pageNumber": 0,
                "accountNo": acc_no
            }
            result = self.curl_post(self.url["auth"], params, headers={"Authorization": self.auth_token})
            
            if result['code'] == '00' and 'data' in result and result['data'] and 'currentHistoryList' in result['data']:
                return {'code':200,'success': True, 'message': 'Thành công',
                                'data':{
                                    'transactions':result['data']['currentHistoryList'],
                        }}
            else:
                self.is_login = False
                self.save_data()
                return  {
                        "success": False,
                        "code": 500,
                        "message": result['des']
                    }

    def get_balance(self,account_number):
        if not self.is_login or time.time() - self.time_login > 290:
            print('relogin')
            login = self.re_login()
            if 'success' not in login or not login['success']:
                return login
        params = {
            "DT": self.DT,
            "E": self.E,
            "OV": self.OV,
            "PM": self.PM,
            "ATS": datetime.now().strftime("%y%m%d%H%M%S"),
            "clientId": self.client_id,
            "authMethod": "SMS",
            "mid": 11,
            "isCache": False,
            "maxRequestInCache": False,
        }
        result = self.curl_post(self.url["auth"], params, headers={"Authorization": self.auth_token})
        if 'data' in result and result['data'] and  'currentList' in result['data']:
            for account_info in result['data']['currentList']:
                if account_info['accountNo'] == account_number:
                    account_balance = account_info['availableBalance']
                    if int(account_balance) < 0:
                        return {'code':448,'success': False, 'message': 'Blocked account with negative balances!',
                                'data': {
                                    'balance':int(account_balance)
                                }
                                } 
                    else:
                        return {'code':200,'success': True, 'message': 'Thành công',
                                'data':{
                                    'account_number':self.account_number,
                                    'balance':int(account_balance)
                        }}
            return {'code':404,'success': False, 'message': 'account_number not found!'} 
        else:
            self.is_login = False
            self.save_data()
            return {'code':401 ,'success': False, 'message': 'Please relogin!','data':result}

    def get_captcha(self):
        self.captcha_token = "".join(random.choices(string.ascii_letters + string.digits, k=30))
        response = self.session.get(self.url["getCaptcha"] + self.captcha_token, headers={"user-agent": self.get_user_agent()},proxies=self.proxies)
        result = base64.b64encode(response.content).decode("utf-8")
        return result
    def createTaskCaptcha(self, base64_img):
        url = 'http://103.72.96.214:8277/api/captcha/bidv'
        payload = json.dumps({
        "base64": base64_img
        })
        headers = {
        'Content-Type': 'application/json'
        }
        response = requests.post(url, headers=headers, data=payload)
        return response.text


    def checkProgressCaptcha(self, task_id):
        url = 'https://api.anti-captcha.com/getTaskResult'
        data = {
            "clientKey": self.key_anticaptcha,
            "taskId": task_id
        }
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        response = requests.post(url, headers=headers, data=json.dumps(data))
        response_json = json.loads(response.text)
        if response_json["success"] != "ready":
            time.sleep(1)
            return self.checkProgressCaptcha(task_id)
        else:
            return response_json["solution"]["text"]
    def solve_captcha(self):
        get_captcha = self.get_captcha()
        task = self.createTaskCaptcha(get_captcha)
        captchaText =json.loads(task)['captcha']
        if not captchaText:
            return {"success": False, "msg": "Solve Captcha failed"}
        else:
            self.captcha_value = captchaText
            return {"success": True, "key": self.captcha_token, "captcha": self.captcha_value}

    # def encrypt_data_2(self, data):
    #     data["clientPubKey"] = self.client_public_key
    #     key = get_random_bytes(32)
    #     iv = get_random_bytes(16)
    #     rsa_key = RSA.import_key(self.default_public_key)
    #     cipher_rsa = PKCS1_OAEP.new(rsa_key)
    #     encrypted_key = base64.b64encode(cipher_rsa.encrypt(key)).decode("utf-8")
    #     cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    #     encryptor = cipher.encryptor()
    #     # encrypted_data = iv + cipher.encrypt(json.dumps(data).encode("utf-8"))

    #     encrypted_data = iv + encryptor.update(json.dumps(data).encode('utf-8')) + encryptor.finalize()
    #     return {"d": base64.b64encode(encrypted_data).decode("utf-8"), "k": encrypted_key}
    
    def encrypt_data(self, data):
        url = "https://vcbbiz1.pay2world.vip/eximbank/encrypt"
        payload = json.dumps(data)
        headers = {
        'Content-Type': 'application/json',
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        return json.loads(response.text)
    def decrypt_data(self, cipher):
        url = "https://vcbbiz1.pay2world.vip/eximbank/decrypt"

        payload = json.dumps(cipher)
        headers = {
        'Content-Type': 'application/json',
        }
        response = requests.request("POST", url, headers=headers, data=payload)

        return json.loads(response.text)

    def curl_post(self, url, data, headers=None):
        try:
            headers = self.header_null(headers)
            encrypted_data = self.encrypt_data(data)
            # self.load_cookies()
            # if test:
            #     response = self.session.post(url, headers=headers, data=json.dumps({"d":"OaPnaeUM0dwdLivAj4m/8xqErTtuDcqL6JsNQjNt5nowJhAsAKxOjOHt0Dy3Fqd69b5+kLDsqxoi/d5tbheKlOdElTNuKYQ1ANkdsTIwATlALF6Se0YV4h76DviOWST5E3psAOV5r1NPgWwSLNy0Iw3jqRO4D3bmyqRSgGxkhK0oKrXovRc61vXfmVzNaa+s+Tp7Wo6WW6mbayFYJjHmqs0Vh8XwIdxQnCkTFudJXmwffGKQVxSwd5c2VBq/lKxrUMVxWf/8ihUS6upvTNhGE3PcuNuMPd0AqUnBP+r6InPSYFkRlIsVuA05YcjdCVc0d9ax2EC5avGFa7BPNwZ6tJN98beBkofa3VXBDDk0wNGTuN7yUqRUHg08dCPSguC1dxkWgXN7b0jiOcItzEqnKqoDZUWKjbhFo7lHCiKbUW+t8grETqJK5rlbXsbhtyr6dq7z9f0AvQpMXl6Qab23XfXT8GQ9oMUPRONVgmcWKyi7kmhrrPyk4BBkeglYmYKHD2Y546GBvrGtUum9vVMdU+Qmna6rjmMhAdHM+7fQpvTt+AvY8Wc/OEKKCWRPUHfqtkdyF3aMaI0gZJYEyJUSxh1ACbZj+g5X5kt+6RvA6LNTISwKQEebnffcxbYekfU2","k":"bGFkH6ZFF8l57AxMDqSohKJASgHVVpSOkAGqb4nW+ZdBNOIl0xhFiJ3bQc8Yna8YtK+XyB+0s+WlKgWaApMNYuIb2CXmOv+UeIbuvuMoxcncqHKGTDVOZRfCnWaNZ5TDajPIwp0VuCzdRjbEy7weZUitkK1QKE6fHo/J4Ph27qjHRZ1oXQxiE6vzrVReCn4Z31Ez4jBt5/OJPP4ea7Kt/9Hcot1cD9lSS2M/W3zEGR64wpG11nsgBY4rsikeKUxBzReSdzUE6N639Eobs9/8B8FG/6da2kDEpZo+7u4hWtTjgt5yXjKT2dbr4kg6R1GJQta1whVQi5k0enduEuOnug=="}), timeout=self.timeout)
            # else:
            response = self.session.post(url, headers=headers, data=json.dumps(encrypted_data), timeout=self.timeout,proxies=self.proxies)
            self.save_cookies(self.session.cookies)
            result = response.json()
            self.auth_token = response.headers.get("Authorization")
            return self.decrypt_data(result)
        except requests.exceptions.RequestException as e:
            if e.response.status_code == 403:
                return {"success": False, "msg": "Token hết hạn vui lòng đăng nhập lại"}

            response = e.response.content.decode("utf-8")
            return self.decrypt_data(json.loads(response))

    def header_null(self, headers=None):
        default_headers = {
            'Accept': 'application/json',
            'Accept-Language': 'vi',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Origin': 'https://edigi.eximbank.com.vn',
            'Referer': 'https://edigi.eximbank.com.vn/dang-nhap',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            "X-Request-ID": random_number_string(15),
            'sec-ch-ua': '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
            }
        if headers:
            default_headers.update(headers)
        if self.auth_token:
            default_headers['Authorization'] = self.auth_token
        return default_headers

    def get_user_agent(self):
        user_agent_array = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36"
        ]
        return random.choice(user_agent_array)


