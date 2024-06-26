from math import ceil
import os
import sys
import time
import traceback
import requests
import requests.cookies
import re
# import gzip
import json
import urllib.parse


def main():
    secret_file = "secret.cfg"
    username, password = get_userinfo(secret_file)
    while True:
        try:
            main_loop(10, 60, username, password)
        except Exception as e:
            info = ""
            for s in traceback.format_exception(e):
                info += s
            log(info)


def main_loop(timeout_without_network: int, timeout_with_network: int,
              username: str, password: str):
    while True:
        origin_url = get_verification_url()
        if origin_url == None:
            if pong():
                time.sleep(timeout_with_network)
            else:
                time.sleep(timeout_without_network)
            continue
        # 获取cookies中的sessionid
        cookies = get_initial_cookies(origin_url)
        # 对 密码+">"+mac 进行加密作为password传给认证服务器
        modulus, exponent = get_modexp_from_pageinfo(origin_url, cookies)
        macstring = re.search(r"mac=(\w*)&", origin_url.query)
        if macstring == None:
            macstring = "111111111"
        else:
            macstring = macstring.group(1)
        passwordEncode = password + ">" + macstring
        passwordEncrypt = rsa_no_padding(passwordEncode, modulus, exponent)
        # 构造认证所需eportal cookies
        cookies = construct_cookies(username, passwordEncrypt, cookies)
        # 发送登录POST请求
        cookies = login(origin_url, cookies)
        # 等待
        time.sleep(2)


def count_lines(filename: str):
    lines = 0
    if os.path.exists(filename):
        with open(filename, "r") as f:
            for _ in f:
                lines += 1
    return lines


def truncate_line(filename: str, n: int):
    lines = 0
    with open(filename, "r+") as f:
        for _ in f:
            lines += 1
            if lines >= n:
                f.truncate()
                f.write("\n")
                break
    return


def log(info: str):
    time_str = "At " + time.strftime("%Y-%m-%d %H:%M:%S",
                                     time.localtime()) + " "
    log_file = os.environ.get("AUTO_CONNECT_HUSTNET_LOG_FILE", "connect2.log")
    n_lines = count_lines(log_file)
    if n_lines > 500:
        truncate_line(log_file, 500)
    print(time_str + info.strip())
    with open(log_file, "a") as f:
        f.write(time_str + info.strip() + "\n")


def rsa_no_padding(text, modulus: int, exponent: int):
    # 16进制转10进制
    text = text.encode('utf-8')
    # 字符串逆向并转换为bytes
    # 将字节转化成int型数字，如果没有标明进制，看做ascii码值
    input_nr = int.from_bytes(text, byteorder='big')
    # 计算x的y次方，如果z在存在，则再对结果进行取模，其结果等效于pow(x,y) %z
    crypt_nr = pow(input_nr, exponent, modulus)
    # 取模数的比特长度(二进制长度)，除以8将比特转为字节
    length = ceil(modulus.bit_length() / 8)
    # 将密文转换为bytes存储(8字节)，返回hex(16字节)
    crypt_data = crypt_nr.to_bytes(length, byteorder='big')
    return crypt_data.hex()


def get_verification_url() -> urllib.parse.ParseResult | None:
    urls = (
        r"http://connect.rom.miui.com/generate_204",
        r"http://connectivitycheck.platform.hicloud.com/generate_204",
        r"http://wifi.vivo.com.cn/generate_204",
        r"http://1.1.1.1",
    )

    res = None
    for url in urls:
        try:
            res = requests.get(url, allow_redirects=False, proxies=None)
        except Exception as e:
            log(str(e))

    if res == None or res.content.decode() == "":
        return None

    # 获取认证url
    origin_url = re.search(r"top.self.location.href='(.*)'",
                           res.content.decode("utf-8"))
    if origin_url == None:
        return None
    else:
        origin_url = origin_url.group(1)
    origin_url = urllib.parse.urlparse(origin_url)
    log("GET: " + origin_url.geturl())

    return origin_url


def get_onlineuserinfo(
        origin_url: urllib.parse.ParseResult,
        cookies: requests.cookies.RequestsCookieJar
    | None) -> bool:
    # http头
    headers = {
        r"Accept": "*/*",
        r"Accept-Language": r"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        r"User-Agent":
        r"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
        r"Content-Type": r"application/x-www-form-urlencoded; charset=UTF-8",
        r"Origin": origin_url._replace(path="", query="").geturl(),
        r"Referer": origin_url.geturl(),
    }

    # 获取登录信息：是否登录
    userinfourl = origin_url._replace(
        path=r"/eportal/InterFace.do",
        query=r"method=getOnlineUserInfo").geturl()
    log("POST: " + userinfourl)
    userinfores = requests.post(userinfourl,
                                data={"userIndex": ""},
                                headers=headers,
                                cookies=cookies,
                                allow_redirects=True)
    userinfo = json.loads(userinfores.content)
    if userinfo["result"] == 'fail':
        return False
    elif userinfo["result"] == 'success':
        return True
    else:
        log(userinfo)
    return True


def get_modexp_from_pageinfo(origin_url: urllib.parse.ParseResult,
                             cookies: requests.cookies.RequestsCookieJar):
    # http头
    headers = {
        r"Accept": "*/*",
        r"Accept-Language": r"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        r"User-Agent":
        r"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
        r"Content-Type": r"application/x-www-form-urlencoded; charset=UTF-8",
        r"Origin": origin_url._replace(path="", query="").geturl(),
        r"Referer": origin_url.geturl(),
    }

    # 获取登录页面上有用的信息：这是另一个接口了
    pageinfourl = origin_url._replace(path=r"/eportal/InterFace.do",
                                      query=r"method=pageInfo").geturl()
    log("POST: " + pageinfourl)
    pageinfores = requests.post(pageinfourl,
                                data={"queryString": origin_url.query},
                                headers=headers,
                                cookies=cookies,
                                allow_redirects=True)
    cookies.update(pageinfores.cookies)
    pageinfo = json.loads(pageinfores.content)
    publicKeyExponent = int(pageinfo["publicKeyExponent"], base=16)
    publicKeyModulus = int(pageinfo["publicKeyModulus"], base=16)
    return publicKeyModulus, publicKeyExponent


def construct_cookies(userId: str, passwordEncrypt: str,
                      cookies: requests.cookies.RequestsCookieJar | None):
    if cookies == None:
        cookies = requests.cookies.RequestsCookieJar()
    dicts = {
        "EPORTAL_COOKIE_SERVER": "",
        "EPORTAL_COOKIE_DOMAIN": "",
        "EPORTAL_COOKIE_SAVEPASSWORD": "true",
        "EPORTAL_COOKIE_OPERATORPWD": "",
        "EPORTAL_COOKIE_NEWV": "true",
        "EPORTAL_AUTO_LAND": "",
        "EPORTAL_USER_GROUP": urllib.parse.quote("华中科技大学"),
        "EPORTAL_COOKIE_SERVER_NAME": "",
        "EPORTAL_COOKIE_USERNAME": userId.strip(),
        "EPORTAL_COOKIE_PASSWORD": passwordEncrypt.strip(),
    }
    for key, value in dicts.items():
        cookies.set(key, value)
    return cookies


def login(origin_url: urllib.parse.ParseResult,
          cookies: requests.cookies.RequestsCookieJar) -> bool:
    loginurl = origin_url._replace(path=r"/eportal/InterFace.do",
                                   query=r"method=login").geturl()
    log("POST: " + loginurl)
    # http头
    headers = {
        r"Accept": "*/*",
        r"Accept-Language": r"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        r"User-Agent":
        r"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
        r"Content-Type": r"application/x-www-form-urlencoded; charset=UTF-8",
        r"Origin": origin_url._replace(path="", query="").geturl(),
        r"Referer": origin_url.geturl(),
    }

    # login POST请求表单
    if (not "EPORTAL_COOKIE_USERNAME" in cookies.keys()) or (
            not "EPORTAL_COOKIE_PASSWORD" in cookies.keys()):
        return False
    postdata = {
        "service": "",
        "operatorPwd": "",
        "operatorUserId": "",
        "validcode": "",
        "passwordEncrypt": "true",
        "queryString": urllib.parse.quote(origin_url.query),
        "userId":
        cookies.get("EPORTAL_COOKIE_USERNAME").strip(),  # type: ignore
        "password":
        cookies.get("EPORTAL_COOKIE_PASSWORD").strip(),  # type: ignore
    }
    # print(postdata)

    loginres = requests.post(loginurl,
                             data=postdata,
                             cookies=cookies,
                             headers=headers,
                             allow_redirects=True)
    cookies.update(loginres.cookies)
    # 解析响应体
    loginrescontent = json.loads(loginres.content)
    if loginrescontent['result'] == 'fail':
        return False
    elif loginrescontent['result'] == 'success':
        return True
    log(loginrescontent)
    return True


def get_initial_cookies(
    origin_url: urllib.parse.ParseResult
) -> requests.cookies.RequestsCookieJar:
    loginpageres = requests.get(origin_url.geturl(), allow_redirects=True)
    # page_html = loginpageres.content
    # if loginpageres.headers["Content-Encoding"].strip() == "gzip":
    #     page_html = gzip.decompress(loginpageres.content)
    return loginpageres.cookies


def ping(host, n):
    cmd = "ping {} {} {} -w 1000".format(
        "-n" if sys.platform.lower() == "win32" else "-c",
        n,
        host,
    )
    return 0 == os.system(cmd)


def pong():
    return ping("hust.edu.cn", 4) or ping("8.8.8.8", 4)


def get_userinfo(secret_file):
    if not os.path.exists(secret_file):
        with open(secret_file, 'w') as f:
            f.write(input("Username: "))
            f.write("\n")
            f.write(input("Password: "))
    with open(secret_file, 'r') as f:
        username = f.readline().strip()
        password = f.readline().strip()
        if username == "" or password == "":
            raise Exception("error username or password")
    return username, password


if __name__ == "__main__":
    main()
