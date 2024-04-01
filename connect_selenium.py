import os
import sys
import time
from selenium import webdriver
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.edge.service import Service as EdgeService
from webdriver_manager.microsoft import EdgeChromiumDriverManager
from selenium.webdriver.common.by import By


def count_lines(filename):
    lines = 0
    if os.path.exists(filename):
        with open(filename, "r") as f:
            for _ in f:
                lines += 1
    return lines


def truncate_line(filename, n):
    lines = 0
    with open(filename, "r+") as f:
        for _ in f:
            lines += 1
            if lines >= n:
                f.truncate()
                f.write("\n")
                break
    return


def log(info):
    time_str = "At " + time.strftime("%Y-%m-%d %H:%M:%S",
                                     time.localtime()) + " "
    log_file = os.environ.get("AUTO_CONNECT_HUSTNET_LOG_FILE", "connect.log")
    n_lines = count_lines(log_file)
    if n_lines > 500:
        truncate_line(log_file, 500)
    print(time_str + info.strip())
    with open(log_file, "a") as f:
        f.write(time_str + info.strip() + "\n")


def update_webdriver():
    driver_file = os.environ.get("AUTO_CONNECT_HUSTNET_DRIVERPATH_FILE",
                                 "driver_path.txt")
    try:
        # 更新webdriver
        driver_path = EdgeChromiumDriverManager().install()
        # 将当前driver path写入文件
        with open(driver_file, "w") as f:
            f.write(driver_path.strip())
        log("update webdriver")
    except Exception as e:
        log("update webdriver failed: " + e)
    return


def login(username: str, password: str):
    # selenium 配置
    options = EdgeOptions()
    options.add_argument("headless")
    # options.binary_location = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"  # 浏览器的位置

    # 此时无网络
    driver_file = os.environ.get("AUTO_CONNECT_HUSTNET_DRIVERPATH_FILE",
                                 "driver_path.txt")
    if not os.path.exists(driver_file):
        log(driver_file + " not found")
        return
    with open(driver_file, "r") as f:
        driver_path = f.readline()
    if not os.path.exists(driver_path):
        log(driver_path + " not found")
        return
    driver = webdriver.Edge(service=EdgeService(driver_path), options=options)
    try:
        driver.get("http://1.1.1.1")
        uri = driver.current_url.split(":")[-1]
        if not str.startswith(uri, r"8080/eportal/index.jsp"):
            log("Network have connnected")
        else:
            username_tip = driver.find_element(By.ID, "username")
            username_tip.send_keys(username)

            pwd_posi = driver.find_element(By.ID, "pwd_hk_posi")
            pwd_posi.click()
            pwd_tip = driver.find_element(By.ID, "pwd")
            pwd_tip.send_keys(password)

            login_Link = driver.find_element(By.ID, "loginLink")
            login_Link.click()
            log("Login success!")
    except Exception as e:
        log("An error occured:\n" + e)
    finally:
        driver.quit()
    return


def ping(host, n):
    cmd = "ping {} {} {} -w 1000 > ping.log".format(
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
        username = f.readline()
        password = f.readline()
        if username == "" or password == "":
            raise Exception("error username or password")
    return username, password


if __name__ == "__main__":
    log("Script started")
    secret_file = "secret.cfg"
    username, password = get_userinfo(secret_file)
    # login(username, password)
    while True:
        if pong():
            # 此时有网络
            update_webdriver()
            time.sleep(30)
        else:
            # 此时无网络
            login(username, password)
