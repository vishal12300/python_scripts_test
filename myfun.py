import socket
import requests
from bs4 import BeautifulSoup
import re
import nmap
from concurrent.futures import ThreadPoolExecutor


nmap_checker_times = 0


def get_ip(s):
    try:
        return socket.gethostbyname(s)
    except Exception as Error:
        return "error"


def get_all_urls(con):
    try:
        links = con.findAll('a')
        urls = list(map(lambda x:x.get('href'), links))
        return urls
    except EOFError as E:
        return "error"


def get_js_urls(con):
    try:
        js_data = con.findAll('script')
        urls = list(map(lambda x:x.get('src'), js_data))
        return urls
    except Exception as E:
        return "error"


def get_title(con):
    try:
        title = con.find('title').get_text()
        return title
    except Exception as Error:
        return "error"


def get_body_text(con):
    try:
        body_text = con.find('body').get_text()
        text = body_text.replace("\n"," ").replace("  "," ")
        return text
    except Exception as Error:
        return "error"


def get_request(s):
    url = f"http://{s}/"
    r = requests.get(url)
    print(len(r.content), r.url, r.status_code)
    con = BeautifulSoup(r.content.decode(), 'lxml')
    urls = get_all_urls(con)
    js_url = get_js_urls(con)
    content_size = len(r.content.decode())
    title = get_title(con)
    body_text = get_body_text(con)
    header = str(r.headers)
    status_code = r.status_code
    return []


def nmap_checker(ip, port):
    global nmap_checker_times
    worker = nmap.PortScanner()
    result = worker.scan(ip, str(port))
    try:
        status = result['scan'][ip]['tcp'][port]['state']
        service_name = result['scan'][ip]['tcp'][port]
        service_name = str(service_name)
        service_name = service_name.replace("{","").replace("}","").replace(","," ")
        ret_data = {'port':port, 'status':status, 'service':service_name}
        print(ret_data)
        return ret_data
    except Exception as Error:
        if nmap_checker_times == 3:
            return "Error"
        nmap_checker_times += 1
        print(nmap_checker_times)
        nmap_checker(ip, port)


def open_port(ip):
    top_port = [66, 80, 81, 280, 443, 445, 457, 488, 591, 593, 777, 900, 1080, 1100, 1241, 1352, 1433, 1434, 1521,
                 1944, 2301, 2381, 2688, 2693, 2851, 3000, 3106, 3128, 3306, 4000, 4001, 4002, 4100, 4848, 5000,
                 5432, 5490, 5554, 5800, 5801, 5802, 6346, 6347, 6842, 7001, 7002, 8000, 8001, 8002, 8008, 8010,
                 8080, 8081, 8181, 8443, 8765, 8888, 30821]
    with ThreadPoolExecutor(max_workers=15) as executor:
        for port in top_port:
            executor.map(nmap_checker, [ip],[port])
        executor.shutdown(wait=True)


domain = "vishals.club"

ip = get_ip(domain)
print(ip)

