import socket
import requests
from bs4 import BeautifulSoup
import nmap
from concurrent.futures import ThreadPoolExecutor


class CustomScanner:
    top_port = [66, 80, 81, 280, 443, 445, 457, 488, 591, 593, 777, 900, 1080, 1100, 1241, 1352, 1433, 1434, 1521,
                1944, 2301, 2381, 2688, 2693, 2851, 3000, 3106, 3128, 3306, 4000, 4001, 4002, 4100, 4848, 5000,
                5432, 5490, 5554, 5800, 5801, 5802, 6346, 6347, 6842, 7001, 7002, 8000, 8001, 8002, 8008, 8010,
                8080, 8081, 8181, 8443, 8765, 8888, 30821]
    def __init__(self, domains):
        self.target = domains
        self.url = f"http://{self.target}/"
        self.nmap_checker_time = 0
        self.open_ports = []
        self.port_service = []

    @property
    def ip(self):
        try:
            return socket.gethostbyname(self.target)
        except Exception as E:
            return "127.0.0.1"

    @property
    def urls(self):
        try:
            links = self.contnet.findAll('a')
            return list(map(lambda x:x.get('href'), links))
        except Exception as E:
            return [None]

    @property
    def page_title(self):
        try:
            title = self.contnet.find('title').get_text()
            return title
        except Exception as E:
            return "No Title"

    @property
    def js_urls(self):
        try:
            js_data = self.contnet.findAll('script')
            return list(map(lambda x:x.get('src'), js_data))
        except Exception as E:
            return [None]

    @property
    def body_text(self):
        try:
            b_text = self.contnet.find('body').get_text()
            return b_text.replace("\n"," ").replace("  "," ")
        except Exception as E:
            return "text"

    def request_data(self):
        r = requests.get(self.url)
        self.status_code = r.status_code
        self.header = str(r.headers)
        self.contnet_size = len(r.content.decode())
        self.contnet = BeautifulSoup(r.content.decode(), 'lxml')

    def open_port_checker(self,port):
        try:
            worker = nmap.PortScanner()
            result = worker.scan(self.ip, str(port))
            status = result['scan'][self.ip]['tcp'][port]['state']
            service_name = result['scan'][self.ip]['tcp'][port]
            service_name = str(service_name)
            service_name = service_name.replace("{","").replace("}","").replace(","," ")
            if status == 'open':
                self.open_ports.append(port)
                self.port_service.append(service_name)
        except Exception as error:
            if self.nmap_checker_time == 3:
                return "error"
            self.open_port_checker(port)

    def nmap_checker(self):
        with ThreadPoolExecutor(max_workers=10) as executor:
            for port in self.top_port:
                executor.map(self.open_port_checker, [port])
            executor.shutdown(wait=True)


target = "vishals.club"

demo = CustomScanner(target)

print(demo.ip)
print(demo.request_data())
print(demo.js_urls)
print(demo.page_title)
print(demo.body_text)
print(demo.header)
print(type(demo.header))
print(demo.nmap_checker())
print(demo.__dict__)
print(demo.open_ports)
print(demo.port_service)
