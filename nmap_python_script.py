# pip install nmap python-nmap python3-nmap

import nmap
from concurrent.futures import ThreadPoolExecutor

 # random IP from shodan.io
target = "198.50.250.87"

# Top Ports
ports = [80, 81, 593, 8010, 7001, 2688, 4100, 900, 2693, 5000, 777, 8080, 8081, 1944, 1433, 1434, 280, 4000, 4001, 4002, 2851, 3106, 5800, 5801,
         5802, 5554, 5432, 1080, 3000, 443, 3128, 445, 8765, 8888, 8000, 8001, 66, 6842, 8002, 1352, 457, 6346, 6347,
         1100, 2381, 8008, 591, 7002, 1241, 30821, 488, 3306, 4848, 1521, 5490, 8181, 8443,
         2301]


def nmap_checker(ip, port):
    worker = nmap.PortScanner()
    # print("In......")
    result = worker.scan(ip, str(port))
    try:
        status = result['scan'][ip]['tcp'][port]['state']
        service_name = result['scan'][ip]['tcp'][port]
        service_name = str(service_name)
        service_name = service_name.replace("{","").replace("}","").replace(","," ")
        print(port,status, service_name)
    except Exception as Error:
        print(Error)
        nmap_checker(ip, port)


def main(target, ports):
    with ThreadPoolExecutor(max_workers=15) as executor:
        for port in ports:
            executor.map(nmap_checker, [target], [port])
        executor.shutdown(wait=True)


main(target, ports)
