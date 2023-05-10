import re
import json
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import socket
import subprocess
import http.client
import ssl

def scan_domains(site):
    options = Options()
    # options.binary_location = "/usr/bin/firefox"
    options.add_argument('--headless')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--no-sandbox')

    driver = webdriver.Chrome('static/chromedriver', options=options)
    # driver = webdriver.Chrome('static/chromedriver_linux', options=options)
    # driver = webdriver.Firefox('/usr/local/bin/')
    # driver.set_page_load_timeout(20)
    #driver.implicitly_wait(1)
    driver.get(site)
    html = driver.page_source
    driver.quit()
    #print(html)

    myArray = []
    myArrayDash = []
    myArrayDash2 = []
    mySetDash = ()

    result = re.findall(r'(src=\'|src="|href=")((http|//).*?)"', html)
    for r in result:
        #print(r[1])
        #print(r)
        myArray.append(r[1])
        for i in myArray:
            index = i.split('//'[1])
            #print(index)
            index_clear = index[2].split('?')
            #print(index_clear[0], 'index_clear')
            myArrayDash.append(index_clear[0])
            #myArrayDash.append(index[2])
            #print(index[2])
    #print(myArrayDash)
    mySetDash = set(myArrayDash)

    response = []
    for i in mySetDash:
        if not i in response:
            response.append(i)

    return response


    # for i in mySetDash:
    #     print(i)

# result = scan_domains('https://www.i.ua/')
# for i, v in enumerate(result):
#     print(i, v)


def port_check(ip, ports=None):
    if ports is None:
        ports = [80, 443]
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        # print(f'Checking port {ip}:{port}')
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except socket.gaierror:
            print(f'Cannot resolve hostname {ip}')
    return open_ports

def get_server_type(ip, port):
    conn = http.client.HTTPConnection(ip, port)
    conn.request("HEAD", "/")
    try:
        res = conn.getresponse()
    except http.client.RemoteDisconnected:
        return 'Disconnected'
    except ConnectionResetError:
        return 'Connection reset'
    server_type = res.getheader("Server")
    conn.close()
    return server_type


def check_ssl(ip_address, hostname):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((ip_address, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                ssl.match_hostname(cert, hostname)
                return 'valid'
    except ssl.CertificateError:
        return 'not valid'


def ip_port_check(site):
    result_ip_port = subprocess.run(['ubuntu', '-c', f'host -t A {site}'], stdout=subprocess.PIPE)
    output = result_ip_port.stdout.decode('utf-8')
    ip_port_list = output.split('\n')
    ip_port_dict = {}
    for index, item in enumerate(ip_port_list):
        item = item.rstrip('.')
        if item == '':
            ip_port_list.pop(index)
            continue
        # if item != 'record':
        item = item.split(' ')[-1]
        ip_port_list[index] = item
        ip_port_dict[item] = port_check(item)
    port_server = {}
    for ip, port in ip_port_dict.items():
        if port:
            for p in port:
                if p == 443:
                    port_server[p] = [get_server_type(ip, p), check_ssl(ip, site)]
                else:
                    port_server[p] = get_server_type(ip, p)
        ip_port_dict[ip] = port_server

    return ip_port_dict

