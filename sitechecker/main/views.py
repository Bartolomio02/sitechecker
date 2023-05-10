from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from .forms import LoginForm
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import AllowAny
import subprocess
from django.http import JsonResponse
from check_domains import scan_domains
from django.http import StreamingHttpResponse
from concurrent.futures import ThreadPoolExecutor
import requests
import json
import socket
import http.client
import ssl
import re
import time
from threading import Lock
from threading import Semaphore




# Create your views here.

@login_required(login_url='/login')
def index(request):
    if request.is_ajax():
        # process ajax request
        return JsonResponse({'message': 'Hello, AJAX!'})
    else:
        return render(request, 'main/index.html')


@authentication_classes([])
@permission_classes([AllowAny])
class ScanHost(APIView):
    def post(self, request, *args, **kwargs):
        site = request.data.get('site')
        adding_domains = request.data.get('add_domain')
        site = site.replace('https://', '')
        print('adding dom', str(adding_domains))
        if str(adding_domains) == 'false':
            result_mx = subprocess.run(['host', '-t', 'MX', site], stdout=subprocess.PIPE)
            result_ns = subprocess.run(['host', '-t', 'MX', site], stdout=subprocess.PIPE)
            output = result_mx.stdout.decode('utf-8') + result_ns.stdout.decode('utf-8')
            output = output.split('\n')
            output = [i for i in output if i != '']
            output = [i.split(' ')[-1][0:-1] for i in output]
            output_html = ''
            for i in output:
                if i != 'recor':
                    if i != 'record':
                        if i != '3(NXDOMAIN':
                            if i != '3(NXDOMAIN)':
                                output_html += f'<li class="host-item"><div class="host-item__name"><span class="host-item__name-text">{i}</span><button class="host-item__name-scan">Scan</button><button class="host-item__name-del"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16"><path d="M1 1l14 14M15 1L1 15" stroke-width="2" stroke-linecap="round"/></svg></button></div></li>'
            return Response({'host': output_html})
        else:
            site_list = [site] + scan_domains(f'https://www.{site}/')
            output = ''
            for i in site_list:
                if i != '':
                    if i != 'recor':
                        if i != 'record':
                            if i != '3(NXDOMAIN':
                                if i != '3(NXDOMAIN)':
                                    try:
                                        result_mx = subprocess.run(['host', '-t', 'MX', i], stdout=subprocess.PIPE)
                                        result_ns = subprocess.run(['host', '-t', 'MX', i], stdout=subprocess.PIPE)
                                        output += result_mx.stdout.decode('utf-8') + result_ns.stdout.decode('utf-8')
                                    except PermissionError:
                                        continue
            output = output.split('\n')
            output = [i for i in output if i != '']
            output = [i.split(' ')[-1][0:-1] for i in output]
            output_html = ''
            for i in output:
                if i != 'recor':
                    if i != 'record':
                        if i != '3(NXDOMAIN':
                            if i != '3(NXDOMAIN)':
                                output_html += f'<li class="host-item"><div class="host-item__name"><span class="host-item__name-text">{i}</span><button class="host-item__name-scan">Scan</button><button class="host-item__name-del"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16"><path d="M1 1l14 14M15 1L1 15" stroke-width="2" stroke-linecap="round"/></svg></button></div></li>'
            return Response({'host': output_html})

    def get(self, request, *args, **kwargs):
        site = request.GET.get('site')
        site = site.replace('https://', '')
        result_mx = subprocess.run(['host', '-t', 'MX', site], stdout=subprocess.PIPE)
        result_ns = subprocess.run(['host', '-t', 'MX', site], stdout=subprocess.PIPE)
        output = result_mx.stdout.decode('utf-8') + result_ns.stdout.decode('utf-8')
        output = output.split('\n')
        output = [i for i in output if i != '']
        output = [i.split(' ')[-1][0:-1] for i in output]
        return Response({'host': output})


@authentication_classes([])
@permission_classes([AllowAny])
class ScanHostDetails(APIView):
    def post(self, request, *args, **kwargs):
        auto_scan = request.data.get('auto-scan')
        auto_adding_domains = request.data.get('auto-adding-domains')
        site = request.data.get('site')
        site = site.replace('https://', '')
        accordionItemsCount = request.data.get('accordionItemsCount')
        accordionhtml = request.data.get('accordionhtml')
        thread_count = request.data.get('thread-count')
        thread_count = int(thread_count)
        scan_ports = request.data.get('scan-ports')
        try:
            scan_ports = scan_ports.split(',')
        except AttributeError:
            scan_ports = None
        if scan_ports == ['']:
            scan_ports = None
        print('scan_ports', scan_ports)
        print('auto_scan', auto_scan)
        print('auto_adding_domains', str(auto_adding_domains))
        site_list = [site]
        if str(auto_scan) == 'True':

            if str(auto_adding_domains) == 'True':
                site_list += checker_ssl_altname(site)
                print(f"site_list: {site_list}")
                site_list_filter = []
                site_list_no_filter = []
                site_list_filter = []
                for site in site_list:
                    if site != '':
                        site = site.rstrip(".")
                        mail_list = mail_check(site)
                        ns_list = ns_check(site)
                        mail_ns_list = mail_list + ns_list
                        site_list_filter.append(site)
                        print(f"mail_ns_list: {mail_ns_list}")
                        for x in mail_ns_list:
                            if x != 'recor':
                                if x != 'record':
                                    if x != '3(NXDOMAIN':
                                        if x != '3(NXDOMAIN)':
                                            x = x.split(' ')[-1].rstrip(".")
                                            if x.endswith(site):
                                                if x not in site_list_filter:
                                                    site_list_filter.append(x)
                    else:
                        site_list.pop(site_list.index(site))
                print(f"site_list_filter: {site_list_filter}")
                site_count_list = []
                for i, x in enumerate(site_list_filter):
                    site_count_list.append((x, i + int(accordionItemsCount), scan_ports))
                return StreamingHttpResponse(process_data(site_count_list, site_list, thread_count))
            mail_list = mail_check(site)
            ns_list = ns_check(site)
            site_list_no_filter = [site] + mail_list + ns_list
            site_list = []
            for x in site_list_no_filter:
                x = x.split(' ')[-1].rstrip(".")
                if x.endswith(site):
                    site_list.append(x)
            site_count_list = []
            for i, x in enumerate(site_list):
                site_count_list.append((x, i + int(accordionItemsCount), scan_ports))

            return StreamingHttpResponse(process_data(site_count_list, worker_count=thread_count))
        else:
            if str(auto_adding_domains) != 'True':
                common_name, issuer, not_before, not_after = ssl_check(site)
                mail_list = mail_check(site)
                ns_list = ns_check(site)
                cname_list = cname_check(site)
                ipv6_list = ipv6_check(site)
                ip_port_list = ip_port_check(site, scan_ports)
                first_ip = next(iter(ip_port_list))
                try:
                    first_port = ip_port_list[first_ip].items()
                    first_port = next(iter(first_port))[0]
                except KeyError:
                    print(ip_port_list[first_ip])
                    first_port = ''
                except StopIteration:
                    print(ip_port_list[first_ip])
                    first_port = ''

                handle, startaddress, endaddress, name, type_, parenthandle, country = check_rdap(first_ip)
                ssl_error = ''
                output = {
                    'peername': f'[ "{first_ip}", {first_port} ]',
                    'common_name': common_name,
                    'issuer': issuer,
                    'not_before': not_before,
                    'not_after': not_after,
                    'mail_list': mail_list,
                    'ns_list': ns_list,
                    'cname_list': cname_list,
                    'ipv6_list': ipv6_list,
                    'ip_port_list': ip_port_list,
                    'network': {
                        'handle': handle,
                        'startaddress': startaddress,
                        'endaddress': endaddress,
                        'name': name,
                        'type': type_,
                        'parenthandle': parenthandle,
                        'country': country
                    }
                }
                output_html = generate_accordion_html(site, mail_list, ns_list, cname_list, ipv6_list, ip_port_list,
                                                      accordionItemsCount, output, ssl_error)
                return Response({'host': output_html})
            else:
                site_list = scan_domains(f'https://www.{site}/')
                site_count_list = []
                for i, x in enumerate(site_list):
                    if x != '':
                        x = x.rstrip(".")
                        site_count_list.append((x, i + int(accordionItemsCount), scan_ports))
                print(f'site_count_list: {site_count_list}')
                return StreamingHttpResponse(process_data(site_count_list, site_list, thread_count))

    def get(self, request, *args, **kwargs):
        site = request.GET.get('site')
        site = site.replace('https://', '')
        accordionItemsCount = request.GET.get('accordionItemsCount')
        accordionhtml = request.GET.get('accordionhtml')
        common_name, issuer, not_before, not_after = ssl_check(site)
        mail_list = mail_check(site)
        ns_list = ns_check(site)
        cname_list = cname_check(site)
        ipv6_list = ipv6_check(site)
        ip_port_list = ip_port_check(site)
        first_ip = next(iter(ip_port_list))
        try:
            first_port = ip_port_list[first_ip].items()
            first_port = next(iter(first_port))[0]
        except KeyError:
            print(ip_port_list[first_ip])
            first_port = ''

        handle, startaddress, endaddress, name, type_, parenthandle, country = check_rdap(first_ip)
        output = {
            'peername': f'[ "{first_ip}", {first_port} ]',
            'common_name': common_name,
            'issuer': issuer,
            'not_before': not_before,
            'not_after': not_after,
            'mail_list': mail_list,
            'ns_list': ns_list,
            'cname_list': cname_list,
            'ipv6_list': ipv6_list,
            'ip_port_list': ip_port_list,
            'network': {
                'handle': handle,
                'startaddress': startaddress,
                'endaddress': endaddress,
                'name': name,
                'type': type_,
                'parenthandle': parenthandle,
                'country': country
            }
        }
        print(accordionItemsCount)
        if accordionItemsCount == 0:
            output_html = f'<div class="accordion-item"><h2 class="accordion-header" id="heading{accordionItemsCount}"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse{accordionItemsCount}" aria-expanded="false" aria-controls="collapse{accordionItemsCount}">{site}</button></h2><div id="collapse{accordionItemsCount}" class="accordion-collapse collapse" aria-labelledby="heading{accordionItemsCount}" data-bs-parent="#accordionExample"><div class="accordion-body"><div class="accordion-body__item"><div class="accordion-body__item-title">Peername</div><div class="accordion-body__item-value">{output["peername"]}</div></div><div class="accordion-body__item"><div class="accordion-body__item-title">Common name</div><div class="accordion-body__item-value">{output["common_name"]}</div></div><div class="accordion-body__item"><div class="accordion-body__item-title">Issuer</div><div class="accordion-body__item-value">{output["issuer"]}</div></div><div class="accordion-body__item"><div class="accordion-body__item-title">Not before</div><div class="accordion-body__item-value">{output["not_before"]}</div></div><div class="accordion-body__item"><div class="accordion-body__item-title">Not after</div><div class="accordion-body__item-value">{output["not_after"]}</div></div><div class="accordion-body__item"><div class="accordion-body__item-title">Mail list</div><div class="accordion-body__item-value">{output["mail_list"]}</div></div><div class="accordion-body__item"><div class="accordion-body__item-title">NS list</div><div class="accordion-body__item-value">{output["ns_list"]}</div></div><div class="accordion-body__item"><div class="accordion-body__item-title">CNAME list</div><div class="accordion-body__item-value">{output["cname_list"]}</div></div><div class="accordion-body__item"><div class="accordion-body__item-title">IPv6 list</div><div class="accordion-body__item-value">{output["ipv6_list"]}</div></div><div class="accordion-body__item"><div class="accordion-body__item-title">IP port list</div><div class="accordion-body__item-value">{output["ip_port_list"]}</div></div><div class="accordion-body__item"><div class="accordion-body__item-title">Network</div><div class="accordion-body__item-value">{output["network"]}</div></div></div></div></div>'
        return Response({'host': output})


def port_check(ip, ports=None):
    if ports is None:
        ports = [80, 443]
    open_ports = []
    print(f'Checking ports {ports}')
    for port in ports:
        port = int(port)
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


def ssl_check(site):
    result_ssl = subprocess.run([f'ssl-checker/ssl_checker.py', '-H', f'{site} -j'], stdout=subprocess.PIPE)
    output = result_ssl.stdout.decode('utf-8')
    output_dict = json.loads(output)
    try:
        common_name = output_dict[site]['issued_to']
    except KeyError:
        common_name = ''
    try:
        issuer = output_dict[site]['issuer_o']
    except KeyError:
        issuer = ''
    try:
        not_before = output_dict[site]['valid_from']
    except KeyError:
        not_before = ''
    try:
        not_after = output_dict[site]['valid_till']
    except KeyError:
        not_after = ''
    return common_name, issuer, not_before, not_after


def mail_check(site):
    result_mail = subprocess.run(['host', '-t', 'MX', site], stdout=subprocess.PIPE)
    output = result_mail.stdout.decode('utf-8')
    mail_list = output.split('\n')
    if mail_list[-1] == '':
        mail_list = mail_list[:-1]
    return mail_list


def ns_check(site):
    result_ns = subprocess.run(['host', '-t', 'NS', site], stdout=subprocess.PIPE)
    output = result_ns.stdout.decode('utf-8')
    ns_list = output.split('\n')
    if ns_list[-1] == '':
        ns_list = ns_list[:-1]
    return ns_list


def cname_check(site):
    result_cname = subprocess.run(['host', '-t', 'CNAME', site], stdout=subprocess.PIPE)
    output = result_cname.stdout.decode('utf-8')
    cname_list = output.split('\n')
    if cname_list[-1] == '':
        cname_list = cname_list[:-1]
    return cname_list


def ipv6_check(site):
    result_ip = subprocess.run(['host', '-t', 'AAAA', site], stdout=subprocess.PIPE)
    output = result_ip.stdout.decode('utf-8')
    ip_list = output.split('\n')
    if ip_list[-1] == '':
        ip_list = ip_list[:-1]
    return ip_list


def ip_port_check(site, scan_ports=None):
    result_ip_port = subprocess.run(['host', '-t', 'A', site], stdout=subprocess.PIPE)
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
        ip_port_dict[item] = port_check(item, scan_ports)
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


def ip_in_domain(domain):
    try:
        response = socket.gethostbyname(domain)
    except:
        response = ''

    return response


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


def check_rdap(ip_address):
    try:
        response = requests.get(f'https://rdap.arin.net/registry/ip/{ip_address}', timeout=5)
        response = response.json()
    except:
        return 'None', 'None', 'None', 'None', 'None', 'None', 'None'
    try:
        handle = response["handle"]
    except:
        handle = ' '
    try:
        startaddress = response["startAddress"]
    except:
        startaddress = ' '
    try:
        endaddress = response["endAddress"]
    except:
        endaddress = ' '
    try:
        name = response["name"]
    except:
        name = ' '
    try:
        type_ = response["type"]
    except:
        type_ = ' '
    try:
        parenthandle = response["parentHandle"]
    except:
        parenthandle = ' '
    try:
        country = response["country"]
    except:
        country = 'None'
    return handle, startaddress, endaddress, name, type_, parenthandle, country


def process_value(site):
    # обработка значения в потоках
    site, accordionItemsCount, scan_ports = site
    if 'cdn' in site:
        return Response({'host': ' '})
    print(site, accordionItemsCount)
    common_name, issuer, not_before, not_after = ssl_check(site)
    mail_list = mail_check(site)
    ns_list = ns_check(site)
    cname_list = cname_check(site)
    ipv6_list = ipv6_check(site)
    ip_port_list = ip_port_check(site, scan_ports)
    first_ip = next(iter(ip_port_list))
    try:
        first_port = ip_port_list[first_ip].items()
        first_port = next(iter(first_port))[0]
    except KeyError:
        first_port = ' '
    except StopIteration:
        first_port = ' '

    handle, startaddress, endaddress, name, type_, parenthandle, country = check_rdap(first_ip)
    ssl_error = ''
    output = {
        'peername': f'[ "{first_ip}", {first_port} ]',
        'common_name': common_name,
        'issuer': issuer,
        'not_before': not_before,
        'not_after': not_after,
        'mail_list': mail_list,
        'ns_list': ns_list,
        'cname_list': cname_list,
        'ipv6_list': ipv6_list,
        'ip_port_list': ip_port_list,
        'network': {
            'handle': handle,
            'startaddress': startaddress,
            'endaddress': endaddress,
            'name': name,
            'type': type_,
            'parenthandle': parenthandle,
            'country': country
        }
    }
    output_html = generate_accordion_html(site, mail_list, ns_list, cname_list, ipv6_list, ip_port_list,
                                          accordionItemsCount, output, ssl_error)
    print('yes')
    return Response({'host': output_html})


def process_data(site_list, domain_list=None, worker_count=1):
    if domain_list is None:
        domain_list = [site_list[0][0]]
    results = []
    semaphore = Semaphore(value=1)
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        # запускаем обработку каждого значения в потоке
        futures = [executor.submit(process_value, site) for site in site_list]
        # получаем результат каждой задачи, как только она завершится
        for future in futures:
            result = future.result()
            results.append(result)
            print('len result', len(results))

            # result_data = escape_json_string(str(result.data))
            # преобразуем результат в json
            print('result.data', result.data)

            # # блокируем доступ к генератору до тех пор, пока другой поток не закончит получение текущего элемента
            # with lock:
            #     # отдаем результат через StreamingHttpResponse
            #     time.sleep(0.1)
            #     yield response_json
            # ждем освобождения мьютекса
            semaphore.acquire()
            try:
                # отдаем результат через StreamingHttpResponse
                response_json = json.dumps(result.data, ensure_ascii=False)
                time.sleep(0.1)
                print(f'len response_json {len(response_json)}')
                yield response_json
            finally:
                # освобождаем семафор
                semaphore.release()
        # print(f'len site_list {len(site_list)}')
        # for result in executor.map(process_value, site_list):
        #     results.append(result)
        #     print('len result', len(results))
        #
        #     print('result.data', result.data)
        #     response_json = json.dumps(result.data, ensure_ascii=False)
        #
        #     # отдаем результат через StreamingHttpResponse
        #     time.sleep(0.1)
        #     yield response_json

    # отдаем итоговый результат
    # print(results)
    # result = ''
    # for i in results:
    #     result += i.data['host']
    # print(result)
    # print('last response')
    for domain in domain_list:
        response_json = json.dumps({'domain': domain}, ensure_ascii=False)
        time.sleep(0.1)
        yield response_json


def generate_accordion_html(site, mail_list, ns_list, cname_list, ipv6_list, ip_port_list, accordionItemsCount, output,
                            ssl_error):
    mail_list_html = ''
    for i in mail_list:
        i = i.rstrip(".")
        site = i.split(" ")[0]
        mail = i.split(" ")[-1]
        i = i.replace(f"{site} ", '')
        i = i.replace(mail, "")
        mail_list_html += f'<li class="detail-info"><span class="green-text">{site} </span> {i}<span class="green-text" style="margin-left: 3px;">{mail}<span></li>'
    ns_list_html = ''
    for i in ns_list:
        i = i.rstrip(".")
        site = i.split(" ")[0]
        ns = i.split(" ")[-1]
        i = i.replace(f"{site} ", '')
        i = i.replace(ns, "")
        ns_list_html += f'<li class="detail-info"><span class="green-text">{site} </span> {i}<span class="green-text" style="margin-left: 3px;">{ns}<span></li>'
    cname_list_html = ''
    for i in cname_list:
        i = i.rstrip(".")
        site = i.split(" ")[0]
        cname = i.split(" ")[-1]
        i = i.replace(f"{site} ", '')
        i = i.replace(cname, "")

        cname_list_html += f'<li class="detail-info"><span class="green-text">{site} </span>{i} <span class="green-text">{cname}</span></li>'
    ipv6_list_html = ''
    for i in ipv6_list:
        i = i.rstrip(".")
        site = i.split(" ")[0]
        ipv6 = i.split(" ")[-1]
        i = i.replace(f"{site} ", '')
        i = i.replace(ipv6, "")
        ipv6_list_html += f'<li class="detail-info"><span class="green-text">{site} </span>{i} <span class="green-text">{ipv6}</span></li>'
    ip_port_list_html = ''
    for i in ip_port_list:
        ip_port_list_html += f'<li class="detail-info"><span class="green-text">{i.rstrip(".")}</span></li>'
        for j in ip_port_list[i]:
            if type(ip_port_list[i][j]) == list:
                if ip_port_list[i][j][1] == "valid":
                    ip_port_list_html += '<ul class="detail">'
                    ip_port_list_html += f'<li class="detail-info"><span class="green-text">{j} </span>Server: <span class="green-text" style="margin-left: 3px;">{ip_port_list[i][j][0]} </span> SSL: <span class="green-text" style="margin-left: 3px;">{ip_port_list[i][j][1]}</span> </li>'
                    ip_port_list_html += '</ul>'
                else:
                    ssl_valide = ip_port_list[i][j][1].split(" ")
                    ip_port_list_html += '<ul class="detail">'
                    ip_port_list_html += f'<li class="detail-info"><span class="green-text">{j} </span>Server: <span class="green-text" style="margin-left: 3px;">{ip_port_list[i][j][0]} </span> SSL: <span class="red-text" >{ssl_valide[0]} </span> <span class="green-text" style="margin-left: 3px;">{ssl_valide[1]}</span> </li>'
                    ip_port_list_html += '</ul>'
            else:
                ip_port_list_html += '<ul class="detail">'
                ip_port_list_html += f'<li class="detail-info"><span class="green-text">{j} </span> Server: <span class="green-text" style="margin-left: 3px;">{ip_port_list[i][j]}</span></li>'
                ip_port_list_html += '</ul>'
        for j in ip_port_list[i]:
            if j == 443: # проверка на наличие 443 порта новая строчка
                try:
                    if ip_port_list[i][j][1] == "not valid":
                        ssl_error = '''<img src="/static/main/img/ssl.png" alt="error" class="error-img">'''
                        break
                except TypeError:
                    ssl_error = '''<img src="/static/main/img/ssl.png" alt="error" class="error-img">'''
                    print(f"TypeError {ip_port_list}")
                    break

    output_html = f'''<div class="accordion-item my-accordion-item">
            <h2 class="accordion-header" id="heading{accordionItemsCount}">
                <button class="accordion-button collapsed my-accordion-button" type="button"
                        data-bs-toggle="collapse" data-bs-target="#collapse{accordionItemsCount}"
                        aria-expanded="false" aria-controls="collapse{accordionItemsCount}">
                    <div class="title">
                    <div class="accordion-numbers">{str(int(accordionItemsCount) + 1)}</div>
                    <div class="accordion-title">{site}</div>
                    </div>
                    <div class="title">
                    <div class="">{ssl_error}</div>
                    <a class="accordion-delete"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16"><path d="M1 1l14 14M15 1L1 15" stroke-width="2" stroke-linecap="round"/></svg>
                    </a>
                    </div>
                </button>
            </h2>
            <div id="collapse{accordionItemsCount}" class="accordion-collapse collapse"
                 aria-labelledby="heading{accordionItemsCount}" data-bs-parent="#accordionExample">
                <div class="accordion-body detail-info-main">
                    <ul class="main-detail-category">
                        <li class="detail-category">
                            <span class="title-category">SSL:</span>
                            <ul class="detail">
                                <li class="detail-info"><div class="info"><span class="green-text">peername:</span> {output["peername"]}<div></li>
                                <li class="detail-info"><span class="green-text">commonname: </span> {output["common_name"]}</li>
                                <li class="detail-info"><span class="green-text">issuer: </span> {output["issuer"]}</li>
                                <li class="detail-info"><span class="green-text">notbefore: </span> {output["not_before"]}</li>
                                <li class="detail-info"><span class="green-text">notafter: </span> {output["not_after"]}</li>
                            </ul>
                        </li>
                        <li class="detail-category">
                            Mail:
                            <ul class="detail">
                                {mail_list_html}
                            </ul>
                        </li>
                        <li class="detail-category">
                            NS:
                            <ul class="detail">
                                {ns_list_html}
                            </ul>
                        </li>
                        <li class="detail-category">
                            Cname:
                            <ul class="detail">
                                {cname_list_html}
                            </ul>
                        </li>
                        <li class="detail-category">
                            Ipv6:
                            <ul class="detail">
                                {ipv6_list_html}
                            </ul>
                        </li>
                        <li class="detail-category">
                            Ip + ports:
                            <ul class="detail">
                                {ip_port_list_html}
                            </ul>
                        </li>
                        <li class="detail-category">
                            Network:
                            <ul class="detail">
                                <li class="detail-info"><span class="green-text">handle: </span>{output['network']["handle"]}</li>
                                <li class="detail-info"><span class="green-text">startAddress: </span>{output['network']["startaddress"]}</li>
                                <li class="detail-info"><span class="green-text">endAddress: </span>{output['network']["endaddress"]}</li>
                                <li class="detail-info"><span class="green-text">name: </span>{output['network']["name"]}</li>
                                <li class="detail-info"><span class="green-text">type: </span>{output['network']["type"]}</li>
                                <li class="detail-info"><span class="green-text">parentHandle: </span>{output['network']["parenthandle"]}</li>
                                <li class="detail-info"><span class="green-text">country: </span>{output['network']["country"]}</li>
                            </ul>
                        </li>
                    </ul>
                </div>
            </div>
        </div>'''
    return output_html



def login(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]  # получаем данные из формы
            password = form.cleaned_data["password"]
            print(email, password)
            user = authenticate(request, email=email, password=password)  # аутентифицируем пользователя
            if user is not None:
                print("user is not None")
                auth_login(request, user)  # авторизуем пользователя
                return redirect("main")
            else:
                form.add_error(None, "Неверный логин или пароль")  # добавляем ошибку в форму
    else:
        form = LoginForm()
    return render(request, "main/login.html", {"form": form})


def logout(request):
    auth_logout(request)
    return redirect("main")


def checker_ssl_altname(hostname):
    context = ssl.create_default_context()
    with context.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
        sock.connect((hostname, 443))
        cert = sock.getpeercert()
        alt_names = cert.get('subjectAltName', [])
        alt_names_list = [name[1] for name in alt_names if name[0].lower() == 'dns']
        # remove leading "*." from alt names
        alt_names_list = [re.sub(r'^\*\.', '', name) for name in alt_names_list]
        return list(set(alt_names_list))