import ssl
import re
import socket


def checker_ssl_altname(hostname):
    context = ssl.create_default_context()
    with context.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
        sock.connect((hostname, 443))
        cert = sock.getpeercert()
        alt_names = cert.get('subjectAltName', [])
        alt_names_list = [name[1] for name in alt_names if name[0].lower() == 'dns']
        # remove leading "*." from alt names
        alt_names_list = [re.sub(r'^\*\.', '', name) for name in alt_names_list]
        return alt_names_list  # Online Python compiler (interpreter) to run Python online.


# print(checker_ssl_altname('www.i.ua'))

link = ['i.ua']
link += checker_ssl_altname('i.ua')
print(link)