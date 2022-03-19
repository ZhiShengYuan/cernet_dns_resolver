from ipaddress import ip_network
import requests
import dns.resolver
from dns.resolver import Resolver
from dnslib import DNSRecord, QTYPE, RD, SOA, DNSHeader, RR, A
import socket
import logging

CernetIpCidrList = ['1.51.0.0/16', '1.184.0.0/15', '42.244.0.0/14', '43.252.48.0/22', '49.52.0.0/14', '49.120.0.0/14',
                    '49.140.0.0/15', '49.208.0.0/15', '58.154.0.0/15', '58.192.0.0/12', '59.64.0.0/12', '101.4.0.0/14',
                    '101.76.0.0/15', '103.81.200.0/22', '103.87.20.0/22', '103.115.120.0/22', '103.137.60.0/24',
                    '103.165.110.0/23', '103.205.162.0/24', '103.226.80.0/22', '110.64.0.0/15', '111.114.0.0/15',
                    '111.116.0.0/15', '111.186.0.0/15', '113.54.0.0/15', '114.212.0.0/15', '114.214.0.0/16',
                    '115.24.0.0/14', '115.154.0.0/15', '115.156.0.0/15', '115.158.0.0/16', '116.13.0.0/16',
                    '116.56.0.0/15', '118.202.0.0/15', '118.228.0.0/15', '118.230.0.0/16', '120.94.0.0/15',
                    '121.48.0.0/15', '121.52.160.0/19', '121.192.0.0/14', '121.248.0.0/14', '122.204.0.0/14',
                    '125.216.0.0/13', '175.185.0.0/16', '175.186.0.0/15', '180.84.0.0/15', '180.201.0.0/16',
                    '180.208.0.0/15', '183.168.0.0/15', '183.170.0.0/16', '183.172.0.0/14', '192.124.154.0/24',
                    '202.4.128.0/19', '202.38.2.0/23', '202.38.64.0/18', '202.38.140.0/23', '202.38.146.0/23',
                    '202.38.184.0/21', '202.38.192.0/18', '202.112.0.0/13', '202.120.0.0/15', '202.127.216.0/21',
                    '202.127.224.0/19', '202.179.240.0/20', '202.192.0.0/12', '203.91.120.0/21', '210.25.0.0/16',
                    '210.26.0.0/15', '210.28.0.0/14', '210.32.0.0/12', '211.64.0.0/13', '211.80.0.0/13',
                    '218.192.0.0/13', '219.216.0.0/13', '219.224.0.0/13', '219.242.0.0/15', '219.244.0.0/14',
                    '222.16.0.0/12', '222.192.0.0/12', '223.2.0.0/15', '223.128.0.0/15']
CERNETDnsResolver = Resolver()
CERNETDnsResolver.nameservers = ['101.7.8.9']  # this is the dns of cernet
Basic_Doh_Url = 'https://101.6.6.6:8443/dns-query?'
Doh_Header = {'accept': 'application/dns-json'}
TencentResolver = Resolver()
TencentResolver.nameservers = ['223.5.5.5']  # this is the dns of tencent


def get_cernet_ip(domain):
    domain = domain.lower().strip()
    try:
        ip = CERNETDnsResolver.resolve(domain, 'A')
        return ip[0].to_text()
    except Exception as e:
        print(e)
        return None


def cernet_doh_query_json(domain):
    try:
        requesturl = Basic_Doh_Url + 'name=' + domain + '&type=A'
        response = requests.get(requesturl, headers=Doh_Header)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception as e:
        print(e)
        return None


def parse_json(json):
    if json is None:
        return None
    try:
        if json['Status'] == 0:
            if json['Answer'] is not None:
                for answer in json['Answer']:
                    if answer['type'] == 1:
                        return answer['data']
    except Exception as e:
        print(e)
        return None


def cernet_doh(domain):
    json = cernet_doh_query_json(domain)
    print(json)
    ip = parse_json(json)
    print(ip)
    if ip is not None:
        return ip
    return None


def normal_query_dns(domain):
    try:
        ip = TencentResolver.resolve(domain, 'A')
        return ip[0].to_text()
    except Exception as e:
        print(e)
        return None


def is_cernet_ip(ip) -> bool:
    ip += '/32'
    for cidr in CernetIpCidrList:
        if ip_network(ip).subnet_of(ip_network(cidr)):
            print("The ip addr of " + ip +" Is cernet ip")
            return True
    print("The ip addr of " + ip + " NOT cernet ip")
    return False


def query(domain):
    ip = cernet_doh(domain)
    if ip is not None:
        if is_cernet_ip(ip):
            return ip
        else:
            return normal_query_dns(domain)

def get_ip_from_domain(domain):
    return query(domain)

def reply_for_not_found(income_record):
    header = DNSHeader(id=income_record.header.id, bitmap=income_record.header.bitmap, qr=1)
    header.set_rcode(0)  # 3 DNS_R_NXDOMAIN, 2 DNS_R_SERVFAIL, 0 DNS_R_NOERROR
    record = DNSRecord(header, q=income_record.q)
    return record


def reply_for_A(income_record, ip, ttl=None):
    r_data = A(ip)
    header = DNSHeader(id=income_record.header.id, bitmap=income_record.header.bitmap, qr=1)
    domain = income_record.q.qname
    query_type_int = QTYPE.reverse.get('A') or income_record.q.qtype
    record = DNSRecord(header, q=income_record.q, a=RR(domain, query_type_int, rdata=r_data, ttl=ttl))
    return record


def dns_handler(s, message, address):
    try:
        income_record = DNSRecord.parse(message)
    except:
        logging.error('from %s, parse error' % address)
        return
    try:
        qtype = QTYPE.get(income_record.q.qtype)
    except:
        qtype = 'unknown'
    domain = str(income_record.q.qname).strip('.')
    info = '%s -- %s, from %s' % (qtype, domain, address)
    if qtype == 'A':
        ip = get_ip_from_domain(domain)
        if ip:
            response = reply_for_A(income_record, ip=ip, ttl=60)
            s.sendto(response.pack(), address)
            return logging.info(info)
    # at last
    response = reply_for_not_found(income_record)
    s.sendto(response.pack(), address)
    logging.info(info)

if __name__ == '__main__':
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(('', 53))
    logging.info('dns server is started')
    while True:
        message, address = udp_sock.recvfrom(8192)
        dns_handler(udp_sock, message, address)

print(query('mirrors.ustc.edu.cn'))