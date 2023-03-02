import dns.resolver
from urllib.parse import * 
import socket

def check_mx_records(domain):
    try:
        answers = dns.resolver.query(domain, 'MX')
        mx_records = [answer.exchange.to_text() for answer in answers]
        return mx_records
    except dns.resolver.NXDOMAIN:
        return None

def check_spf_records(domain):
    try:
        answers = dns.resolver.query(domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                if "v=spf1" in txt_string.decode():
                    return txt_string.decode()
        return None
    except dns.resolver.NXDOMAIN:
        return None

def check_dmarc_records(domain):
    try:
        dmarc_domain = "_dmarc." + domain
        answers = dns.resolver.query(dmarc_domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                if "v=DMARC1" in txt_string.decode():
                    return txt_string.decode()
        return None
    except dns.resolver.NXDOMAIN:
        return None

def check_dkim_records(domain):
    try:
        answers = dns.resolver.query(domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                if "dkim=" in txt_string.decode():
                    return txt_string.decode()
        return None
    except dns.resolver.NXDOMAIN:
        return None

def check_reverse_dns(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return None


def mail_mis_config(domain_name):
    # url = "https://www.mollie.com/"
    url="https://"+domain_name

    parse_url = urlparse(url)
    print(parse_url)
    print(parse_url.netloc)
    domain=parse_url.netloc
    if domain.startswith('www.'):
        domain = domain[4:]
    print(domain)

    ip_address = socket.gethostbyname(domain)

    try:
        mx_records = check_mx_records(domain)
        if mx_records:
            print("MX Records: ")
            print(mx_records)
            print()
        else:
            print("No MX Records found.")
    except:
        print("dns.resolver.NoAnswer: The DNS response does not contain an answer to the question: "+domain+" IN TXT")
    try:
        spf_records = check_spf_records(domain)
        if spf_records:
            print("SPF Records:"+spf_records)
            print(type(spf_records))
        else:
            print("No SPF Records found.")
    except:
        spf_records=None
        print("dns.resolver.NoAnswer: The DNS response does not contain an answer to the question: "+domain+" IN TXT")
    try:
        dmarc_records = check_dmarc_records(domain)
        if dmarc_records:
            print("DMARC Records:"+dmarc_records)
        else:
            print("No DMARC Records found.")
    except:
        print("dns.resolver.NoAnswer: The DNS response does not contain an answer to the question: "+domain+" IN TXT")

    # dkim_records = check_dkim_records(domain)
    try:
        reverse_dns = check_reverse_dns(ip_address)
        if reverse_dns:
            print("Rerverse DNS Records:"+reverse_dns)
        else:
            print("No Reverse DNS Records found.")
    except:
        print("dns.resolver.NoAnswer: The DNS response does not contain an answer to the question: "+domain+" IN TXT")

    try:
        return {"MX_Records":mx_records,"SPF_Records":spf_records,"DMARC_Records":dmarc_records,"Reverse_dns_record":reverse_dns}

    except:
        return {"MX_Records":"None","SPF_Records":"None","DMARC_Records":"None","Reverse_dns_record":"None"}


# abc=mail_mis_config("www.mollie.com")
# print(abc)
