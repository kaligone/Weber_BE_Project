import dns.resolver
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

url = "mollie.com"
domain = url.split("//")[-1].split("/")[0].split(":")[0]
ip_address = socket.gethostbyname(domain)

mx_records = check_mx_records(domain)
spf_records = check_spf_records(domain)
dmarc_records = check_dmarc_records(domain)
dkim_records = check_dkim_records(domain)
reverse_dns = check_reverse_dns(ip_address)

if mx_records:
    print("MX Records:", mx_records)
else:
    print("No MX Records found.")

if spf_records:
    print("SPF Records:", spf_records)
else:
    print("No SPF Records found.")

if dmarc_records:
    print("DMARC Records:", dmarc_records)
else:
    print("No DMARC Records found.")

if reverse_dns:
    print("Rerverse DNS Records:",reverse_dns)
else:
    print("No Reverse DNS Records found.")