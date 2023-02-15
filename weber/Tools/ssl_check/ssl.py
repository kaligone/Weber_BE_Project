import ssl
import socket
from datetime import datetime
from datetime import datetime
from typing import NamedTuple
import pandas as pd


class CertificateInfo(NamedTuple):
    domain: str
    expiry_date: datetime
    expires_in: int
    issuer: str


    def expires_on(self):
        return self.expiry_date.strftime('%Y-%m-%d')

    def get_certificate_details(domain, port=443):
        context = ssl.create_default_context()
        s = socket.create_connection((domain, port))
        with context.wrap_socket(s, server_hostname=domain) as ss:
            certificate = ss.getpeercert()
        return certificate


    def read_certificate(hostname, certificate):
        date_format = r'%b %d %H:%M:%S %Y %Z'
        not_after = certificate['notAfter']
        expire_date = datetime.strptime(not_after, date_format)
        remaining = expire_date - datetime.now()

        issuer = dict(x[0] for x in certificate['issuer'])
        issued_by = issuer['organizationName']

        return CertificateInfo(hostname, expire_date, remaining.days, issued_by)


    def has_valid_certificate(certificate, port=443):
        if certificate:
            now = datetime.utcnow()
            not_before = datetime.strptime(certificate['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(certificate['notAfter'], '%b %d %H:%M:%S %Y %Z')
            if now >= not_before and now <= not_after:
                return True
            else:
                return False
        else:
            return False


if __name__ == "__main__":

    
    domain = "www.google.com"
    try:
        certificate1=CertificateInfo.get_certificate_details(domain)
      
        if CertificateInfo.has_valid_certificate(certificate1):
            print(f"The certificate for {domain} is valid.")
            cert_info=CertificateInfo.read_certificate(domain,certificate1)
            print("Domain Name: "+cert_info.domain+"\n"+
                            "Expiry : "+str(cert_info.expires_on())+"\n"+
                            "Certificate Expiring in "+str(cert_info.expires_in)+" Days\n"
                            "Certificate Issuer : "+cert_info.issuer)
        else:
            print(f"The domain {domain} have a expired certificate.")
 
    except:
        print(f"The domain {domain} does not have a certificate.")

    
