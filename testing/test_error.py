

import dns.resolver
import subprocess
from ldap3 import Server, Connection, ALL, NTLM
import ssl, socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from ldap3 import Server, Connection, ALL, NTLM

def get_expiration_date(domain):
    context = ssl.create_default_context()
    hostname = "mail." + domain
    with socket.create_connection((hostname, 465)) as sock:
        # Wrap the socket with SSL
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            # Get the certificate
            cert = ssock.getpeercert()
            # Extract the expiration date
            expiration_date = cert['notAfter']
            # Convert to a datetime object
            expiration_datetime = datetime.strptime(expiration_date, '%b %d %H:%M:%S %Y GMT')
            print(expiration_datetime)

    current_date = datetime.utcnow()

    # the certificate is expired
    if current_date > expiration_datetime:
        print(f"The SSL certificate from {domain} has expired on {expiration_date}.")
    else:
        print(f"The SSL certificate from {domain} is valid until {expiration_date}.")
    return expiration_datetime

# get_expiration_date(f"domains/{domain}/cert3.pem")
get_expiration_date("creeksidemfg.com")