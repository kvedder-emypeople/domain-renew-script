import datetime, argparse
import dns.resolver
import subprocess
from ldap3 import Server, Connection, ALL, NTLM
import ssl, socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from ldap3 import Server, Connection, ALL, NTLM


def get_expiration_date(domain):
    try:
        context = ssl.create_default_context()
        # hostname = "mail." + domain
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
                # print(expiration_datetime)

        current_date = datetime.utcnow()


        if current_date > expiration_datetime:
            print(f"The SSL certificate from {domain} has expired on {expiration_date}.")
        else:
            print(f"The SSL certificate from {domain} is valid until {expiration_date}.")
        return expiration_datetime

    except Exception as e:
        print(f"Error checking SSL certificate from {domain}: {e}")

def check_mx_record(domains):
    valid_mx = []
    for d in domains:
        try:
            mx_records = dns.resolver.resolve(d, 'MX')
            print(f"MX Entries for {d}:")
            for mx in mx_records:
                if str(mx.exchange).endswith('filter.upwardmail.net.'):
                    print(mx.exchange)
                    print("Domain uses eMyPeoples Filter for MX Entry.")
                    mx_result = True
            print("")

            a_domain = f"mail.{d}"
            a_records = dns.resolver.resolve(a_domain, 'A')
            print(f"A Records Entries for {d}:")
            for a in a_records:
                print(a)
                if a.address.endswith('216.24.56.67'):
                    print("Domain points to eMyPeople UpwardMail Server.")
                    a_result = True
            if mx_result == True and a_result == True:
                valid_mx.append(d)
        except Exception as e:
            print(f"Error resolving MX for {d}: {e}")
    return valid_mx

def is_domain_expiring_soon(expiration_date):
    """Check if the domain is expiring within 2 weeks."""
    today = datetime.now()
    return (expiration_date - today).days <= 30

def query_ldap_domains(ldap_server_url, base_dn, username, password):
    domains = []
    try:
        server = Server(ldap_server_url, use_ssl=True, get_info=ALL)
        print("starting connection")
        conn = Connection(server, user=username, password=password, auto_bind=False)
        print("connection made")
        if not conn.bind():
            print('error in bind', conn.result)
        else:
            print("Successfully connected and bound user to LDAP server")
        # # Perform the search for domain entries
        conn.search(base_dn, search_filter='(objectClass=mailDomain)', attributes=['domainName'])
        # # Extract domain names from the search results
        for entry in conn.entries:
            domains.append(entry['domainName'][0])  # Assuming 'dc' attribute contains domain names

        conn.unbind()  # Clean up the connection
        # print("unbound connection")
    except Exception as e:
        print(f"Error querying LDAP server: {e}")


def renew_certificate(domain):
    """Renew the certificate for a given domain."""
    print(f"Renewing certificate for {domain}...")
    try:
        # Command to renew certificates
        # certbot --dry-run -qn certonly --cert-name <domain> --webroot /var/www/html -d domain
        subprocess.run(['certbot', '--dry-run', '-n', 'certonly','--cert-name', domain, '--webroot', '-w', '/var/www/html', '-d', domain], check=True)
        subprocess.run(['chmod', '+r', f'/etc/letsencrypt/live/{domain}/privkey.pem'], check=True)
        print(f"Successfully renewed certificate for {domain}.")
        return domain
    except subprocess.CalledProcessError as e:
        print(f"Certbot failed to renew certificate for {domain}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Tool for administering SSL Certs on the UpwardMail server.",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-e", "--expires", help="-e <DOMAIN>, this will return the expiration date of the "
                                                "provided domains SSL Cert.", default=False, )
    parser.add_argument("-d", "--dns", help="-m <DOMAIN>, this will check and return the MX records for the domain along with the A record for mail.<DOMAIN>.com",
                        default=False, )
    parser.add_argument("-r", "--renew", help="-r <DOMAIN>, this will check expiration date, MX and A record validity, then renew the Let's Encrypt certificate for the provide domain.",
                        default=False, )

    args = parser.parse_args()

    args_list = vars(args)
    if args.expires:
        date = get_expiration_date(args.expires)
        print(date)
    elif args.dns:
        domains = []
        domains.append(args.dns)
        check_mx_record(domains)
    elif args.renew:
        domains = []
        domains.append(args.renew)
        valid_mx = check_mx_record(domains)
        to_renew = []
        print("")
        # loop through domains with valid MX and A records and check expiration dates and renew if needed
        for d in valid_mx:
            expiration_date = get_expiration_date(d)
            if expiration_date:
                # check if the domain is expiring soon
                if is_domain_expiring_soon(expiration_date):
                    print("Domain Needs Renewed")
                    to_renew.append(d)
                else:
                    print("Domain Does Not Need Renewed.")
        if len(to_renew) > 0:
            # Renew certificates for domains that meet both criteria
            for domain in to_renew:
                renew_certificate(domain)

            else:
                print("No Domains Need Renewed")



main()