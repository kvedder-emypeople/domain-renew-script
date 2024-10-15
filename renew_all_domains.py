import datetime
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


        if current_date > expiration_datetime:
            print(f"The SSL certificate from {domain} has expired on {expiration_date}.")
        else:
            print(f"The SSL certificate from {domain} is valid until {expiration_date}.")
        return expiration_datetime

    except Exception as e:
        print(f"Error checking SSL certificate from {domain}: {e}")


def is_domain_expiring_soon(expiration_date):
    """Check if the domain is expiring within 2 weeks."""
    today = datetime.now()
    return (expiration_date - today).days <= 14


def check_mx_record(domains):
    valid_mx = []
    for d in domains:
        try:
            mx_records = dns.resolver.resolve(d, 'MX')
            for mx in mx_records:
                if str(mx.exchange).endswith('filter.upwardmail.net.'):
                    # print(f"{d} uses emypeople filters.")
                    valid_mx.append(d)
        except Exception as e:
            print(f"Error resolving MX for {d}: {e}")
    return valid_mx


def renew_certificate(domain):
    """Renew the certificate for a given domain."""
    print(f"Renewing certificate for {domain}...")
    try:
        # Command to renew certificates
        subprocess.run(['certbot', 'renew', '--domains', domain], check=True)
        print(f"Successfully renewed certificate for {domain}.")
        return domain
    except subprocess.CalledProcessError as e:
        print(f"Failed to renew certificate for {domain}: {e}")


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

    return domains

def main():
    # start things off by getting the list of domains on the mail server by querying the LDAP server for the list
    ldap_server_url = "10.0.5.130"
    base_dn = "o=domains,dc=emypeople,dc=net"
    username = "cn=vmail,dc=emypeople,dc=net"
    password = "bMppDN7fZSp2YyhSBJNXDJLzj1E0IseB"
    domain_list = query_ldap_domains(ldap_server_url, base_dn, username, password)
    # print the list of domains
    print("Domains found:", domain_list)

    # next, we check the MX record for each domain, and build out a list of the domains that use the upward mail server
    # as their mail exchanger
    valid_mx_domains = check_mx_record(domain_list)

    # start an empty list for domains that need renewed
    to_renew = []
    # iterate through each domain to check expiration and determine if they need renewed
    for domain in valid_mx_domains:
        expiration_date = get_expiration_date(domain)
        print(expiration_date)
        if expiration_date:
            # check if the domain is expiring soon
            if is_domain_expiring_soon(expiration_date):
                print("domain needs renewed")
                to_renew.append(domain)
            else:
                print("domain is good for now")
        else:
            print("Domain did not respond when queried using SMTP secure.")
    if len(to_renew) > 0:
        # print the list of domains that need renewed
        print(to_renew)
        # Renew certificates for domains that meet both criteria
        # for domain in mx_check_list:
        #     renew_certificate(domain)

    else:
        print("No Domains Need Renewed")
    print("Script execution completed.")

# Define your domains
if __name__ == "__main__":
    main()
