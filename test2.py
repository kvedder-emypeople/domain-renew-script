import datetime
import dns.resolver
import subprocess
from ldap3 import Server, Connection, ALL, NTLM
import ssl
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

def get_expiration_date(cert_file):
    try:
        # Load the certificate
        with open(cert_file, 'rb') as f:
            cert_data = f.read()

        # Parse the certificate
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Extract the expiration date (UTC)
        expiration_date = cert.not_valid_after_utc

        # Get current date and time (UTC, naive)
        current_date = datetime.utcnow()  # This is naive, but we can handle it

        # Make current date aware by adding UTC offset
        current_date = current_date.replace(tzinfo=expiration_date.tzinfo)

        # Check if the certificate is expired
        if expiration_date < current_date:
            print(f"The SSL certificate from {cert_file} has expired on {expiration_date}.")
        else:
            print(f"The SSL certificate from {cert_file} is valid until {expiration_date}.")
        return expiration_date
    except Exception as e:
        print(f"Error checking SSL certificate from {cert_file}: {e}")


def is_domain_expiring_soon(expiration_date):
    """Check if the domain is expiring within 2 weeks."""
    today = datetime.datetime.now()
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



from ldap3 import Server, Connection, ALL, NTLM


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
    ldap_server_url = "10.0.5.130"
    base_dn = "o=domains,dc=emypeople,dc=net"
    username = "cn=vmail,dc=emypeople,dc=net"
    password = "bMppDN7fZSp2YyhSBJNXDJLzj1E0IseB"

    domain_list = query_ldap_domains(ldap_server_url, base_dn, username, password)
    print("Domains found:", domain_list)

    """Main method to check domains and renew certificates."""

    valid_mx_domains = check_mx_record(domain_list)

    to_renew = []

    # Iterate through each domain to check expiration
    for domain in valid_mx_domains:
        expiration_date = get_expiration_date(f"domains/{domain}/cert3.pem")
        print(expiration_date)
        # Check if the domain is expiring soon
        if is_domain_expiring_soon(expiration_date):
            to_renew.append(domain)
    print(to_renew)
    # Check MX records for the domains that are expiring soon


    # Renew certificates for domains that meet both criteria
    # for domain in mx_check_list:
    #     renew_certificate(domain)

    print("Script execution completed.")


# Define your domains
if __name__ == "__main__":
    main()
