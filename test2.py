import datetime
import dns.resolver
import subprocess
from ldap3 import Server, Connection, ALL, NTLM

def get_expiration_date(domain):
    """Fetch the expiration date for a given domain."""
    # Placeholder logic to fetch expiration date
    # Replace with actual expiration fetching logic
    return datetime.datetime.now() + datetime.timedelta(days=10)  # Example


def is_domain_expiring_soon(expiration_date):
    """Check if the domain is expiring within 2 weeks."""
    today = datetime.datetime.now()
    return (expiration_date - today).days <= 14


def check_mx_record(domain):
    """Check if the MX record points to 8.8.8.8."""
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx in mx_records:
            if str(mx.exchange).endswith('8.8.8.8'):
                return True
    except Exception as e:
        print(f"Error resolving MX for {domain}: {e}")
    return False


def renew_certificate(domain):
    """Renew the certificate for a given domain."""
    print(f"Renewing certificate for {domain}...")
    try:
        # Command to renew certificates
        subprocess.run(['certbot', 'renew', '--domains', domain], check=True)
        print(f"Successfully renewed certificate for {domain}.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to renew certificate for {domain}: {e}")



def query_ldap_domains(ldap_server_url, base_dn, username, password):

    domains = []

    try:
        # Connect to the LDAP server
        server = Server(ldap_server_url, get_info=ALL)
        conn = Connection(server, user=username, password=password, auto_bind=True)

        # Perform the search for domain entries
        conn.search(base_dn, '(objectClass=domain)', attributes=['dc'])

        # Extract domain names from the search results
        for entry in conn.entries:
            domains.append(entry.dc.value)  # Assuming 'dc' attribute contains domain names

    except Exception as e:
        print(f"Error querying LDAP server: {e}")

    finally:
        conn.unbind()  # Clean up the connection

    return domains

def main():

    ldap_server_url = "ldap:// 10.0.5.130"
    base_dn = "dc=example,dc=com"
    username = "your_username"
    password = "your_password"

    domain_list = query_ldap_domains(ldap_server_url, base_dn, username, password)
    print("Domains found:", domain_list)

    """Main method to check domains and renew certificates."""
    to_renew = []

    # Iterate through each domain to check expiration
    for domain in domains:
        expiration_date = get_expiration_date(domain)

        # Check if the domain is expiring soon
        if is_domain_expiring_soon(expiration_date):
            to_renew.append(domain)

    # Check MX records for the domains that are expiring soon
    mx_check_list = [domain for domain in to_renew if check_mx_record(domain)]

    # Renew certificates for domains that meet both criteria
    for domain in mx_check_list:
        renew_certificate(domain)

    print("Script execution completed.")


# Define your domains
if __name__ == "__main__":
    domains = ["example1.com", "example2.com", "example3.com"]
    main(domains)
