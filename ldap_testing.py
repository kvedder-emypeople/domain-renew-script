
from ldap3 import Server, Connection, ALL, NTLM


def query_ldap_domains(ldap_server_url, base_dn, username, password):
    """
    Query the LDAP server for a list of domains.

    Args:
        ldap_server_url (str): The LDAP server URL.
        base_dn (str): The base distinguished name to search under.
        username (str): The username for LDAP authentication.
        password (str): The password for LDAP authentication.

    Returns:
        list: A list of domain names found in the LDAP server.
    """
    domains = []

    try:
        # Connect to the LDAP server
        server = Server(ldap_server_url, get_info=ALL)
        conn = Connection(server, user=username, password=password, auto_bind=False)

        # Perform the search for domain entries
        conn.search(base_dn, '(objectClass=mailDomain)', attributes=['dc'])

        # Extract domain names from the search results
        # for entry in conn.entries:
        #     domains.append(entry.dc.value)  # Assuming 'dc' attribute contains domain names

    except Exception as e:
        print(f"Error querying LDAP server: {e}")

    finally:
        conn.unbind()  # Clean up the connection

    return domains

ldap_server_url = "ldap://10.0.5.130"
base_dn = "cn=vmail,dc=emypeople,dc=net"
username = "postmaster"
password = "f#7&HHTVwGbk4T3&"

domain_list = query_ldap_domains(ldap_server_url, base_dn, username, password)
print("Domains found:", domain_list)