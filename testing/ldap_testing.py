
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
            print("Successfully connected to LDAP server")
        # # Perform the search for domain entries
        conn.search(base_dn, search_filter='(objectClass=mailDomain)', attributes=['domainName'])
        # print(conn.entries)
        # # Extract domain names from the search results
        for entry in conn.entries:
        domains.append(entry['domainName'])  # Assuming 'dc' attribute contains domain names

        except Exception as e:
            print(f"Error querying LDAP server: {e}")


        conn.unbind()  # Clean up the connection
        print("unbound connection")
        return domains

ldap_server_url = "10.0.5.130"
base_dn = "o=domains,dc=emypeople,dc=net"
username = "cn=vmail,dc=emypeople,dc=net"
password = "bMppDN7fZSp2YyhSBJNXDJLzj1E0IseB"

domain_list = query_ldap_domains(ldap_server_url, base_dn, username, password)
print(domain_list)