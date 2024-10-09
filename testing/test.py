import OpenSSL.crypto
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl

from datetime import datetime, timedelta

today = datetime.now()
expiration_date = today + timedelta(days=12)

if (expiration_date - today).days <= 14:
    print("domain is expiring soon")
else:
    print("domain does not need renewed")