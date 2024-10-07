import OpenSSL.crypto
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl

folder_with_domains = "./domains"

cert = crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open("domains/1lostcreek.com/cert3.pem").read())
print(cert.)
print(cert.has_expired())