


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

    except Exception as e:
        print(f"Error checking SSL certificate from {cert_file}: {e}")

# get_expiration_date(f"domains/{domain}/cert3.pem")
get_expiration_date("domains/1lostcreek.com/cert3.pem")