# Create request
openssl req -nodes -newkey rsa:2048 -keyout private_key.pem -out cert_request.pem -subj "/CN=email.gov-of-caltopia.info/ST=CA/C=US/emailAddress=admin@gov-of-caltopia.info/O=Government_Of_Caltopia/OU=None"
