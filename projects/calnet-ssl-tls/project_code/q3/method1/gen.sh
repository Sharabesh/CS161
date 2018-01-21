# Create request
openssl req -nodes -newkey rsa:2048 -keyout private_key.pem -out cert_request.pem -subj "/CN=replace_here"

# New CN in request
echo "data.gov-of-caltopia.info/.neocal.info" > temp
tr -d '\n' < temp > input_cn.dat
rm temp

# Replace CN in request
../rewrite_cn cert_request.pem private_key.pem input_cn.dat mod_cert_request.pem
