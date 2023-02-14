import jwt
from datetime import datetime, timedelta
import argparse

# Add arguments for secret key and expiration time in hours
parser = argparse.ArgumentParser(description='Generate JWT token.')
parser.add_argument('secret_key', type=str, help='Secret key for the JWT token')
parser.add_argument('expiration_hours', type=int, help='Expiration time in hours for the JWT token')
args = parser.parse_args()

# Generate the JWT token
payload = {
    'user_id': '1234567890',
    'aud': 'VerneMQCluster101',
    'iss': 'VMQ',
    'alg': 'dir',
    'exp': datetime.utcnow() + timedelta(hours=args.expiration_hours)  # Token expires in the specified number of hours
}
secret_key = args.secret_key
algorithm = 'HS256'

token = jwt.encode(payload, secret_key, algorithm)

print(token.decode('utf-8'))
