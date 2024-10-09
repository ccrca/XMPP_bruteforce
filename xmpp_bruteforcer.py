# 09/10/24
# SCRAM-SHA-1 decypher

#  SaltedPassword  := Hi(Normalize(password), salt, i)
#  ClientKey       := HMAC(SaltedPassword, "Client Key")
#  StoredKey       := SHA1(ClientKey)
#  AuthMessage     := client-first-message-bare + "," +             
#                     server-first-message + "," +
#                     client-final-message-without-proof
#  ClientSignature := HMAC(StoredKey, AuthMessage)
#  ClientProof     := ClientKey XOR ClientSignature
#  ServerKey       := HMAC(SaltedPassword, "Server Key")
#  ServerSignature := HMAC(ServerKey, AuthMessage)

import argparse
import base64
import hashlib
import hmac
import re
import pyshark
from scapy.all import *
import logging


TIMEOUT=5
# Define dictionnary stucture
xml_dict = {
        "user":None,
        "proof":None,
        "cnonce":None,
        "snonce":None,
        "b64_salt":None,
        "serv_sign":None
        }

def display_banner():
    banner = r"""
  _______________  _______  ___________           ⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣰⣋⠉⠀⠀⠉⠉⣓⣦⣀⣀⠀⠀⠀⠀⠀⠀⠀
 /  _____/\   _  \ \   _  \ \_   _____/__.__.     ⠀⠀⠀⠀⠀⠀⢠⡞⠛⠙⢻⣿⣷⣦⠀⠀⡖⠉⠉⢻⣿⣷⣂⠀⠀⠀⠀⠀
/   \  ___/  /_\  \/  /_\  \ |    __)<   |  |     ⠀⠀⠀⠀⠀⠀⣼⡇⠀⢰⣾⡟⣿⣿⡆⢰⣷⣤⣴⡟⠛⢻⣿⠀⠀⠀⠀⠀
\    \_\  \  \_/   \  \_/   \|     \  \___  |     ⠀⠀⠀⠀⠀⠀⡍⣿⣿⣿⣏⣀⣼⣿⠃⠘⠿⣿⣿⣧⣤⣼⡿⠧⠀⠀⠀⠀
 \______  /\_____  /\_____  /\___  /  / ____|     ⠀⠀⠀⠀⠀⠠⣍⠖⠒⣒⠀⠀⠈⠀⠀⠀⠀⠈⠉⢨⡤⠄⠹⢺⠂⠀⠀⠀
        \/       \/       \/     \/   \/          ⠀⠀⠀⠀⠀⠈⠛⢯⠁⢸⡳⡐⠦⠤⣤⠤⠤⡴⠘⢁⡇⠀⠀⡜⠁⠀⠀⠀
           ____  ___                              ⠀⠀⠀⠀⠀⠀⠀⠀⢓⢼⡕⡗⠲⠬⣧⠤⠤⡗⠒⢋⣇⡠⠞⠁⠀⠀⠀⠀
           \   \/  / _____ ______ ______ ______   ⠀⠀⠀⠀⠀⢀⡴⠚⠁⠀⠉⠙⠒⠒⠧⠤⠤⠧⠤⠚⠁⠳⣀⠀⠀⠀⠀⠀
            \     / /     \\____ \\____ \\____ \  ⠀⢀⣠⣴⡼⢋⣀⡤⠼⠉⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⢆⠈⢦⡀⣠⢤⣄
            /     \|  Y Y  \  |_> >  |_> >  |_> > ⠀⠘⣗⠥⡰⡏⠀⠀⠀⠀⢧⠀⠀⠀⠀⠀⠀⠀⠀⢰⠃⠀⢙⡆⣉⢑⢻⠀
           /___/\  \__|_|  /   __/|   __/|   __/  ⠀⠀⠀⠀⠛⠃⠀⠀⠀⠀⠘⡄⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠘⠛⠻⣼⠛⠀
                 \_/     \/|__|   |__|   |__|     ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⢀⡤⣄⠀⠀⠀⡞⠀⠀⠀⠀⠀⠀⠀⠀
"""
    print(banner)

def fast_progress_bar(current, total, bar_length=40):
    percent = current / total
    progress = int(bar_length * percent)
    bar = '█' * progress + '-' * (bar_length - progress)
    sys.stdout.write(f'\r|{bar}| {percent:.2%} Complete C= C= C=┌( `ー´)┘')
    sys.stdout.flush()

def ping_host(host, port):
    # Check if port is open and unfiltered
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((host, port))

        print(f"Successfully connected to {host} on port {port}")
        sock.close()

    except socket.timeout:
        print(f"Connection to {host} on port {port} timed out")
    except socket.error as e:
        print(f"Failed to connect to {host} on port {port}: {e}")

    return

###################### Parse capture with tshark ######################

def parse_cap(capfile):
    # Find pcap, parse XMPP, keep the TCP stream of the successfull challenge, parse client and server nonce
    try:
        pcap = pyshark.FileCapture(capfile, display_filter='xmpp')
    except FileNotFoundError:
        raise ValueError("Capture file not found, make sure you got the path right")
    
    xml_filter = ["_ws_expert_severity", "xml_attribute", "_ws_expert_group", "_ws_expert", "xmlns", "_ws_expert_message"]

    successful_streams = find_successful_streams(pcap)
    if successful_streams:
        logging.debug(f"Found {len(successful_streams)} successful TCP streams.")
        extract_auth_details(pcap, successful_streams, xml_filter)
        if logging.DEBUG:
            scram_print(xml_dict)
    else:
        logging.info("No successful TCP streams found.")

def find_successful_streams(pcap):
    successful_streams = []

    for packet in pcap:
        if 'XMPP' in packet:
            xml_state = packet['XMPP'].get_field_value('success')
            if xml_state == "SUCCESS":
                tcp_stream = packet.tcp.stream
                successful_streams.append(tcp_stream)
    return successful_streams

def extract_auth_details(pcap, successful_streams, xml_filter):

    logging.info("\033[93mThe First successful TCP stream number : "+ successful_streams[0]+ "\033[0m")
    successful_streams = successful_streams[0] # On verra plus tard hein

    for packet in pcap:
        if 'TCP' in packet and packet.tcp.stream in successful_streams:
            if 'XMPP' in packet:
                xmpp_layer = packet['XMPP']
                logging.debug(f"\033[91mPacket {packet.number} in TCP stream {packet.tcp.stream}:\033[0m")

                for data in xmpp_layer.field_names:
                    if data in xml_filter:
                        continue
                    d = xmpp_layer.get_field_value(data)
                    if data == "cdata":
                        try:
                            d = base64.b64decode(d).decode('utf-8')
                            find_param(d, xmpp_layer)
                        except Exception:
                            logging.debug("cdata is not base64 decodable :p")

                    logging.debug(f"{data} => {d}")
                logging.debug("\033[93m-\033[0m" * 40)

def find_param(cdata, xmpp_layer):
    if xmpp_layer.get_field_value("challenge"): 
    # Example : r=hydraFe3A1scL7C0jtKsm+kcg96MWg769FuRu,s=kM6lTjjnZW4F8WLboyagcA==,i=4096
        xml_dict["b64_salt"] = re.search(r's=([^,]+)', cdata).group(1)

    if xmpp_layer.get_field_value("response"):  
    # Example : n,,n=koma_test,r=hydra | c=biws,r=hydraFe3A1scL7C0jtKsm+kcg96MWg769FuRu,p=mZU2Qekd8JR7ybCtb3hnJMGEfIg=
        cnonce_match = re.search(r'n=([^,]+),r=([^,]+)', cdata)
        if cnonce_match:
            xml_dict["user"] = cnonce_match.group(1)
            xml_dict["cnonce"] = cnonce_match.group(2)

        snonce_match = re.search(r'r=([^,]*),p=', cdata)
        if snonce_match:
            xml_dict["snonce"] = snonce_match.group(1).strip(xml_dict["cnonce"])

        xml_dict["proof"] = re.search(r'p=([^,]+)', cdata).group(1)

    if xmpp_layer.get_field_value("success"):   
    # Example : v=YQlegvbEwDo2o60YiK2iAkYyPKE=
        xml_dict["serv_sign"] = cdata[2:]

def scram_print(xmldata):
    print("\033[92m--- Parameters extracted ---\033[0m")
    print("\033[92m",xmldata,"\033[0m")
    print("\033[92m--- -------------------- ---\033[0m")

###################### End of capture parsing ######################

def client_proof(client_key, client_sig):
    #  ClientProof := ClientKey XOR ClientSignature
    r = b""
    for l in range(len(client_key)):
        r += (client_key[l] ^ client_sig[l]).to_bytes(length=1, byteorder="big")
    return r.hex()

def get_auth_msg(user:str, salt:str, cnonce:str, snonce:str, iteration:int):
    # AuthMessage := client-first-message-bare + "," + server-first-message + "," + client-final-message-without-proof
    # no proof message => GS2 header + SCRAM username, nonce
    auth_message = f"n={user},r={cnonce},r={cnonce}{snonce},s={salt},i={iteration},c=biws,r={cnonce}{snonce}"
    return auth_message

def get_client_signature(stored_key, auth_msg):
    # ClientSignature := HMAC(StoredKey, AuthMessage)
    sig = hmac.digest(bytes.fromhex(stored_key), auth_msg.encode(), hashlib.sha1)
    return sig

def get_server_signature(server_key, auth_msg):
    # ServerSignature := HMAC(ServerKey, AuthMessage)
    sig = hmac.digest(server_key, auth_msg.encode(), hashlib.sha1)
    return sig

def get_stored_key(client_key):
    # StoredKey := SHA1(ClientKey)
    h = hashlib.sha1(client_key).hexdigest()
    return h

def get_client_key(saltedpwd):
    # ClientKey := HMAC(SaltedPassword, "Client Key")
    key = hmac.digest(saltedpwd, b"Client Key", hashlib.sha1)
    return key

def get_server_key(saltedpwd):
    # ServerKey := HMAC(SaltedPassword, "Server Key")
    key = hmac.digest(saltedpwd, b"Server Key", hashlib.sha1)
    return key

def get_salted_pwd(pwd:str, salt:str, iter:int):
    # SaltedPassword  := Hi(Normalize(password), salt, i)
    salted_pwd = hashlib.pbkdf2_hmac('sha1', pwd.encode(), salt, int(iter))
    return salted_pwd

def get_salt(b64_salt):
    try:
        hex_salt = base64.b64decode(b64_salt).hex()
        bytes_salt = bytes.fromhex(hex_salt)
    except:
        raise ValueError("Invalid salt encoding")
    return bytes_salt

def bruteforce(user:str="", proof:str="", b64_salt:str="", cnonce:str="", snonce:str="", password:str="",serv_sign:str="", 
               wordlist:str="", prefix:str="", suffix:str="", random_suffix:int=0, capfile:str="", host:str="", port:int=0, iter:int=4096):

    prefix = prefix if prefix is not None else ""
    suffix = suffix if suffix is not None else ""
    password = password if password is not None else ""
    passwords = []
    passwords.append(password)

    if capfile is not None:
        parse_cap(capfile)
        if not xml_dict:
            raise argparse.ArgumentTypeError("Couldn't extract anything from a successful challenge")

        # idgaf code is trash, look end of code for an alternative
        user = user if user is not None else xml_dict["user"]
        proof = proof if proof is not None else xml_dict["proof"]
        b64_salt = b64_salt if b64_salt is not None else xml_dict["b64_salt"]
        cnonce = cnonce if cnonce is not None else xml_dict["cnonce"]
        snonce = snonce if snonce is not None else xml_dict["snonce"]
        serv_sign = serv_sign if serv_sign is not None else xml_dict["serv_sign"]

        if any(value is None for value in xml_dict.values()):
            raise ValueError("\033[91mMissing parameters to complete decryption.\n=> 'None' found in the dictionary.\033[0m")

    if host is not None:
        xmpp_pattern = r"/(?P<scheme>xmpp:\/\/)?(?P<host>[a-zA-Z0-9.-]+)(:(?P<port>[0-9]+))?"
        xmpp_match = re.search(xmpp_pattern, host)
        if xmpp_match:
            host = xmpp_match.group("host")
            port = port if port is not None else xmpp_match.group("port")
        else:
            raise ValueError("\033[91mInvalid host\033[0m")
        logging.info("Host : " + host)
        logging.info("Port : " + str(port))
        ping_host(host, port)
        # TRAvAUx EN COURS
        return

    if wordlist and os.path.isfile(wordlist):
        try:
            with open(wordlist, "r", encoding="utf-8") as w:
                passwords.extend(w.readlines())
        except UnicodeDecodeError:
            print(f"\033[91mError: Unable to decode the file '{wordlist}' with utf-8 encoding.\033[0m")
            try:
                with open(wordlist, "r", encoding="latin-1") as w:
                    passwords.extend(w.readlines())
            except UnicodeDecodeError:
                print(f"\033[91mError: Unable to decode the file '{wordlist}' with latin-1 encoding.\033[0m")

    if random_suffix > 0:
        # Load random characters
        logging.info("Loading random prefixes with length : " + str(random_suffix))
        charset = string.printable
        for k in itertools.permutations(charset, random_suffix):
            needle = "".join(k)
            passwords.append(needle)

    # Iterate over passwords
    c = 0
    for password in passwords:
        c+=1
        fast_progress_bar(c + 1, len(passwords))

        if password is None or password == "":
            continue  
        logging.info("\n"+"\033[93m --\033[0m" * 25)

        password = prefix+password.strip()+suffix
        
        logging.info("\033[93mTested password: \033[0m\x1b[43;1m"+ str(password)+"\033[0m") # ex: pencil
        salt = get_salt(b64_salt)
        logging.info("Salt : " + str(salt))
        salted_pwd = get_salted_pwd(password, salt, iter)               # Normalize and salt tested password
        logging.info("Salted password : "+ str(salted_pwd))
        client_key = get_client_key(salted_pwd)
        logging.info("Client key : "+ str(client_key))
        storedkey = get_stored_key(client_key)
        logging.info("Stored key : "+ str(storedkey))
        auth_msg = get_auth_msg(user, b64_salt, cnonce, snonce, iter)
        logging.info("Auth message : "+ str(auth_msg))
        client_sig = get_client_signature(storedkey, auth_msg)
        logging.info("Client Signature : "+ str(client_sig))
        server_key = get_server_key(salted_pwd)
        logging.info("Server Key : "+ str(server_key))
        server_sig = get_server_signature(server_key, auth_msg)
        logging.info("Server Signature : "+ str(server_sig))
        tested_proof = client_proof(client_key, client_sig)
        logging.info("Tested Client Proof : "+ str(tested_proof))

        hexproof = base64.b64decode(proof).hex()
        logging.info("Actual Client Proof : "+ str(hexproof))
        if tested_proof == hexproof or server_sig == serv_sign:
            print(f"\n\033[92m (´-ω-`) Flag found : {password} !\033[0m")
            return
    return print("\n\033[91m (｡•́︿•̀｡) Nothing found \033[0m")

def file_path(string):
    if os.path.isfile(string):
        return string
    else:
        raise print("\033[91m (｡•́︿•̀｡) Wordlist not found, make sure this file exists :", string,"\033[0m")

# SCRAM-SHA-1 Decypher
def main():
    main_parser = argparse.ArgumentParser(description="XMPP Bruteforce si dieu veut")

    # Groupe pour les fichiers de capture
    capture_group = main_parser.add_argument_group('Capture Options')
    capture_group.add_argument('-cp', '--capfile', required=False, type=file_path, help="Wireshark capture file")
    capture_group.add_argument('-sh', '--show-packets', dest="showpkts", action="store_true", help="Show XMPP packets content", required=False)

    # Groupe pour les options de mot de passe
    password_group = main_parser.add_argument_group('Password Options')
    password_group.add_argument('-p', '--password', required=False, help="Wanna try a specific password ?")
    password_group.add_argument('--random-suffix', required=False, type=int, default=0, dest="random_suffix", help="Generate password suffix")
    password_group.add_argument('--prefix', required=False, help="Known password prefix")
    password_group.add_argument('--suffix', required=False, help="Known password suffix")

    # Groupe pour les options de serveur
    server_group = main_parser.add_argument_group('Server Options')
    server_group.add_argument('-H', '--host', required=False, help="XMPP server hostname or IP")
    server_group.add_argument('-P', '--port', type=int, default=5222, help="XMPP server port")

    # Groupe pour les options de wordlist
    wordlist_group = main_parser.add_argument_group('Wordlist Options')
    wordlist_group.add_argument('-w', '--wordlist', required=False, type=file_path, help="Wordlist")

    # Groupe pour les options d'utilisateur
    user_group = main_parser.add_argument_group('User Options')
    user_group.add_argument('-u', '--username', dest="user", required=False, help="Username")
    user_group.add_argument('-pf', '--proof', required=False, help="Encoded proof")

    # Groupe pour les options de nonce et de sel
    nonce_group = main_parser.add_argument_group('Nonce and Salt Options')
    nonce_group.add_argument('--cnonce', required=False, help="Client nonce")
    nonce_group.add_argument('-i', '--iteration', dest="iter", type=int, default=4096, required=False, help="Number of iterations")
    nonce_group.add_argument('--snonce', required=False, help="Server nonce")
    nonce_group.add_argument('--salt', required=False, dest="b64_salt", help="Salt used in challenge")
    nonce_group.add_argument('-ss', '--server-sign', dest="serv_sign", required=False, help="Server signature")

    # Groupe pour les options de verbosité
    verbosity_group = main_parser.add_argument_group('Verbosity Options')
    verbosity_group.add_argument('-v', '--verbose', required=False, help="Enable debug messages", action="store_const", dest="loglevel", const=logging.INFO)

    args = main_parser.parse_args()

    if not args.wordlist and not args.password and not args.random_suffix:
        logging.info("No parameter provided, testing with random 3 letters password")
        args.random_suffix = 3

    if args.showpkts:
        logging.basicConfig(level=logging.DEBUG, format='%(message)s')
        print("\033[2m\033[3mDebug mode\033[0m")
    else:
        logging.basicConfig(level=args.loglevel, format='%(message)s')

    args_dict = vars(args)
    args_dict.pop('loglevel', None)
    args_dict.pop('showpkts', None)
    bruteforce(**args_dict)

if __name__ == "__main__":
    main_parser = argparse.ArgumentParser(description="XMPP Bruteforce si dieu veut")
    if len(sys.argv) == 1:
        display_banner()
        main_parser.print_help()
        sys.exit(1)
    try:
        main()
    except KeyboardInterrupt:
        print("\033[91m\nI shall yield mine efforts to the twilight's embrace. (/=ω=)/\033[0m")
        print("\033[2m\033[3mProgram interrupted\033[0m")

    ############################################
    # arguments = dict((key, value) for d in (locals(), xml_dict) for key, value in d.items())
    # print("Required parameters, updated", required_params)
    # for key in locals().keys():
    #     if locals()[key] is None and key in required_params:
    #         # logging.debug("Found empty " + key + " in xml extracted content")
    #         locals()[key] = required_params[key]
    # b64_salt = locals().get("b64_salt") # otherwise variable isn't really updated => naze