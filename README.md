# XMPP Python Bruteforce
# SASL SCRAM-SHA-1 Authentication 😁

- [x] `Bruteforce with wordlist and random characters`
- [x] `Wireshark Capture file`
    - [ ] Check if there's other XMPP success in the capture and bruteforce them too 
- [ ] Bruteforce and try to connect to the running server
- [ ] Add another XMPP auth algorithm

## Summary

A simple python script to find a password from a XMPP authentication using SCRAM-SHA-1 method. You can add base64 encoded parameters one-by-one or simply put your pcap file in argument.
This tool follow the TCP stream of a successful authentication challenge and try to correlate a password by encrypting it in the exact same way.

You can enter a specific wordlist, a password or a "random prefix". If nothing is entered, by default, random passwords will be generated using random-prefix and a length of 3 printable characters (ascii letters, digits, punctuation and whitespace).


c'est vite fait, au nom j'ai fait au mieux

## Usage

**Basic installation**
```
git clone https://github.com/ccrca/XMPP_bruteforce.git && cd XMPP_bruteforce

pip install -r requirements.txt

python3 xmpp_bruteforcer.py -u "user" -pf "v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=" -w rockyou-75.txt --cnonce "fyko+d2lbbFgONRv9qkxdawL" --snonce "3rfcNHYJY1ZVvWVs7j" --salt "QSXCR+Q6sek8bf92" --server-sign "rmF9pqV8S7suAoZWja4dJRkFsKQ="
```

**With poetry**
```
git clone https://github.com/ccrca/XMPP_bruteforce.git && cd XMPP_bruteforce

poetry install

poetry run python3 xmpp_bruteforcer.py -u "user" -pf "v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=" -w rockyou-75.txt --cnonce "fyko+d2lbbFgONRv9qkxdawL" --snonce "3rfcNHYJY1ZVvWVs7j" --salt "QSXCR+Q6sek8bf92" --server-sign "rmF9pqV8S7suAoZWja4dJRkFsKQ="

```

**Using PCAP file**

The tool depends on tshark for the pcap parsing tasks. I recommend you to use it with other available options : wordlist, password, random-prefix
Enable the `-sh` `--show-packets` option to get a better a view on the XML content that is extracted.
```
❯ python3 xmpp_bruteforcer.py -cp ./ch8.pcap -sh -p "pencil"
Debug mode
Using selector: EpollSelector
Found 1 successful TCP streams.
The First successful TCP stream number : 1
----------------------------------------
Packet 22 in TCP stream 1:
xml_tag => <response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
xml_cdata => biwsbj11c2VybmFtZSxyPWJHRnhkVzlwYkdGeGRXOXBiR0Z4ZFc5cENnPT0K
 => </response>
out => 1
response => RESPONSE
cdata is not base64 decodable :p
cdata => n,,n=username,r=bGFxdW9pbGFxdW9pbGFxdW9pCg==
----------------------------------------
Packet 25 in TCP stream 1:
xml_tag => <challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
xml_cdata => cj1iR0Z4ZFc5cGJHRnhkVzlwYkdGeGRXOXBDZz09YkdFZ2JXRnVieUJoSUdacGJta2djMkVnY0dWcGJtVUsscz1rTTZsVGpqblpXNEY4V0xib3lhZ2NBPT0saT00MDk2Cg==
 => </challenge>
in => 1
challenge => CHALLENGE
cdata => r=bGFxdW9pbGFxdW9pbGFxdW9pCg==bGEgbWFubyBhIGZpbmkgc2EgcGVpbmUK,s=kM6lTjjnZW4F8WLboyagcA==,i=4096
----------------------------------------
--- Parameters extracted ---
 {'user': 'username', 'proof': 'b3VobGV6b3pvbHVpbGEK', 'cnonce': 'bGFxdW9pbGFxdW9pbGFxdW9pCg==', 'snonce': 'bGEgbWFubyBhIGZpbmkgc2EgcGVpbmUK', 'b64_salt': 'kM6lTjjnZW4F8WLboyagcA==', 'serv_sign': 'bmlxdWVsZXRhCg=='}
--- -------------------- ---
```

### Help !!

```
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


❯ python3 xmpp_bruteforcer.py -h
usage: xmpp_bruteforcer.py [-h] [-cp CAPFILE] [-sh] [-p PASSWORD] [--random-suffix RANDOM_SUFFIX] [--prefix PREFIX]
                           [--suffix SUFFIX] [-H HOST] [-P PORT] [-w WORDLIST] [-u USER] [-pf PROOF] [--cnonce CNONCE]
                           [-i ITER] [--snonce SNONCE] [--salt B64_SALT] [-ss SERV_SIGN] [-v]

XMPP Bruteforce si dieu veut

options:
  -h, --help               show this help message and exit

Capture Options:
  -cp CAPFILE, --capfile   Wireshark capture file
  -sh, --show-packets      Show XMPP packets content

Password Options:
  -p PASSWORD, --password  Wanna try a specific password ?
  --random-suffix          Generate password suffix
  --prefix PREFIX          Known password prefix
  --suffix SUFFIX          Known password suffix

Server Options:
  -H HOST, --host          XMPP server hostname or IP
  -P PORT, --port          XMPP server port

Wordlist Options:
  -w WORDLIST, --wordlist  Wordlist

User Options:
  -u USER, --username      Username
  -pf PROOF, --proof       Encoded proof

Nonce and Salt Options:
  --cnonce CNONCE          Client nonce
  -i ITER, --iteration     Number of iterations
  --snonce SNONCE          Server nonce
  --salt B64_SALT          Salt used in challenge
  -ss SERV_SIGN,           Server signature

Verbosity Options:
  -v, --verbose            Enable debug messages

```

If you want a better look at what's happenning, enable verbose mode `-v` `--verbose`
```

|█---------------------------------------| 3.99% Complete C= C= C=┌( `ー´)┘
 -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
Tested password: pencil
Salt : b'A%\xc2G\xe4:\xb1\xe9<m\xffv'
Salted password : b'\x1d\x96\xee:R\x9bZ_\x9eG\xc0\x1f"\x9a,\xb8\xa6\xe1_}'
Client key : b'\xe24\xc4{\xf6\xc3f\x96\xddm\x85+\x99\xaa\xa2\xba&UW('
Stored key : e9d94660c39d65c38fbad91c358f14da0eef2bd6
Auth message : n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j
Client Signature : b']q8\xc4\x86\xb0\xbf\xab\xdfI\xe3\xe2\xda\x8b\xd6\xe5\xc7\x9d\xb6\x13'
Server Key : b'\x0f\xe0\x92X\xb3\xac\x85+\xa5\x02\xccb\xba\x90>\xaa\xcd\xbf}1'
Server Signature : b'\xaea}\xa6\xa5|K\xbb.\x02\x86V\x8d\xae\x1d%\x19\x05\xb0\xa4'
Tested Client Proof : bf45fcbf7073d93d022466c94321745fe1c8e13b
Actual Client Proof : bf45fcbf7073d93d022466c94321745fe1c8e13b

 (´-ω-`) Flag found : pencil !
```

## Resources

- https://stackoverflow.com/questions/29298346/xmpp-sasl-scram-sha1-authentication
- https://datatracker.ietf.org/doc/html/rfc5802
- https://wiki.xmpp.org/web/SASL_Authentication_and_SCRAM

## DISCLAIMER
This tool is intended for educational and testing purposes only. The author of this tool is not responsible for any misuse or illegal activities performed with it. Use this tool only on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal and unethical.


## 😼 Links

[RootMe 💀](http://catleidoscope.sergethew.com/) - [HackTheBox 🟩](https://hackertyper.com/)
