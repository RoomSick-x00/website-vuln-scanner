# test_tls.py
from workers.scanner_modules.tls import TLSScanner

scanner = TLSScanner()

target = "https://tls-v1-0.badssl.com:1010"
results = scanner.scan(target, timeout=5)

for finding in results:
    print(finding)
    

# sites to check ->
# https://self-signed.badssl.com
# "https://expired.badssl.com"
# https://sha1-intermediate.badssl.com
# https://tls-v1-0.badssl.com:1010
# https://rc4.badssl.com
# https://no-forward-secrecy.badssl.com
# https://rsa1024.badssl.com
# python -m workers.scanner_modules.test_tls -> run using 