import dns.message
import dns.rdatatype
import dns.rdataclass
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import dns.rrset
import socket
import threading
import signal
import os
import sys
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ──────────────────────────
# 1.  AES-helper functions
# ──────────────────────────
def generate_aes_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), iterations=100_000,
        salt=salt, length=32
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_with_aes(plaintext: str, password: str, salt: bytes) -> str:
    """Return a **string** token (base64/urlsafe)."""
    key = generate_aes_key(password, salt)
    token_bytes = Fernet(key).encrypt(plaintext.encode())
    return token_bytes.decode()          # <- string-cast for TXT record

def decrypt_with_aes(encrypted_data, password: str, salt: bytes) -> str:
    """Works whether *encrypted_data* is bytes or str."""
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode()
    key = generate_aes_key(password, salt)
    plaintext_bytes = Fernet(key).decrypt(encrypted_data)
    return plaintext_bytes.decode()

# ──────────────────────────
# 2.  Encryption parameters
# ──────────────────────────
SALT      = b'Tandon'
PASSWORD  = 'jy3991@nyu.edu'
SECRET    = 'AlwaysWatching'
TOKEN     = encrypt_with_aes(SECRET, PASSWORD, SALT)  # string token

# ──────────────────────────
# 3.  DNS record database
# ──────────────────────────
dns_records = {
    'example.com.': {
        dns.rdatatype.A:    '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX:   [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME:'www.example.com.',
        dns.rdatatype.NS:   'ns.example.com.',
        dns.rdatatype.TXT:  ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.', 'admin.example.com.',
            2023081401, 3600, 1800, 604800, 86400
        ),
    },
    'safebank.com.':  {dns.rdatatype.A: '192.168.1.102'},
    'google.com.':    {dns.rdatatype.A: '192.168.1.103'},
    'legitsite.com.': {dns.rdatatype.A: '192.168.1.104'},
    'yahoo.com.':     {dns.rdatatype.A: '192.168.1.105'},
    'nyu.edu.': {
        dns.rdatatype.A:    '192.168.1.106',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.TXT:  (TOKEN,),                      # exfil payload
        dns.rdatatype.MX:   [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.NS:   'ns1.nyu.edu.',
    },
}

# ──────────────────────────
# 4.  DNS server logic
# ──────────────────────────
def run_dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 53))          # local test-only server

    while True:
        try:
            data, addr = sock.recvfrom(2048)
            request  = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            q = request.question[0]
            qname, qtype = q.name.to_text(), q.rdtype

            if qname in dns_records and qtype in dns_records[qname]:
                payload = dns_records[qname][qtype]
                rdata_objs = []

                if qtype == dns.rdatatype.MX:
                    for pref, host in payload:
                        rdata_objs.append(MX(dns.rdataclass.IN, qtype, pref, host))

                elif qtype == dns.rdatatype.SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = payload
                    rdata_objs.append(SOA(dns.rdataclass.IN, qtype,
                                          mname, rname, serial, refresh,
                                          retry, expire, minimum))
                else:  # A, AAAA, TXT, NS, etc.
                    for item in (payload if isinstance(payload, tuple) else (payload,)):
                        # Wrap TXT in quotes to preserve the full token
                        txt = f'"{item}"' if qtype == dns.rdatatype.TXT else item
                        rdata_objs.append(
                            dns.rdata.from_text(dns.rdataclass.IN, qtype, txt)
                        )

                # add answer section
                rrset = dns.rrset.RRset(q.name, dns.rdataclass.IN, qtype)
                for r in rdata_objs:
                    rrset.add(r)
                response.answer.append(rrset)

            # mark Authoritative Answer
            response.flags |= (1 << 10)
            print(f"Responding to request: {qname}")
            sock.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            print("\nExiting...")
            sock.close()
            sys.exit(0)

# ──────────────────────────
# 5.  Simple CLI wrapper
# ──────────────────────────
def run_dns_server_user():
    print("DNS server running – press 'q' + ⏎ to quit.")

    def watcher():
        while input().lower() != 'q':
            pass
        os.kill(os.getpid(), signal.SIGINT)

    t = threading.Thread(target=watcher, daemon=True)
    t.start()
    run_dns_server()

if __name__ == '__main__':
    run_dns_server_user()
