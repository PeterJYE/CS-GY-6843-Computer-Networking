import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
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
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


sys.modules['DNSServer'] = sys.modules[__name__]


def generate_aes_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100_000,
        salt=salt,
        length=32,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_with_aes(plain: str, password: str, salt: bytes) -> bytes:
    key = generate_aes_key(password, salt)
    return Fernet(key).encrypt(plain.encode("utf-8"))


def decrypt_with_aes(cipher: bytes, password: str, salt: bytes) -> str:
    key = generate_aes_key(password, salt)
    return Fernet(key).decrypt(cipher).decode("utf-8")


salt = b"Tandon"
password = "jy3991@nyu.edu"
input_string = "AlwaysWatching"


encrypted_value: bytes = encrypt_with_aes(input_string, password, salt)


dns_records = {
    "example.com.": {
        dns.rdatatype.A: "192.168.1.101",
        dns.rdatatype.AAAA: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        dns.rdatatype.MX: [(10, "mail.example.com.")],
        dns.rdatatype.CNAME: "www.example.com.",
        dns.rdatatype.NS: "ns.example.com.",
        dns.rdatatype.TXT: ("This is a TXT record",),
        dns.rdatatype.SOA: (
            "ns1.example.com.",
            "admin.example.com.",
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },
    "nyu.edu.": {
        dns.rdatatype.A: "192.168.1.106",
        dns.rdatatype.TXT: (
            base64.b64encode(encrypted_value).decode("utf-8"),
        ),
        dns.rdatatype.MX: [(10, "mxa-00256a01.gslb.pphosted.com.")],
        dns.rdatatype.AAAA: "2001:0db8:85a3:0000:0000:8a2e:0373:7312",
        dns.rdatatype.NS: "ns1.nyu.edu.",
    },
    "safebank.com.": {dns.rdatatype.A: "192.168.1.102"},
    "google.com.": {dns.rdatatype.A: "192.168.1.103"},
    "legitsite.com.": {dns.rdatatype.A: "192.168.1.104"},
    "yahoo.com.": {dns.rdatatype.A: "192.168.1.105"},
}

def run_dns_server() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 53))

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            q = request.question[0]
            qname = q.name.to_text()
            qtype = q.rdtype

            if qname in dns_records and qtype in dns_records[qname]:
                record_data = dns_records[qname][qtype]
                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, host in record_data:
                        rdata_list.append(
                            MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, host)
                        )

                elif qtype == dns.rdatatype.SOA:
                    rdata_list.append(
                        SOA(
                            dns.rdataclass.IN,
                            dns.rdatatype.SOA,
                            *record_data,
                        )
                    )

                elif qtype == dns.rdatatype.TXT:
                    # dnspython expects each TXT chunk quoted
                    strings = record_data if isinstance(record_data, tuple) else (record_data,)
                    for s in strings:
                        rdata_list.append(
                            dns.rdata.from_text(
                                dns.rdataclass.IN, dns.rdatatype.TXT, f'"{s}"'
                            )
                        )

                else:  # A, AAAA, CNAME, NS …
                    items = record_data if isinstance(record_data, (list, tuple)) else (record_data,)
                    for item in items:
                        rdata_list.append(
                            dns.rdata.from_text(dns.rdataclass.IN, qtype, item)
                        )

                for r in rdata_list:
                    rrset = dns.rrset.RRset(q.name, dns.rdataclass.IN, qtype)
                    rrset.ttl = 300
                    rrset.add(r)
                    response.answer.append(rrset)

            response.flags |= 1 << 10  # recursion-available
            print("Responding to request:", qname)
            sock.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            print("\nExiting …")
            sock.close()
            sys.exit(0)


def run_dns_server_user() -> None:
    print("DNS server is running.  Type 'q' + Enter to quit.")

    def watcher():
        while True:
            if input().strip().lower() == "q":
                os.kill(os.getpid(), signal.SIGINT)

    t = threading.Thread(target=watcher, daemon=True)
    t.start()
    run_dns_server()


if __name__ == "__main__":
    run_dns_server_user()

