import argparse
import socket
import time

from dnslib import DNSRecord, QTYPE, RCODE


def parse_server(value: str) -> str:
    if value.startswith("@"):
        return value[1:]
    return value


def format_rr(rr) -> str:
    return f"{rr.rname}\t{rr.ttl}\t{rr.rclass}\t{QTYPE.get(rr.rtype, rr.rtype)}\t{rr.rdata}"


def print_section(title: str, records) -> None:
    print(f"\n;; {title} SECTION ({len(records)})")
    for rr in records:
        print(format_rr(rr))


def query(server: str, port: int, name: str, rtype: str, timeout: float) -> DNSRecord:
    qtype_code = getattr(QTYPE, rtype.upper(), None)
    if qtype_code is None:
        raise SystemExit(f"Unsupported query type: {rtype}")

    request = DNSRecord.question(name, rtype.upper())
    data = request.pack()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(data, (server, port))
        response, _ = sock.recvfrom(4096)
    return DNSRecord.parse(response)


def main() -> None:
    parser = argparse.ArgumentParser(description="A dig-like DNS query client.")
    parser.add_argument("server", help="DNS server, for example @127.0.0.1")
    parser.add_argument("name", help="Domain name to query")
    parser.add_argument("rtype", nargs="?", default="A", help="Record type: A, AAAA, CNAME")
    parser.add_argument("-p", "--port", type=int, default=53, help="DNS server UDP port")
    parser.add_argument("-t", "--timeout", type=float, default=4.0, help="Timeout seconds")
    args = parser.parse_args()

    server = parse_server(args.server)
    started = time.perf_counter()
    response = query(server, args.port, args.name, args.rtype, args.timeout)
    elapsed_ms = (time.perf_counter() - started) * 1000

    header = response.header
    print(f";; ->>HEADER<<- opcode: {header.opcode}, status: {RCODE.get(header.rcode)}, id: {header.id}")
    print(
        ";; flags:"
        f" qr={header.qr} aa={header.aa} tc={header.tc} rd={header.rd}"
        f" ra={header.ra}; QUERY: {len(response.questions)},"
        f" ANSWER: {len(response.rr)}, AUTHORITY: {len(response.auth)}, ADDITIONAL: {len(response.ar)}"
    )

    print("\n;; QUESTION SECTION")
    for q in response.questions:
        print(f";{q.qname}\t{q.qclass}\t{QTYPE.get(q.qtype, q.qtype)}")

    print_section("ANSWER", response.rr)
    print_section("AUTHORITY", response.auth)
    print_section("ADDITIONAL", response.ar)
    print(f"\n;; Query time: {elapsed_ms:.2f} msec")
    print(f";; SERVER: {server}#{args.port}")


if __name__ == "__main__":
    main()
