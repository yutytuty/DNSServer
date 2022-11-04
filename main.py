import socket


test_packet = b"\x7a\xf5\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77" \
              b"\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"

BUFFERSIZE = 1024
PORT = 53
IP = "0.0.0.0"

DOMAINS: dict[str, str] = {
    "www.batata.co.il": "213.8.147.218"
}


def domain_to_dns_domain(domain: str) -> bytes:
    split = domain.split(".")
    b = b""
    for leaf in split:
        b += len(leaf).to_bytes(1, "big") + leaf.encode()
    return b


def address_to_dns_address(address: str) -> bytes:
    b = b""
    for num in address.split("."):
        b += int(num).to_bytes(1, "big")
    return b


class Query:
    TYPE_A = "\x00\x01"
    IN = "\x00\x01"

    def __init__(self, transaction_id: bytes, flags: bytes, question_num: bytes, answer_num: bytes, authority_num: bytes,
                 additional_num: bytes, domain: str, query_type: bytes, class_type: bytes):
        self.transaction_id = transaction_id
        self.flags = flags
        self.question_num = question_num
        self.answer_num = answer_num
        self.authority_num = authority_num
        self.additional_num = additional_num

        self.domain = domain
        self.query_type = query_type
        self.class_type = class_type

    def body_bytes(self):
        return domain_to_dns_domain(self.domain) + b"\00" + self.query_type + self.class_type


class Response:
    STANDARD_FLAGS = b"\x81\x80"
    DOMAIN_POINTER = b"\xc0\x0c"
    TYPE_A = b"\x00\x01"
    IN = b"\x00\x01"
    # 2 minutes 55 seconds
    TTL = b"\x00\x00\x00\xaf"

    def __init__(self, query: Query, flags: bytes, answer_num: int, domain_pointer: bytes, resp_type: bytes,
                 class_type: bytes, address: str, ip_data_length: int):
        self.query = query
        self.answer_num = answer_num
        self.domain_pointer = domain_pointer
        self.resp_type = resp_type
        self.class_type = class_type
        self.address = address
        self.ip_data_length = ip_data_length
        self.flags = flags

    def encode(self) -> bytes:
        return self.query.transaction_id + self.flags + \
               self.query.question_num + self.answer_num.to_bytes(2, "big") + \
               self.query.authority_num + self.query.additional_num + \
               self.query.body_bytes() + self.domain_pointer + self.resp_type + self.class_type + \
               self.TTL + self.ip_data_length.to_bytes(2, "big") + address_to_dns_address(self.address)


def parse_query(packet: bytes) -> Query:
    """
    parse query
    :param packet: the packet that the user send to the server
    :return: query data class
    """
    query_bytes = packet[12:]
    domain = ""
    while True:
        length = query_bytes[0]
        domain += query_bytes[1:length + 1].decode()
        query_bytes = query_bytes[length + 1:]

        # check for null terminator
        if query_bytes[0] == 0x00:
            query_bytes = query_bytes[1:]
            break

        domain += "."

    return Query(packet[:2], packet[2:4], packet[4:6], packet[6:8], packet[8:10], packet[10:12],
                 domain, query_bytes[:2], query_bytes[2:])


def create_response(query: Query):
    flags = Response.STANDARD_FLAGS
    # assume we return only one answer
    answer_num = 1
    domain_pointer = Response.DOMAIN_POINTER
    resp_type = Response.TYPE_A
    class_type = Response.IN
    if query.domain in DOMAINS.keys():
        address = DOMAINS[query.domain]
    else:
        address = "10.0.0.2"
    ip_data_length = len(address.split("."))

    return Response(query, flags, answer_num, domain_pointer, resp_type, class_type, address, ip_data_length)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((IP, PORT))
    print("listening on: ", (IP, PORT))

    while True:
        try:
            (packet, addr) = s.recvfrom(BUFFERSIZE)
            q = parse_query(packet)
            resp = create_response(q)
            s.sendto(resp.encode(), addr)
        except KeyboardInterrupt:
            print('skill issue lol')
            break

    s.close()


main()
