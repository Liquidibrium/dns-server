from struct import pack
from constants import Types, write_in_file
from ipaddress import IPv6Address


class DNSMessageBuilder():

    def __init__(self, request_id):
        self.request_id = request_id
        self.message = b''

    def build_flags(self, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=1, z=0, rcode=0):
        # self.flags
        flags = 0
        flags |= qr << 15
        flags |= opcode  # opcode
        flags |= aa << 10
        flags |= tc << 9
        flags |= rd << 8
        flags |= ra << 7
        flags |= z  # Z
        flags |= rcode
        self.flags = flags

    def build_head(self, count_questions, count_answers, count_authorities, count_additional):
        self.message += pack('!HHHHHH', self.request_id, self.flags, count_questions,
                             count_answers, count_authorities, count_additional)

    @staticmethod
    def _build_name(domain_name):
        query_list = []
        parts = domain_name.split('.')
        overall_length = len(parts)
        for part in parts:
            part_length = len(part)
            overall_length += part_length
            if part_length > 63 or overall_length > 255:
                # error
                pass
            query_list.append(pack("!B", part_length))
            query_list.append(part.encode('utf-8'))
        query_list.append(bytes(0))
        return b"".join(query_list)

    def build_query(self, domain_name, qtype, qclass):
        self.message += self._build_name(domain_name) + \
            pack('!H', qtype) + pack('!H', qclass)

    def _build_response_data(self, answer_type, data):
        if answer_type == Types.A:
            ip_bytes = data.split('.')
            return pack('!BBBB', *map(int, ip_bytes))
        if answer_type == Types.CNAME or answer_type == Types.NS:
            return self._build_name(data)
        if answer_type == Types.MX:
            pref = pack('!H', data[0])
            mail = self._build_name(data[1])
            return pref + mail
        if answer_type == Types.SOA:
            soa = data.split()
            name_server = self._build_name(soa[0])
            host = self._build_name(soa[1])
            rest_info = pack(
                '!IIIII', int(soa[2]), int(soa[3]), int(soa[4]), int(soa[5]), int(soa[6]))
            return name_server + host + rest_info
        if answer_type == Types.TXT:
            text = data.encode('utf-8')
            text_len = pack('!B', len(text))
            return text_len + text
        if answer_type == Types.AAAA:
            return IPv6Address(data)._ip.to_bytes(16, 'big')
        # unsupported
        return b""

    def _build_result_set(self, domain_name, answer_type, answer_class,
                          ttl, data):
        name = self._build_name(domain_name)
        atype = pack('!H', answer_type)
        aclass = pack('!H', answer_class)
        time_to_leave = pack('!I', ttl)
        response_data = self._build_response_data(answer_type, data)
        response_data_length = pack('!H', len(response_data))
        self.message += name + atype + aclass + \
            time_to_leave+response_data_length+response_data

    def build_answer(self, domain_name, answer_type, answer_class,
                     ttl, data):
        self._build_result_set(domain_name, answer_type, answer_class,
                               ttl, data)

    def build_authority(self, domain_name, answer_type, answer_class,
                        ttl, data):
        self._build_result_set(domain_name, answer_type, answer_class,
                               ttl, data)

    def build_additional(self, domain_name, answer_type, answer_class,
                         ttl, data):
        self._build_result_set(domain_name, answer_type, answer_class,
                               ttl, data)
