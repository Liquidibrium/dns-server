from ipaddress import IPv6Address
from struct import unpack
from constants import Types, write_in_file
from header_sets import QuestionSet, ResultSet


class DNSMessageParser():

    def __init__(self, request):
        self.request = request
        self.index = 0
        self.parse_header()
        self.questions = [self.parse_question()
                            for _ in range(self.count_questions)]
        self.answers = [self.parse_answer()
                            for _ in range(self.count_answers)]
        self.authorities = [self.parse_authority()
                            for _ in range(self.count_authorities)]
        self.additions = [self.parse_additional()
                            for _ in range(self.count_additional)]
    
    # parse 12 bytes long dns header
    def parse_header(self):
        self.index += 12
        self.request_id, self.flags, self.count_questions, self.count_answers, self.count_authorities, self.count_additional = unpack(
            '!HHHHHH', self.request[:self.index])
        self._parse_flags()

    def _parse_flags(self):
        self.qr = (self.flags & 1 << 15) >> 15
        self.opcode = (self.flags & 0x7800) >> 12
        self.aa = (self.flags & 1 << 10) >> 10
        self.tc = (self.flags & 1 << 9) >> 9
        self.rd = (self.flags & 1 << 8) >> 8
        self.ra = (self.flags & 1 << 7) >> 7
        self.z = (self.flags & 0x70) >> 4
        self.rcode = self.flags & 0xF

    # return domain name if fist byte indicates offset
    # then domain name is return from that offset
    def _parse_name(self, index):
        name = ''
        while True:
            octet = unpack('!B', self.request[index:index + 1])[0]
            if octet == 0:
                return (name, index + 1)
            if octet & 0xC0 != 0xC0:  # 11*
                name += self.request[index + 1: index +
                                     1 + octet].decode('utf-8') + '.'
                index += octet + 1
            else:  # DNS Packet Compression
                offset = unpack('!H', self.request[index:index + 2])[0]
                offset &= 0x3FFF  # make first two bits  zero
                return (name + self._parse_name(offset)[0], index + 2)
        return (name, index)

    def parse_question(self):
        domain_name, self.index = self._parse_name(self.index)
        qtype, qclass = unpack(
            '!HH', self.request[self.index:self.index+4])
        self.index += 4
        return QuestionSet(domain_name, qtype, qclass)

    def parse_result_set(self):
        name, self.index = self._parse_name(self.index)
        result_type, result_class, time_to_leave, rdata_length = unpack(
            '!HHIH', self.request[self.index:self.index+10])
        self.index += 10
        data = self._parse_rdata(
            result_type, result_class, rdata_length)
        self.index += rdata_length
        return ResultSet(name, result_type, result_class, time_to_leave, data)

    def _parse_rdata(self, answer_type, answer_class, rdata_length):
        if answer_type == Types.A:
            ip_bytes = unpack('!BBBB', self.request[self.index:self.index+4])
            ipv4 = f'{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}'
            return ipv4
        if answer_type == Types.CNAME or answer_type == Types.NS:
            name, _ = self._parse_name(self.index)
            return name
        if answer_type == Types.MX:
            pref = unpack('!H', self.request[self.index:self.index+2])
            mail = self._parse_name(self.index+2)
            return (pref, *mail)
        if answer_type == Types.SOA:
            name_server, new_index = self._parse_name(self.index)
            host, new_index = self._parse_name(new_index)
            rest_info = unpack(
                '!IIIII', self.request[new_index:new_index+20])
            return (name_server, host, *rest_info)  # change this
        if answer_type == Types.TXT:
            text = self.request[self.index+1:self.index +
                                rdata_length-1].decode('utf-8')
            return text
        if answer_type == Types.AAAA:
            return IPv6Address(self.request[self.index:self.index+rdata_length]).compressed
        # unsupported
        return None

    def parse_answer(self):
        return self.parse_result_set()

    def parse_authority(self):
        return self.parse_result_set()

    def parse_additional(self):
        return self.parse_result_set()
