class ResultSet():
    def __init__(self, name, rtype, rclass, time_to_leave, rdata):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.time_to_leave = time_to_leave
        self.rdata = rdata
        # self.rdata_length = rdata_length
        # self.last_byte_index = last_byte_index
        # self.byte_message = b''

class QuestionSet():
    def __init__(self, name, qtype, qclass):
        self.name = name
        self.qtype = qtype
        self.qclass = qclass