import socket
import threading
from parser import DNSMessageParser
from struct import pack, unpack
from time import time
from builder import DNSMessageBuilder
from constants import (MSG_MAX_SIZE, MSG_SIZE, ROOT_SERVER_IPS, Types,
                       random_id, write_in_file)


class DNSServer:

    def __init__(self, ip, port, zones=[]):
        self.ip = ip
        self.port = port
        self._init_socket()
        self.zones = zones
        self.thread_pool = []
        self.shut_down = False
        # contains domain:response pairs
        self.cache = {}  # TODO make cache global and  thread safe
        # save all name servers with (domain_name, querty type, nameserver ip)
        # if name server  returned answer it is already saved in cache
        # this for recursion not to be infinite
        self.bed_name_servers = set()

    def _init_socket(self):
        #  crate UDP socket
        self.dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # make reuseable
        self.dns_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.dns_socket.bind((self.ip, self.port))

    def _lookup_cache(self, name, qtype_code):
        # just check if name and query type is in cache and return it
        # TODO add  time to leave
        if (name, qtype_code) in self.cache:
            cache_res, time_to_leave =  self.cache[(name, qtype_code)]
            if time_to_leave >= time():
                return cache_res
        return None

    def _ask_server(self, server_ip, message, message_id):
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.sendto(message, (server_ip, 53))
        udp_socket.settimeout(1)  # set timeout for name server response
        try:
            server_response, _ = udp_socket.recvfrom(
                MSG_MAX_SIZE)  # (MSG_SIZE)
            if server_response:
                parsed_response = DNSMessageParser(server_response)
                # check responde id if is correct
                if parsed_response.request_id == message_id:
                    return server_response, parsed_response
        except:
            pass
        finally:
            udp_socket.close()
        return None, None

    # build recursion desired request for root or name servers
    def _build_rd_query(self, name, qtype_code, request_id):
        builder = DNSMessageBuilder(request_id)
        builder.build_flags()
        builder.build_head(1, 0, 0, 0)
        builder.build_query(name, qtype_code, 1)
        return builder.message

    # recursive lookup for domain name and type
    # first,  the function lookups in local cashe
    # if not found then goes to global servers with ipv4 (TODO ipv6 support)
    # if return response contains proper answer response is returned
    # if not lookup for ips of name servers in server response message
    # and sends query to them
    def _lookup_recursive(self, name, qtype_code, request_id, message, server_ips=ROOT_SERVER_IPS):
        cache_res = self._lookup_cache(name, qtype_code)
        if cache_res is not None:
            return cache_res

        for server_ip in server_ips:
            if (name, qtype_code, server_ip) in self.bed_name_servers:
                break
            self.bed_name_servers.add((name, qtype_code, server_ip))

            server_response, parsed_server_response = self._ask_server(
                server_ip, message, request_id)
            # if receive something # and is not trucated
            if server_response is not None and parsed_server_response.tc != 1:
                if parsed_server_response.count_answers > 0:
                    time_to_leave = parsed_server_response.answers[0].time_to_leave + time()
                    self.cache[(name, qtype_code)] = (server_response , time_to_leave)
                    return server_response

                for auth in parsed_server_response.authorities:
                    # check if it is authoritive name server
                    if auth.rtype == Types.NS:
                        found = False
                        # search  for name server ip in additional result set data
                        for addit in parsed_server_response.additions:
                            if auth.rdata == addit.name:
                                found = True
                                if addit.rtype == Types.A:  # found ip v4
                                    ip = addit.rdata
                                    res_message = self._lookup_recursive(
                                        name, qtype_code, request_id, message, [ip])
                                    if res_message:
                                        return res_message
                                # break #not nessesary, nameservers can have multiple ips
                        if not found:
                            new_id = random_id()  # new random 16 bit id for query
                            new_message = self._build_rd_query(
                                auth.rdata, Types.A, new_id)
                            # look up for name server ips
                            res_message = self._lookup_recursive(
                                auth.rdata, Types.A, new_id, new_message)
                            if res_message:
                                parsed = DNSMessageParser(res_message)
                                # get name servers ips from retrurned response
                                ips = [
                                    answer.rdata for answer in parsed.answers if answer.rtype == Types.A]
                                # continue recursive look up and send queries to authority name servers
                                res_message = self._lookup_recursive(
                                    name, qtype_code, request_id, message, ips)
                                if res_message:
                                    return res_message
            else:
                continue

        return None

    #  look up in zone files
    # return proper answever or authoritive nameserver if
    # there is record about that domain name
    def _lookup_zone(self, name, qtype_code, request_id):
        qtype_str = Types.reversed_types[qtype_code]
        for zone in self.zones:
            # check if we have record for domain name
            if name in zone.get_names().keys():
                builder = DNSMessageBuilder(request_id)
                # flags for response and authoritive answer
                builder.build_flags(qr=1, aa=1)
                try:
                    # try to get domain name with query type
                    answer_datas = zone.get_names()[name].records(
                        qtype_str).get_items()
                    builder.build_head(1, len(answer_datas), 0, 0)
                except:
                    # zones has no record about domain name with that qtype
                    # so then return SOA record
                    qtype_code = 6
                    qtype_str = 'SOA'
                    answer_datas = zone.get_names()[name].records(
                        qtype_str).get_items()

                    builder.build_head(1, 0, len(answer_datas), 0)

                builder.build_query(name, qtype_code, 1)

                for data in answer_datas:
                    builder.build_answer(name, qtype_code, 1, 0, data)
                return builder.message
        return None

    # first lookup into local zone files and
    # then try to find answer from root servers
    def _process_question(self, question, request_id, parser):
        name = question.name
        qtype_code = question.qtype
        # qclass = question.qclass # not used
        zone_response = self._lookup_zone(name, qtype_code, request_id)
        if zone_response:
            return zone_response

        # not found in zone files
        # try to get recursive  from local cache
        # or from root name servers
        # message = self._build_rd_query(name,qtype_code,request_id)
        return self._lookup_recursive(name, qtype_code, request_id, parser.request)

    def _handle_request(self, address, received_message):
        parsed_message = DNSMessageParser(received_message)
        # for question in parsed_message.query_questions:  # TODO support for several questions
        response = self._process_question(
            parsed_message.questions[0], parsed_message.request_id, parsed_message)
        self.dns_socket.sendto(response, address)

    def start_server(self):
        while True:
            # if self.shut_down:
            #     # if server received shut down
            #     self._stop_threads()
            #     return
            received_message, address = self.dns_socket.recvfrom(MSG_SIZE)
            # if server received nothing then exit
            # if len(received_message) == 0:
            #     return

            self._handle_request(address, received_message)

            # # handle each reques in threads
            # thread = threading.Thread(
            #     target=self._handle_request, args=(address, received_message))
            # self.thread_pool.append(thread)
            # thread.start()

    def shut_down_server(self):
        self.shut_down = True

    # wait for thread to finish their work
    def _stop_threads(self):
        for thread in self.thread_pool:
            thread.join()
