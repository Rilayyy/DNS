#!/usr/bin/env -S python3 -u

import argparse, socket, time, json, select, struct, sys, math
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A
from cache import DNSCache
from collections import defaultdict

class Server:
    def __init__(self, root_ip, domain, port):
        self.root_ip = root_ip
        self.domain = ""

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("0.0.0.0", port))
        self.port = self.socket.getsockname()[1]

        self.authoritative_records = defaultdict(list)
        self._parse_zone_file(domain)
        self.log("Bound to port %d" % self.port)

    def _parse_zone_file(self, zone_file):
        """
        Reads the zone file, extracts the SOA records to establish domain space and maps all records to a dic

        :param zone_file: File path to the zone file
        :return: None
        """

        with open(zone_file, 'r') as f:
            zone_data = f.read()

        raw_record = RR.fromZone(zone_data)

        for record in raw_record:
            if record.rtype == QTYPE.SOA:
                self.domain = str(record.rname)

            domain = str(record.rname)
            qtype = record.rtype

            self.authoritative_records[(domain, qtype)].append(record)

    def log(self, message):
        sys.stderr.write(message + "\n")
        sys.stderr.flush()

    def send(self, addr, message):
        self.log("Sending message:\n%s" % message)
        self.socket.sendto(message.pack(), addr)

    def recv(self, socket):
        data, addr = socket.recvfrom(65535)

        # Unpack the DNS request
        request = DNSRecord.parse(data)
        self.log("Received message:\n%s" % request)

        qname = str(request.q.qname)
        qtype = request.q.qtype

        # YOU WILL NEED TO ACTUALLY DO SOMETHING SMART HERE
        # WE ARE JUST REPLYING WITH A FIXED RESPONSE
        response = request.reply()

        if qname.endswith(self.domain):
            response.header.aa = 1

            correct_records = self.authoritative_records.get((qname, qtype), [])

            if correct_records: 
                for record in correct_records:
                    response.add_answer(record)

            else:
                response.header.rcode = 3
            
            self.send(addr, response)
        
        else:
            external_response = self._resolve_external(request)
        
            if external_response:
                self.send(addr, external_response)
            else:
                response.header.rcode = 3
                self.send(addr, response)
        

    def _resolve_external(self, request):
        """
        Resolves the request to an external server

        :param request: The request to resolve
        :return: The response
        """
    

    def run(self):
        seq = 0
        while True:
            socks = select.select([self.socket], [], [], 0.1)[0]
            for conn in socks:
                self.recv(conn)

        return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='send data')
    parser.add_argument('root_ip', type=str, help="The IP address of the root server")
    parser.add_argument('zone', type=str, help="The zone file for this server")
    parser.add_argument('--port', type=int, help="The port this server should bind to", default=0)
    args = parser.parse_args()
    sender = Server(args.root_ip, args.zone, args.port)
    sender.run()