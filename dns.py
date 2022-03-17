#!/usr/bin/env python3

"""
toy recursive DNS resolver that does its own parsing and socket communication, just for fun
"""

import io
import random
import socket
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import List


class RecordType(IntEnum):
    """
    https://en.wikipedia.org/wiki/List_of_DNS_record_types
    """
    A = 1
    NS = 2
    MX = 15


def serialize_qname(qname):
    """
    pack a domain name as a sequence of length-prefixed labels, without compression
    e.g. www.twitter.com will be encoded like this:
    [3]www[7]twitter[3]com[0]
    """
    if not qname.endswith('.'):
        qname += '.'
    labels = qname.split('.')

    enc = bytearray()
    for label in labels:
        enc.append(len(label))
        enc.extend(label.encode())

    return enc


def deserialize_qname(buf):
    """
    parse a packed (potentially compressed) domain name into a string like www.twitter.com.
    """
    return b'.'.join(deserialize_labels(buf)).decode()


def deserialize_labels(buf):
    """
    parse a packed (potentially compressed) domain name into a list of labels
    like ['www', 'twitter', 'com', '']
    """
    labels = []
    while True:
        length, = struct.unpack('!B', buf.read(1))
        if length == 0:
            labels.append(b'')
            break
        elif length >= 0b11000000:
            # recursively follow pointers used for compression
            # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
            ptr_half, = struct.unpack('!B', buf.read(1))
            ptr = ptr_half | ((length & 0b00111111) << 8)

            # save the current position and restore it after finished following the pointer
            saved_pos = buf.tell()
            buf.seek(ptr)
            labels.extend(deserialize_labels(buf))
            buf.seek(saved_pos)
            break
        else:
            labels.append(buf.read(length))
    return labels


@dataclass
class Header:
    """
    https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1

      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """
    ident: int
    qr: bool
    opcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    z: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

    def serialize(self):
        flags = (
            self.rcode
            | (self.z << 4)
            | (self.ra << 7)
            | (self.rd << 8)
            | (self.tc << 9)
            | (self.aa << 10)
            | (self.opcode << 11)
            | (self.qr << 15)
        )

        return struct.pack('!HHHHHH', self.ident, flags, self.qdcount, self.ancount, self.nscount, self.arcount)
    
    @staticmethod
    def deserialize(buf):
        ident, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', buf.read(12))

        rcode =  (flags & 0b0000000000001111)
        z =      (flags & 0b0000000001110000) >> 4
        ra =     (flags & 0b0000000010000000) >> 7  > 0
        rd =     (flags & 0b0000000100000000) >> 8  > 0
        tc =     (flags & 0b0000001000000000) >> 9  > 0
        aa =     (flags & 0b0000010000000000) >> 10 > 0
        opcode = (flags & 0b0111100000000000) >> 11
        qr =     (flags & 0b1000000000000000) >> 15 > 0

        return Header(ident, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount)


@dataclass
class Question:
    """
    https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """
    qname: str
    qtype: int
    qclass: int

    def serialize(self):
        return serialize_qname(self.qname) + struct.pack('!HH', self.qtype, self.qclass)
    
    @staticmethod
    def deserialize(buf):
        qname = deserialize_qname(buf)
        qtype, qclass = struct.unpack('!HH', buf.read(4))
        return Question(qname, qtype, qclass)


@dataclass
class Record:
    """
    https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3

      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """
    qname: str
    rtype: int
    rclass: int
    ttl: int
    rdlen: int
    rdata: bytes
    rdata_cursor: int

    @staticmethod
    def deserialize(buf):
        qname = deserialize_qname(buf)
        rtype, rclass, ttl, rdlen = struct.unpack('!HHiH', buf.read(10))
        rdata_cursor = buf.tell()
        rdata = buf.read(rdlen)
        return Record(qname, rtype, rclass, ttl, rdlen, rdata, rdata_cursor)


@dataclass
class Message:
    """
    https://datatracker.ietf.org/doc/html/rfc1035#section-4.1

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+
    """
    header: Header
    questions: List[Question]
    answers:     List[Record]
    authorities: List[Record]
    additionals: List[Record]

    def serialize(self):
        return (
            self.header.serialize() +
            b''.join([q.serialize() for q in self.questions]) +
            b''.join([r.serialize() for r in self.answers + self.authorities + self.additionals])
        )

    @staticmethod
    def query(qname, qtype):
        header = Header(
            ident=random.getrandbits(16),
            qr=False,
            opcode=0,
            aa=False,
            tc=False,
            rd=False,
            ra=False,
            z=0,
            rcode=0,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0
        )
        question = Question(qname, qtype, 1)
        return Message(header, [question], [], [], [])
    
    @staticmethod
    def deserialize(buf):
        header = Header.deserialize(buf)
        questions = []
        answers = []
        authorities = []
        additionals = []

        for _ in range(header.qdcount):
            questions.append(Question.deserialize(buf))

        for _ in range(header.ancount):
            answers.append(Record.deserialize(buf))

        for _ in range(header.nscount):
            authorities.append(Record.deserialize(buf))

        for _ in range(header.arcount):
            additionals.append(Record.deserialize(buf))

        return Message(header, questions, answers, authorities, additionals)


def single_query(query, ip):
    """
    send a message to the given ip, and returns the parsed response
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query.serialize(), (ip, 53))
    data, _ = sock.recvfrom(4096)
    buf = io.BytesIO(data)
    response = Message.deserialize(buf)
    return response, buf


def recursive_resolve(qname, qtype):
    """
    resolve the record for a given domain name and type, beginning with a hard-coded root server and
    following the glue and NS records all the way down

    check out https://jvns.ca/blog/2022/02/01/a-dns-resolver-in-80-lines-of-go/
    """
    query = Message.query(qname, qtype)
    ip = '198.41.0.4'

    while True:
        response, buf = single_query(query, ip)

        if len(response.answers) > 0:
            for record in response.answers:
                if record.rtype == qtype == RecordType.A:
                    return socket.inet_ntoa(record.rdata)
                if record.rtype == qtype == RecordType.MX:
                    buf.seek(record.rdata_cursor)
                    buf.read(2)
                    return deserialize_qname(buf)
            raise Exception('answers did not contain right record')

        elif len(response.additionals) > 0:
            for record in response.additionals:
                if record.rtype == RecordType.A:
                    ip = socket.inet_ntoa(record.rdata)
                    break

        elif len(response.authorities) > 0:
            for record in response.authorities:
                if record.rtype == RecordType.NS:
                    buf.seek(record.rdata_cursor)
                    authority_name = deserialize_qname(buf)
                    ip = recursive_resolve(authority_name, RecordType.A)
                    break

        else:
            raise Exception(f'could not resolve {qname}')


if __name__ == '__main__':
    print('A twitter.com:', recursive_resolve('twitter.com', RecordType.A))
    print('MX google.com:', recursive_resolve('google.com', RecordType.MX))
