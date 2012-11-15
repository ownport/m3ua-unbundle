#!/usr/bin/env python
#
#   M3UA unbundle
#   
#   tshark -x -r <source.pcap> | python m3ua-unbundle.py  | text2pcap -l141 -t "%H:%M:%S." - <result.pcap>
# 
__author__ = 'Andrey Usov <https://github.com/ownport/m3ua-unbundle>'
__version__ = '0.1.1'
__license__ = """
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 'AS IS'
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE."""


import sys
import math

PROTOCOLS = {
    'SCTP': 132,
}

SCTP_CHUNK_TYPES = {
    'DATA': 0,
    'INIT': 1,
    'INIT ACK': 2,
    'SACK': 3,	
    'HEARTBEAT': 4,
    'HEARTBEAT ACK': 5, 
    'ABORT': 6,
    'SHUTDOWN': 7,
    'SHUTDOWN ACK': 8,
    'ERROR': 9,
    'COOKIE ECHO': 10,
    'COOKIE ACK': 11,
    'ECNE': 12,
    'CWR': 13,
    'SHUTDOWN': 14,
}

def remove_extra(chunk):
    ''' remove extra symbols '''
    
    chunk = chunk[0:53]
    fields = chunk.split(' ')[2:18]
    return ' '.join(fields)

def handle_packet(current_time, data):
    ''' handle packet '''
    data = data.split(' ')
    
    (ethernet_header, data)   = extract_ethernet(data)
    if ethernet_header['ip.type'] <> ['08', '00']:
        # raise RuntimeError('Unknown IP type: %s' % ethernet_header['ip.type'])
        return data
    
    (ipv4_header, data)       = extract_ipv4(data)
    if ipv4_header['protocol'] <> PROTOCOLS['SCTP']:
        # raise RuntimeError('Unknown protocol: %s' % ipv4_header['protocol'])
        return data
        
    (sctp_data, data)       = extract_sctp(current_time, data)
    return data

def extract_ethernet(data):
    ''' extract ethernet header data '''

    header = dict()
    header['mac.desctination'] = data[0:6]
    header['mac.source'] = data[6:12]
    header['ip.type'] = data[12:14]
    return (header, data[14:])

def extract_ipv4(data):
    ''' extract ipv4 header data '''  
      
    header = dict()
    header['version'] = data[0][0]
    header['length'] = int(data[0][1],16) * 4 # length in bytes
    header['dscp'] = data[1]
    header['total_length'] = data[2:4]
    header['identification'] = data[4:6]
    header['flags'] = data[6]
    header['fragment_offset'] = data[6:8]
    header['ttl'] = data[8]
    header['protocol'] = int(data[9], 16)
    return (header, data[header['length']:])

def extract_sctp(current_time, data):
    ''' extact sctp header data '''
    
    header = dict()
    header['source_port'] = data[0:2]
    header['desctination_port'] = data[2:4]
    header['verification_tag'] = data[4:8]
    header['checksum'] = data[8:12]
    data = data[12:]
    
    while True:
        if len(data) == 0:
            break
        (sctp_chunk, data) = extract_sctp_chunk(data)
        if sctp_chunk['type'] == SCTP_CHUNK_TYPES['DATA']:
            # protocol payload identifier
            payload_identifier = int(''.join(sctp_chunk['data'][12:16]), 16)
            if payload_identifier == 3: # M3UA
                if (sctp_chunk['length'] - 16) < 8:  # small chunk
                    continue
                payload = sctp_chunk['data'][16:sctp_chunk['length']]
                m3ua_hdr, payload = m3ua_header(payload)
                mtp3_hdr = m3ua_to_mtp3(m3ua_hdr)
                if not mtp3_hdr:
                    continue
                if 'protocol.padding' in m3ua_hdr:
                    payload = mtp3_hdr + payload[:-m3ua_hdr['protocol.padding']]
                else:
                    payload = mtp3_hdr + payload
                print_data(current_time, payload)
            else:
                if sctp_chunk['length'] % 4 <> 0:
                    chunk_padding = 4 - sctp_chunk['length'] % 4
                    data = data[chunk_padding:]
    return (header, data)

def extract_sctp_chunk(data):
    ''' extract sctp chunk data '''
    header = dict()
    header['type'] = int(data[0], 16)
    header['flags'] = data[1]
    header['length'] = int(''.join(data[2:4]), 16)
    header['data'] = data[0:header['length']]    
    return (header, data[header['length']:])

def m3ua_header(data):
    ''' extract M3UA header information '''
    def network_appearance(data):
        ''' return network_appearance parameters '''
        
        header = dict()
        length = int(''.join(data[0:2]),16)
        header['network_appearance'] = int(''.join(data[2:6]),16)
        return (header, data[length - 2:])

    def protocol(data):
        ''' return protocol parameters '''
        
        header = dict()
        length = int(''.join(data[0:2]),16)
        header['protocol.opc'] = int(''.join(data[2:6]),16)
        header['protocol.dpc'] = int(''.join(data[6:10]),16)
        header['protocol.si'] = int(data[10],16)
        header['protocol.ni'] = int(data[11],16)
        header['protocol.mp'] = data[12]
        header['protocol.sls'] = int(data[13],16)
        if length % 4 <> 0:
            header['protocol.padding'] = 4 - length % 4
        return (header, data[14:])

    header = dict()
    header['version'] = data[0]
    header['reserved'] = data[1]
    header['message_class'] = data[2]
    header['message_type'] = data[3]
    header['message_length'] = int(''.join(data[4:8]),16)

    # handle tags
    data = data[8:]
    while True:
        try:
            tag = data[0:2]
            if tag == ['00','06']:
                data = data[8:]    
            elif tag == ['02','00']:
                (na_hdr, data) = network_appearance(data[2:])
                header.update(na_hdr)
            elif tag == ['02','10']:
                (protocol_hdr, data) = protocol(data[2:])
                header.update(protocol_hdr)
            else:
                break
        except ValueError:
            break
        except IndexError:
            break
    return (header, data)

def m3ua_to_mtp3(m3ua_header):
    mtp3_header = list()
    # Service information octet
    try:
        sio = '%02x' % ((m3ua_header['protocol.ni'] << 6) + m3ua_header['protocol.si'])
        mtp3_header.append(sio)
        routing_label = (m3ua_header['protocol.sls'] << 28) + \
                        (m3ua_header['protocol.opc'] << 14) + \
                        m3ua_header['protocol.dpc']
        routing_label = '%08x' % routing_label
        routing_label = [routing_label[i:i+2] for i in range(0, len(routing_label), 2)]
        routing_label.reverse()
        mtp3_header.extend(routing_label)
    except KeyError:
        return None
    return mtp3_header

def print_data(current_time, data):
    ''' print data block '''

    print '%s' % current_time
    row_id = 0
    while True:
        if row_id >= len(data):
            break
        print '%04X' % row_id, ' '.join(data[row_id:row_id+16])
        row_id += 16
    print

if __name__ == '__main__':

    current_time = '00:00:00.0000'
    data_block = list()
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        if line[-1] == '\n':
            line = line[:-1]
                
        if line:
            data_block.append(line)
        else:
            if len(data_block) > 1:
                filtered_block = ''
                for chunk in data_block:
                    filtered_block += ' ' + remove_extra(chunk)
                    filtered_block = filtered_block.strip()
                handle_packet(current_time, filtered_block)
            else:
                try:
                    curr_time_str = ' '.join(data_block).strip()
                    curr_time_str_split = [f for f in curr_time_str.split(' ') if f]
                    secs, msecs = map(int, curr_time_str_split[1].split('.'))
                    hours = secs / 3600
                    mins = (secs - hours * 3600) / 60
                    secs = (secs - hours * 3600 - mins * 60)
                    current_time = "%02d:%02d:%02d.%06d" % (hours, mins, secs, msecs)
                except:
                    pass
            data_block = list()

