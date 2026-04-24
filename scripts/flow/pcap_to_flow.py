import dpkt
import socket

import argparse
import sys
import csv
import time

PROTOCOLS = [dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP]


class Flow:
    def __init__(self, first_timestamp: float, packet_byte: int) -> None:
        self.start_time = first_timestamp
        self.end_time = first_timestamp
        self.packet_count = 1
        self.byte_count = packet_byte
        
    def update(self, timestamp: float, packet_byte: int) -> None:
        self.end_time = timestamp
        self.packet_count += 1
        self.byte_count += packet_byte
        
    def calc_duration(self) -> float:
        return self.end_time - self.start_time
    
    
def inet_to_str(addr: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET, addr)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, addr)

def get_flow_fivetuple(
    ip: dpkt.ip.IP | dpkt.ip6.IP6, 
    proto: int
) -> tuple[str, str, int, int, int]:
    src_ip = inet_to_str(ip.src) # type: ignore
    dst_ip = inet_to_str(ip.dst) # type: ignore    
    trans = ip.data
    src_port = getattr(trans, 'sport', 0)
    dst_port = getattr(trans, 'dport', 0)    
    endpoints = sorted([(src_ip, src_port), (dst_ip, dst_port)])
    return (endpoints[0][0], endpoints[1][0], endpoints[0][1], endpoints[1][1], proto)
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser()    
    parser.add_argument("--input_path", type=str)
    parser.add_argument("--output_path", type=str)    
    args = parser.parse_args()
    
    input_path = args.input_path
    output_path = args.output_path
    print(f"Processing: {input_path}")
    
    flow_dict = {}
    start_timer = time.perf_counter()
    
    with open(input_path, 'rb') as f:

        try:
            pcap = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            try:
                pcap = dpkt.pcapng.Reader(f)
            except ValueError:
                sys.exit(1)

        
        for ts, buf in pcap:
            # parse eth
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except:
                continue
            
            # parse ip
            if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            ip = eth.data

            # check protocol
            if isinstance(ip, dpkt.ip.IP):
                proto = ip.p # type: ignore
            elif isinstance(ip, dpkt.ip6.IP6):
                proto = ip.nxt # type: ignore
            if proto not in PROTOCOLS:
                continue
            
            try:
                fivetuple = get_flow_fivetuple(ip, proto)
                packet_byte = len(buf)
                if fivetuple not in flow_dict:
                    # create new flow
                    flow_dict[fivetuple] = Flow(ts, packet_byte)
                else:
                    # update exist flow
                    flow_dict[fivetuple].update(ts, packet_byte)
            except Exception:
                continue
        
        with open(output_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 
                            'duration', 'packet_num', 'packet_persec', 'byte_num', 'byte_persec'])
            
            for fivetuple, flow in flow_dict.items():
                duration = flow.calc_duration()
                if duration > 0:
                    packet_persec = flow.packet_count / duration
                    byte_persec = flow.byte_count / duration
                else:
                    packet_persec = 0.0
                    byte_persec = 0.0
                
                writer.writerow([
                    flow.start_time, fivetuple[0], fivetuple[1], fivetuple[2], fivetuple[3], fivetuple[4],
                    f"{duration:.6f}", flow.packet_count, f"{packet_persec:.3f}", flow.byte_count, f"{byte_persec:.3f}"
                ])
            
    end_timer = time.perf_counter()
    process_time = end_timer - start_timer
    
    print(f"flow_num = {len(flow_dict)}")
    print(f"process time = {process_time:.3f}")