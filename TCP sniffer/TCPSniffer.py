from scapy.all import *
from scapy.layers.inet import TCP
from enum import IntEnum

class TcpFlags(IntEnum):
    CWR = 0x80
    ECE = 0x40
    URG = 0x20
    ACK = 0x10
    PSH = 0x08
    RST = 0x04
    SYN = 0x02
    FIN = 0x01

def get_tcp_flags_names(flags):
    flag_names = [flag.name for flag in TcpFlags if flags & flag.value]
    return ', '.join(flag_names)

def process_tcp_packet(packet):
    if TCP in packet:
        tcp_packet = packet[TCP]
        print(f"Porta de Origem: {tcp_packet.sport}")
        print(f"Porta de Destino: {tcp_packet.dport}")
        print(f"Número de Sequência: {tcp_packet.seq}")
        print(f"Número de Confirmação: {tcp_packet.ack}")
        print(f"Offset: {tcp_packet.dataofs}")
        print(f"Reservados: {tcp_packet.reserved}")
        flags = get_tcp_flags_names(tcp_packet.flags)
        print(f"Flags TCP: {flags}")
        print(f"Tamanho da Janela: {tcp_packet.window}")
        print(f"Ponteiro de Urgência: {tcp_packet.urgptr}")
        print(f"Opções: {tcp_packet.options}")
        data = packet.payload
        print(f"Dados: {data}")

sniff(filter="tcp", prn=process_tcp_packet, count=1)
