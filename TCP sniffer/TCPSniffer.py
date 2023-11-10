from scapy.all import *
from scapy.layers.inet import TCP

FLAG_CWR = 0x80
FLAG_ECE = 0x40
FLAG_URG = 0x20
FLAG_ACK = 0x10
FLAG_PSH = 0x08
FLAG_RST = 0x04
FLAG_SYN = 0x02
FLAG_FIN = 0x01

def get_tcp_flags_names(flags):
    flag_names = []
    if flags & FLAG_CWR:
        flag_names.append("CWR")
    if flags & FLAG_ECE:
        flag_names.append("ECE")
    if flags & FLAG_URG:
        flag_names.append("URG")
    if flags & FLAG_ACK:
        flag_names.append("ACK")
    if flags & FLAG_PSH:
        flag_names.append("PSH")
    if flags & FLAG_RST:
        flag_names.append("RST")
    if flags & FLAG_SYN:
        flag_names.append("SYN")
    if flags & FLAG_FIN:
        flag_names.append("FIN")
    return ', '.join(flag_names)

def ProcessarPacote(packet):
    if TCP in packet:
        tcp_packet = packet[TCP]
        print("0 - Porta de Origem: ", tcp_packet.sport)
        print("0 - Porta de Destino: ", tcp_packet.dport)
        print("32 - Número de Sequência: ", tcp_packet.seq)
        print("64 - Número de Confirmação: ", tcp_packet.ack)
        print("96 - Offset: ", tcp_packet.dataofs)
        print("96 - Reservados: ", tcp_packet.reserved)
        flags = get_tcp_flags_names(tcp_packet.flags)
        print("96 - Flags TCP: ", flags)
        print("96 - Tamanho da Janela: ", tcp_packet.window)
        print("128 - Ponteiro de Urgência: ", tcp_packet.urgptr)
        print("160 - Opções: ", tcp_packet.options)
        data = packet.payload
        print("224 - Dados: ", data)

sniff(filter="tcp", prn=ProcessarPacote, count=1)