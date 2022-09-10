from iputils import *
import struct
import ipaddress
from sys import prefix
from grader.iputils import IPPROTO_ICMP
from grader.tcputils import addr2str, calc_checksum, fix_checksum, str2addr

class IP:
    def _init_(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.table = []
        self.count = 0

    def __raw_recv(self, datagram):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = read_ipv4_header(datagram)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            if ttl-1 > 0:
                ttl = ttl - 1
                newdatagram = struct.pack('!BBHHHBBHII', 69, dscp | ecn, 20, identification, flags | frag_offset, ttl, proto, 0, int.from_bytes(str2addr(src_addr), 'big'), int.from_bytes(str2addr(dst_addr), 'big'))
                checksum = calc_checksum(newdatagram)
                newdatagram = struct.pack('!BBHHHBBHII', 69, dscp | ecn, 20, identification, flags | frag_offset, ttl, proto, checksum, int.from_bytes(str2addr(src_addr), 'big'), int.from_bytes(str2addr(dst_addr), 'big'))
                self.enlace.enviar(newdatagram, next_hop)
            else:
                next_hop2 = self._next_hop(src_addr)
                errordatagram = struct.pack('!BBHHHBBHII', 69, dscp | ecn, 48, identification, flags | frag_offset, 64, IPPROTO_ICMP, 0, int.from_bytes(str2addr(self.meu_endereco), 'big'), int.from_bytes(str2addr(src_addr), 'big'))
                checksum2 = calc_checksum(errordatagram)
                errordatagram = struct.pack('!BBHHHBBHII', 69, dscp | ecn, 48, identification, flags | frag_offset, 64, IPPROTO_ICMP, checksum2, int.from_bytes(str2addr(self.meu_endereco), 'big'), int.from_bytes(str2addr(src_addr), 'big'))
                icmp = struct.pack('!BBHHH', 11, 0, 0, 0, 0)
                checksum3 = calc_checksum(errordatagram + icmp)
                icmp = struct.pack('!BBHHH', 11, 0, checksum3, 0, 0)
                errordatagram = errordatagram + icmp + datagram[:28]
                self.enlace.enviar(errordatagram, next_hop2)

    def _next_hop(self, dest_addr):
        # TODO: Use a table de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        counter = 0
        index = []
        maxprefixlenght = 0
        higher = 0
        for i in range(len(self.table)):
            if ipaddress.ip_address(dest_addr) in ipaddress.ip_network(self.table[i][0]):
                counter += 1
                index.append(i)
        if counter > 1:
            for j in index:
                if (ipaddress.ip_network(self.table[j][0])).prefixlen > maxprefixlenght:
                    maxprefixlenght = (ipaddress.ip_network(self.table[j][0])).prefixlen
                    higher = j
            return self.table[higher][1]
        elif counter == 1:
            return self.table[index[0]][1]
        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, table):
        """
        Define a table de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]
        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a table de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.table = table

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        datagram = struct.pack('!BBHHHBBHII', 69, 0, 20+len(segmento), self.count+1, 0, 64, 6, 0, int.from_bytes(str2addr(self.meu_endereco), 'big'), int.from_bytes(str2addr(dest_addr), 'big'))
        headerchecksum = calc_checksum(datagram)
        datagram = struct.pack('!BBHHHBBHII', 69, 0, 20+len(segmento), self.count+1, 0, 64, 6, headerchecksum, int.from_bytes(str2addr(self.meu_endereco), 'big'), int.from_bytes(str2addr(dest_addr), 'big'))
        datagram = datagram + segmento
        self.count = self.count + 1
        self.enlace.enviar(datagram, next_hop)
