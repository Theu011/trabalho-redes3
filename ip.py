from iputils import *
import struct
import ipaddress

IPPROTO_TCP = 6

class IP:
    def __init__(self, enlace):
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

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            ttl = ttl - 1
            if ttl != 0:
                aux = 4 << 4
                ihl = 5
                src_addr = str2addr(src_addr)
                dst_addr = str2addr(dst_addr)
                soma = 0
                datagrama = struct.pack('!BBHHHBBH', aux+ihl, dscp+ecn, 20+len(datagrama), identification, flags+frag_offset, ttl, proto, addr_sum) + src_addr + dst_addr
                addr_sum = calc_checksum(datagrama[:4*ihl])
                datagrama = struct.pack('!BBHHHBBH', aux+ihl, dscp+ecn, 20+len(datagrama), identification, flags+frag_offset, ttl, proto, soma) + src_addr + dst_addr
                datagrama = datagrama + payload
                self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        addresses = []
        if len(self.tab_encaminhamento) == 0:
            return None
        else:
            for ip in self.tab_encaminhamento:
                if ipaddress.ip_address(dest_addr) in ipaddress.ip_network(ip[0]):
                    addresses.append((ipaddress.ip_network(ip[0]), ipaddress.ip_address(ip[1])))
            if len(addresses) > 0:
                max = -1
                fim = 0
                for i, j in addresses:
                    if int(i.prefixlen) >= max:
                        max = int(i.prefixlen)
                        fim = a 
                return str(fim)
        
    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tab_encaminhamento = tabela 


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
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.

        count = 0
        self.identification = contador + 1
        next_hop = self._next_hop(dest_addr)
        aux = 4 << 4
        ihl = 5
        identification = self.identification
        ttl = 64
        proto = 6 
        dscp = 0
        flags = 0
        frag_offset = 0
        ecn = 0
        src_addr = str2addr(self.meu_endereco)
        dst_addr = str2addr(dest_addr)
        addr_sum = 0
        datagrama = struct.pack('!BBHHHBBH', aux+ihl, dscp+ecn, 20+len(segmento), identification, flags+frag_offset, ttl, proto, addr_sum) + src_addr+dst_addr
        addr_sum = calc_checksum(datagrama[:4*ihl])
        datagrama = struct('!BBHHHBBH', aux+ihl, dscp+ecn, 20+len(segmento), identification, flags+frag_offset, ttl, proto, addr_sum) + src_addr + dst_addr
        datagrama = datagrama + segmento
        
        self.enlace.enviar(datagrama, next_hop)
