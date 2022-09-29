from iputils import *

class IP:
    def __init__(self, enlace):
        self.tabela_encaminhamento = []
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr != self.meu_endereco:
            next_hop = self._next_hop(dst_addr)
            dscp, ecn, identification, flags, frag_offset, ttl, proto, src_addr, \
                dst_addr, payload = read_ipv4_header(datagrama)
        
            if ttl != 1:
                ttl = ttl - 1
            else:
                self._icmp_time_limit_exceeded(datagrama, src_addr)
                return 

            datagr = struct.pack('!BBHHHBBH', 0x45, dscp|ecn, 20+len(payload), identification, \
             (flags<<13)|frag_offset, ttl, proto, 0) + str2addr(src_addr) + str2addr(dst_addr)
            
            soma = calc_checksum(datagr)

            datagr = struct.pack('!BBHHHBBH', 0x45, dscp|ecn, 20+len(payload), identification, \
             (flags<<13)|frag_offset, ttl, proto, soma) + str2addr(src_addr) + str2addr(dst_addr)

            datagrama = datagr + payload

            self.enlace.enviar(datagrama, next_hop)
            
        else:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)

    def _next_hop(self, dest_addr):
        prev_matched = {'bits': -1, 'next_hop': None}

        for cidr, next_hop in self.tabela_encaminhamento:
            no_matched_bits = self._addr_match(cidr, dest_addr)
            if no_matched_bits > prev_matched['bits']:
                prev_matched['bits'] = no_matched_bits
                prev_matched['next_hop'] = next_hop

        return prev_matched['next_hop']

    def _addr_match(self, cidr, addr):
        cidr_base, no_matching_bits = cidr.split("/", 1)

        no_matching_bits = int(no_matching_bits)
        
        vetor = list(int(x) for x in cidr_base.split('.'))
        frase = ""

        for posicao in vetor:
                frase += '{0:08b}'.format(posicao)

        cidr_base = frase
        
        vetor = list(int(x) for x in addr.split('.'))
        frase = ""

        for posicao in vetor:
                frase += '{0:08b}'.format(posicao)
        
        addr = frase

        if (cidr_base[:no_matching_bits] != addr[:no_matching_bits]):
            return -1
        else:
            return no_matching_bits

    def _icmp_time_limit_exceeded(self, datagrama, dst_addr):
        payload = struct.pack('!BBHI', 11, 0, 0, 0) + datagrama[:28]
        soma = calc_checksum(payload)
        payload = struct.pack('!BBHI', 11, 0, soma, 0) + datagrama[:28]

        self.enviar(payload, dst_addr, IPPROTO_ICMP)

    def definir_endereco_host(self, meu_endereco):
        self.meu_endereco = meu_endereco
    
    def registrar_recebedor(self, callback):
        self.callback = callback

    def definir_tabela_encaminhamento(self, tabela):
        self.tabela_encaminhamento = tabela

    def enviar(self, segmento, dest_addr, proto=IPPROTO_TCP):
        ttl = 64
        next_hop = self._next_hop(dest_addr)
        flag = 0<<13
        frag_off = 0
        temp = 4<<4
        ihl = 5
        dscp = 0
        ecn = 0
        identification = 0
        
        datagr = struct.pack('!BBHHHBBH', temp + ihl, dscp + ecn, 20+len(segmento), identification, \
             flag + frag_off, ttl, proto, 0) + str2addr(self.meu_endereco) + str2addr(dest_addr)

        soma = calc_checksum(datagr)
        datagr = struct.pack('!BBHHHBBH', temp + ihl, dscp + ecn, 20+len(segmento), identification, \
             flag + frag_off, ttl, proto, soma) + str2addr(self.meu_endereco) + str2addr(dest_addr)
        
        datagrama = datagr + segmento
        self.enlace.enviar(datagrama, next_hop)