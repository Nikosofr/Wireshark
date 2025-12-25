"""
Парсер Ethernet фреймов
"""
import socket
import dpkt

def get_mac_address(mac_bytes):
    """Конвертировать MAC адрес в строку"""
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def get_ip_address(ip_bytes):
    """Конвертировать IP адрес в строку"""
    return socket.inet_ntoa(ip_bytes)

def parse_ethernet(packet_data):
    """Парсить Ethernet фрейм"""
    try:
        eth = dpkt.ethernet.Ethernet(packet_data)
        
        # Получаем MAC адреса
        src_mac = get_mac_address(eth.src)
        dst_mac = get_mac_address(eth.dst)
        
        # Инициализируем значения по умолчанию
        protocol = "OTHER"
        info = ""
        source = src_mac
        destination = dst_mac
        
        # ARP
        if isinstance(eth.data, dpkt.arp.ARP):
            protocol = "ARP"
            arp = eth.data
            source = get_ip_address(arp.spa) if arp.spa else src_mac
            destination = get_ip_address(arp.tpa) if arp.tpa else dst_mac
            info = f"ARP {source} -> {destination}"
        
        # IP пакет
        elif isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            src_ip = get_ip_address(ip.src)
            dst_ip = get_ip_address(ip.dst)
            source = src_ip
            destination = dst_ip
            
            # TCP
            if isinstance(ip.data, dpkt.tcp.TCP):
                protocol = "TCP"
                tcp = ip.data
                info = f"{src_ip}:{tcp.sport} -> {dst_ip}:{tcp.dport}"
                
                # Проверяем HTTP
                if tcp.dport == 80 or tcp.sport == 80:
                    try:
                        if len(tcp.data) > 0:
                            # Простая проверка на HTTP
                            if b'HTTP' in tcp.data[:20] or b'GET' in tcp.data[:20] or b'POST' in tcp.data[:20]:
                                protocol = "HTTP"
                                info = f"HTTP {src_ip}:{tcp.sport} -> {dst_ip}:{tcp.dport}"
                    except:
                        pass
            
            # UDP
            elif isinstance(ip.data, dpkt.udp.UDP):
                protocol = "UDP"
                udp = ip.data
                info = f"{src_ip}:{udp.sport} -> {dst_ip}:{udp.dport}"
                
                # Проверяем DNS
                if udp.sport == 53 or udp.dport == 53:
                    protocol = "DNS"
                    info = f"DNS {src_ip}:{udp.sport} -> {dst_ip}:{udp.dport}"
            
            # ICMP
            elif isinstance(ip.data, dpkt.icmp.ICMP):
                protocol = "ICMP"
                icmp = ip.data
                info = f"ICMP {src_ip} -> {dst_ip}"
        
        return {
            'source': source,
            'destination': destination,
            'protocol': protocol,
            'info': info
        }
        
    except Exception as e:
        return {
            'source': 'Unknown',
            'destination': 'Unknown',
            'protocol': 'OTHER',
            'info': f'Parse error: {str(e)[:50]}'
        }
