from __future__ import absolute_import, division, print_function
from scapy.all import *


def custom_action(packet):
    counter = custom_action.counter
    counter += 1
    output = 'Packet #{}: {} ==> {}'.format(counter, packet[0][1].src, packet[0][1].dst) #Hangi kaynaktan hangi hedefe paket gönderdiğini gösterir.
    with open("custom_action.txt", "a") as file:
        file.write(output + "\n")
    if IP in packet:
        ip_adresi = packet[IP].src #kaynaktan gelen paketlerin hangi IP den geldiğini gösterir. (dst yaparsan tam tersi)
        print("IP Adresi: ", ip_adresi) #konsola bastırır
        with open("ip_adresleri.txt", "a") as file: #Text dosyası oluşturur.
            file.write(ip_adresi + "\n") #Oluşturduğu Text dosyasının içine yazar.
    if Ether in packet:
        mac_adresi = packet[Ether].src #kaynaktan gelen paketlerin hangi MAC den geldiğini gösterir. (dst yaparsan tam tersi)
        print("MAC Adresi: ", mac_adresi) 
        with open("mac_adresleri.txt", "a") as file:
            file.write(mac_adresi + "\n")
    custom_action.counter = counter
    return output


def arp_display(pkt):
    if pkt[ARP].op == 1:  # İstek (request)
        output = 'Request: {} -> {}'.format(pkt[ARP].psrc, pkt[ARP].pdst)
    elif pkt[ARP].op == 2:  # Cevap (response)
        output = '*Response: {} -> {} bu adrestir'.format(pkt[ARP].hwsrc, pkt[ARP].psrc)
    else:
        output = '' #request ve response eşleşir ise çıktıyı verir.

    with open("arp_display.txt", "a") as file:
        file.write(output + "\n")

    return output


def main():
    custom_action.counter = 0
    sniff(filter="ip", prn=custom_action, count=50) #Count'ı kaç yaparsan o kadar paketi okur. 0 yaparsan IP = MAC eşleştirmesini yapmaz.
    sniff(prn=arp_display, filter="arp", store=0, count=10)


if __name__ == "__main__":
    main()