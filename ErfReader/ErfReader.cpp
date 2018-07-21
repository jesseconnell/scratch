#include "ErfReader.h"

#pragma comment(lib, "Ws2_32.lib")

namespace
{
    template<typename OutPtrT = void*>
    inline OutPtrT shiftPointer(void* inPtr, size_t bytes)
    {
        return reinterpret_cast<OutPtrT>(reinterpret_cast<char*>(inPtr) + bytes);
    }
}


ErfReader::ErfReader(std::string fname, bool includeUdp)
    : includeUdp_(includeUdp)
{
    inFile_.open(fname.c_str(), std::ios_base::binary);
    if (!inFile_)
    {
        std::cerr << "errno = " << errno << std::endl;
        throw std::exception("Failed to open");
    }
}

void ErfReader::processFile(std::function<void(const Packet&)> onPacket)
{
    ERFHeader erfHeader;
    Packet    packet;
    size_t    numPackets = 0;
    size_t    packetLength;
    char      buffer[10000];

    do
    {
        inFile_.read((char*)&erfHeader, sizeof(erfHeader));

        if (!inFile_)
        {
            if (inFile_.bad())
            {
                std::cout << "ERF file appears truncated; couldn't read header following packet #" << numPackets << std::endl;
            }

            break; //- This, when !bad(), is the normal exit; i.e. eof
        }

        erfHeader.TotalLength = ntohs(erfHeader.TotalLength);
        erfHeader.WireLength = ntohs(erfHeader.WireLength);
        packetLength = erfHeader.TotalLength - sizeof(erfHeader);
        ++numPackets;

        inFile_.read(buffer, packetLength);
        char* p = buffer;

        //- Only process full reads of Ethernet packets
        if (inFile_ && (erfHeader.RecType & 0x7f) == 2)
        {
            packet.Timestamp = getNanos(erfHeader); //- You don't -have- to do this here, but it's clearer
            packet.Tcp = nullptr;
            packet.Data = nullptr;
            packet.Length = 0;

            if (erfHeader.RecType & 0x80) {
                while (static_cast<char*>(p)[0] & 0x80) {
                    p = shiftPointer<char*>(p, 8);
                }
                p = shiftPointer<char*>(p, 8);
            }
            p = shiftPointer<char*>(p, 2);

            if (processEthernet(packet, p))
            {
                onPacket(packet);
            }
        }
    } while (!inFile_.eof());
}

std::chrono::nanoseconds ErfReader::getNanos(const ERFHeader & erf)
{
    int64_t retval = static_cast<int64_t>(erf.TimeWhole) * 1000000000ll;
    double  temp;

    temp = (static_cast<double>(erf.TimeFrac) / 4294967296.0);
    temp *= 1000000000.0;

    return std::chrono::nanoseconds{ retval + static_cast<int64_t>(std::round(temp)) };
}

bool ErfReader::processEthernet(Packet & packet, void * p)
{
    ethHeader* eth = reinterpret_cast<ethHeader*>(p);

    eth->h_proto = htons(eth->h_proto);

    //- For VLAN, we advance p an appropriate amount and store the proto tag in eth
    if (eth->h_proto == ETH_P_8021Q)
    {
        uint16_t hproto = *shiftPointer<uint16_t*>(eth, sizeof(ethHeader) + 2);
        eth->h_proto = htons(hproto);
        p = shiftPointer<void*>(p, 4);
    }

    if (eth->h_proto == ETH_P_IP)
    {
        return processIPv4(packet, shiftPointer(p, sizeof(ethHeader)));
    }

    if (eth->h_proto == ETH_P_IPV6)
    {
        return processIPv6(packet, shiftPointer(p, sizeof(ethHeader)));
    }

    return false;
}

bool ErfReader::processIPv4(Packet & packet, void * p)
{
    ip4_hdr    * ip = reinterpret_cast<ip4_hdr*>(p);
    uint16_t hdrlen = 4 * ip->HeaderLength;

    if (ip->Protocol == IPPROTO_TCP || ip->Protocol == IPPROTO_UDP)
    {
        ip->FlagsAndOffset = ntohs(ip->FlagsAndOffset);

        if (ip->FlagsAndOffset & IP_MF)
        {
            throw std::exception("IPv4 fragmentation needs to be handled");
        }

        packet.SourceAddr = ntohl(ip->SourceAddress.S_un.S_addr);
        packet.DestAddr = ntohl(ip->DestinationAddress.S_un.S_addr);

        if (includeUdp_ && ip->Protocol == IPPROTO_UDP)
            return processUDP(packet, shiftPointer(p, hdrlen), ntohs(ip->TotalLength) - hdrlen);

        return processTCP(packet, shiftPointer(p, hdrlen), ntohs(ip->TotalLength) - hdrlen);
    }

    return false;
}

bool ErfReader::processIPv6(Packet & packet, void * p)
{
    ip6_hdr* ip = reinterpret_cast<ip6_hdr*>(p);

    if (ip->ip6_nxt == IPPROTO_TCP)
    {
        // TODO - fix up the types for src/dest, do stuff here.
        packet.SourceAddr;
        packet.DestAddr;
        throw std::exception("Don't know how to process ipv6 packet");

        //return processTCP(packet, shiftPointer(p, sizeof(ip6_hdr)), ntohs(ip->ip6_plen));
    }

    //- Throw an exception if we see one of the IPv6 options heading between our endpoints
    if (ip->ip6_nxt == IPPROTO_HOPOPTS || ip->ip6_nxt == IPPROTO_ROUTING || ip->ip6_nxt == IPPROTO_FRAGMENT)
    {
        throw std::exception("Ipv6 optional headers need to be handled");
    }

    return false;
}

bool ErfReader::processTCP(Packet & packet, void * p, uint16_t sz)
{
    tcp_hdr * tcp = reinterpret_cast<tcp_hdr*>(p);
    size_t len = tcp->th_win * 4;


    packet.Tcp = tcp;
    packet.Data = shiftPointer(tcp, len);
    packet.Length = sz - len;

    return true;
}

bool ErfReader::processUDP(Packet & packet, void * p, uint16_t sz)
{
    udp_hdr* udp = reinterpret_cast<udp_hdr*>(p);
    packet.Udp = udp;
    packet.Data = shiftPointer(udp, sizeof(udp_hdr));
    packet.Length = ntohs(udp->udp_length) - sizeof(udp_hdr);

    return true;
}
