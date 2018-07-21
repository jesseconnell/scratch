#pragma once

#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2bth.h>
#include <netiodef.h>

#include <chrono>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>


#ifdef WIN32
constexpr int32_t ETH_P_8021Q = ETHERNET_TYPE_802_1Q;
constexpr int32_t ETH_P_IP = ETHERNET_TYPE_IPV4;
constexpr int32_t ETH_P_IPV6 = ETHERNET_TYPE_IPV6;
constexpr int32_t IP_MF = 0x2000;
#else
#endif

struct ethHeader
{

    uint8_t h_dest[6];      // destination eth addr
    uint8_t h_source[6];    // source ether addr
    uint16_t h_proto;        // packet type ID field
};

struct ERFHeader
{
    uint32_t TimeFrac; // fractional time (~233 picoseconds)
    uint32_t TimeWhole; // seconds
    uint8_t RecType;
    uint8_t Flags;
    uint16_t TotalLength;
    uint16_t LossCounter;  //# packets lost since prev.
    uint16_t WireLength;    // TotalLength - Wire bytesLength of data; this header is TotalLength - WireLength bytes
    // For ETH, this followed by 16bit "ethernet pad"

    size_t skipSize() const
    {
        return sizeof(ERFHeader) + 2 + (RecType & 128) ? 8 : 0;
    }
};

struct udp_hdr
{
    uint16_t source_port;     // Source port no.
    uint16_t dest_port;       // Dest. port no.
    uint16_t udp_length;      // Udp packet length
    uint16_t udp_checksum;    // Udp checksum (optional)
};

struct Packet
{
    std::chrono::nanoseconds Timestamp;
    tcp_hdr*                 Tcp;        //TCP header structure, or nullptr
    udp_hdr*                 Udp;        //UDP header structure, or nullptr
    const void*              Data;       //Payload
    size_t                   Length;     //Length of the payload
    uint64_t                 SourceAddr;
    uint64_t                 DestAddr;
};

class ErfReader
{
public:
    ErfReader(std::string fname, bool includeUdp = false);

    ~ErfReader() = default;

    void processFile(std::function<void(const Packet&)> onPacket);

private:
    static std::chrono::nanoseconds getNanos(const ERFHeader& erf);
    bool processEthernet(Packet& packet, void* p);
    bool processIPv4(Packet& packet, void* p);
    bool processIPv6(Packet& packet, void* p);
    bool processTCP(Packet& packet, void* p, uint16_t sz);
    bool processUDP(Packet& packet, void* p, uint16_t sz);

    bool            includeUdp_;
    std::ifstream   inFile_;
};
