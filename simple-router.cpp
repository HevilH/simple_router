/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router
{
  void
  SimpleRouter::handlePacket(const Buffer &packet, const std::string &inIface)
  {
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

    const Interface *iface = findIfaceByName(inIface);

    if (iface == nullptr)
    {
      std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
      return;
    }

    struct ethernet_hdr *packet_ethhdr = (struct ethernet_hdr *)packet.data();
    unsigned short ether_type = ntohs(packet_ethhdr->ether_type);

    if (ether_type == ethertype_arp)
    {
      std::cerr << "Received an ARP pkt from " << iface->name << "..." << std::endl;
      handleARPPacket(packet, iface);
    }
    else if (ether_type == ethertype_ip)
    {
      std::cerr << "Received an IP pkt from " << iface->name << "..." << std::endl;
      handleIPPacket(packet, iface);
    }
    else
    {
      std::cerr << "Unrecognized Packet!" << std::endl;
    }
  }

  void
  SimpleRouter::handleARPPacket(const Buffer &packet, const Interface *iface)
  {

    arp_hdr arpHdr;
    std::memcpy(&arpHdr, packet.data() + sizeof(ethernet_hdr), sizeof(arp_hdr));
    std::cerr << "Handle ARPpacket..." << std::endl;
    if (ntohs(arpHdr.arp_op) == arp_op_request)
    {
      std::cerr << "Handle ARP Request..." << std::endl;
      Buffer packet_buf(sizeof(ethernet_hdr) + sizeof(arp_hdr));

      struct ethernet_hdr *ethHdr = (struct ethernet_hdr *)packet_buf.data();
      memcpy(ethHdr->ether_dhost, arpHdr.arp_sha, ETHER_ADDR_LEN);
      memcpy(ethHdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
      ethHdr->ether_type = htons(ethertype_arp);

      struct arp_hdr *reply_arpHdr = (struct arp_hdr *)(packet_buf.data() + sizeof(struct ethernet_hdr));
      reply_arpHdr->arp_hrd = htons(arp_hrd_ethernet);
      reply_arpHdr->arp_pro = htons(ethertype_ip);
      reply_arpHdr->arp_hln = ETHER_ADDR_LEN;
      reply_arpHdr->arp_pln = 4;
      reply_arpHdr->arp_op = htons(arp_op_reply);
      memcpy(reply_arpHdr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
      memcpy(reply_arpHdr->arp_tha, arpHdr.arp_sha, ETHER_ADDR_LEN);
      reply_arpHdr->arp_sip = iface->ip;
      reply_arpHdr->arp_tip = arpHdr.arp_sip;

      sendPacket(packet_buf, iface->name);
    }
    else if (ntohs(arpHdr.arp_op) == arp_op_reply)
    {
      std::cerr << "Handle ARP Reply..." << std::endl;
      Buffer mac(ETHER_ADDR_LEN);
      std::memcpy(mac.data(), arpHdr.arp_sha, ETHER_ADDR_LEN);
      std::shared_ptr<ArpRequest> req = m_arp.insertArpEntry(mac, arpHdr.arp_sip);
      if (req != nullptr)
      {
        for (auto &pending_pkt : req->packets)
        {
          std::cerr << "send pending packet..." << std::endl;
          std::memcpy(pending_pkt.packet.data(), arpHdr.arp_sha, ETHER_ADDR_LEN);
          sendPacket(pending_pkt.packet, pending_pkt.iface);
        }
        m_arp.removeRequest(req);
      }
    }
    else
    {
      std::cerr << "Unrecognized ARP Type!" << std::endl;
    }
  }

  void
  SimpleRouter::handleIPPacket(const Buffer &packet, const Interface *iface)
  {
    ip_hdr ipHdr;
    //print_hdrs(packet);
    std::memcpy(&ipHdr, packet.data() + sizeof(ethernet_hdr), sizeof(ip_hdr));

    if (cksum(&ipHdr, sizeof(ip_hdr)) != 0xffff)
    {
      std::cerr << "Wrong checksum." << cksum(&ipHdr, sizeof(ip_hdr)) << std::endl;
      return;
    }

    if (packet.size() - sizeof(ethernet_hdr) < 20)
    {
      std::cerr << "Wrong length." << std::endl;
      return;
    }

    //to router
    if (findIfaceByIp(ipHdr.ip_dst))
    {
      std::cerr << "To the router..." << std::endl;
      if (ipHdr.ip_p == ip_protocol_icmp)
      {
        //Echo reply
        icmp_hdr *icmpHdr = (icmp_hdr *)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
        if (icmpHdr->icmp_type == 8)
        {
          uint16_t pk_sum = icmpHdr->icmp_sum;
          std::size_t data_len = packet.size() - sizeof(ip_hdr) - sizeof(ethernet_hdr);
          icmpHdr->icmp_sum = 0;
          icmpHdr->icmp_sum = cksum(icmpHdr, data_len);
          if (pk_sum == icmpHdr->icmp_sum)
          {
            std::cerr << "echo reply." << std::endl;
            Buffer new_packet(sizeof(ethernet_hdr) + sizeof(ip_hdr) + data_len);
            std::memcpy(new_packet.data(), packet.data(), sizeof(ethernet_hdr));
            std::memcpy(new_packet.data() + sizeof(ethernet_hdr), &ipHdr, sizeof(ip_hdr));

            icmp_hdr *new_icmpHdr = (icmp_hdr *)new uint8_t[data_len];
            std::memcpy(new_icmpHdr, icmpHdr, data_len);
            new_icmpHdr->icmp_type = 0;
            new_icmpHdr->icmp_code = 0;
            new_icmpHdr->icmp_sum = 0;
            new_icmpHdr->icmp_sum = cksum(new_icmpHdr, data_len);
            std::memcpy(new_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr), new_icmpHdr, data_len);

            ip_hdr *new_ipHdr = (ip_hdr *)(new_packet.data() + sizeof(ethernet_hdr));
            new_ipHdr->ip_sum = 0;
            new_ipHdr->ip_p = ip_protocol_icmp;
            new_ipHdr->ip_len = htons(data_len + sizeof(ip_hdr));
            new_ipHdr->ip_ttl = 64;
            new_ipHdr->ip_src = ipHdr.ip_dst;
            new_ipHdr->ip_dst = ipHdr.ip_src;
            new_ipHdr->ip_sum = cksum(new_ipHdr, sizeof(ip_hdr));

            RoutingTableEntry route = m_routingTable.lookup(new_ipHdr->ip_dst);
            const Interface *new_iface = findIfaceByName(route.ifName);

            if (new_iface == NULL)
            {
              std::cerr << "Cannot find outgoing interface." << std::endl;
              return;
            }
            ethernet_hdr ethHdr;
            std::memcpy(ethHdr.ether_shost, new_iface->addr.data(), ETHER_ADDR_LEN);
            ethHdr.ether_type = htons(ethertype_ip);
            
            std::cerr << "111" << std::endl;
            std::shared_ptr<ArpEntry> cacheEntry(m_arp.lookup(route.gw));
            std::cerr << "222" << std::endl;
            if (cacheEntry == NULL)
            {
              std::memcpy(new_packet.data(), &ethHdr, sizeof(ethernet_hdr));
              std::shared_ptr<ArpRequest> arpReq = m_arp.queueRequest(new_ipHdr->ip_dst, new_packet, new_iface->name);
              return;
            }

            std::memcpy(ethHdr.ether_dhost, cacheEntry->mac.data(), ETHER_ADDR_LEN);
            std::memcpy(new_packet.data(), &ethHdr, sizeof(ethernet_hdr));
            sendPacket(new_packet, new_iface->name);
            //print_hdrs(new_packet);
            std::cerr << "Forwarded IP pkt to " << new_iface->name << "..." << std::endl;
          }
        }
      }
      else
      {
        //Port Unreachable
        std::cerr << "Receive TCP/UDP Packet" << std::endl;
        Buffer new_packet(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
        std::memcpy(new_packet.data(), packet.data(), sizeof(ethernet_hdr));
        std::memcpy(new_packet.data() + sizeof(ethernet_hdr), &ipHdr, sizeof(ip_hdr));

        icmp_t3_hdr icmp_t3Hdr;
        std::memset(&icmp_t3Hdr, 0, sizeof(icmp_t3_hdr));
        icmp_t3Hdr.icmp_type = 3;
        icmp_t3Hdr.icmp_code = 3;
        std::size_t length = packet.size() - sizeof(ethernet_hdr);
        length = length < ICMP_DATA_SIZE ? length : ICMP_DATA_SIZE;
        std::memcpy(icmp_t3Hdr.data, packet.data() + sizeof(ethernet_hdr), length);
        icmp_t3Hdr.icmp_sum = cksum(&icmp_t3Hdr, sizeof(icmp_t3_hdr));
        std::memcpy(new_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr), &icmp_t3Hdr, sizeof(icmp_t3_hdr));

        ip_hdr *new_ipHdr = (ip_hdr *)(new_packet.data() + sizeof(ethernet_hdr));
        new_ipHdr->ip_sum = 0;
        new_ipHdr->ip_p = ip_protocol_icmp;
        new_ipHdr->ip_len = htons(sizeof(icmp_t3_hdr) + sizeof(ip_hdr));
        new_ipHdr->ip_ttl = 64;
        new_ipHdr->ip_dst = ipHdr.ip_src;
        new_ipHdr->ip_src = ipHdr.ip_dst;
        new_ipHdr->ip_sum = cksum(new_ipHdr, sizeof(ip_hdr));

        RoutingTableEntry route = m_routingTable.lookup(new_ipHdr->ip_dst);
        const Interface *new_iface = findIfaceByName(route.ifName);
        if (new_iface == nullptr)
        {
          std::cerr << "Cannot find outgoing interface." << std::endl;
          return;
        }

        ethernet_hdr ethHdr;
        std::memcpy(ethHdr.ether_shost, new_iface->addr.data(), ETHER_ADDR_LEN);
        ethHdr.ether_type = htons(ethertype_ip);

        uint32_t lookupAddress = route.mask &&
                                         ((route.dest & route.mask) == (new_iface->ip & route.mask))
                                     ? route.dest
                                     : route.gw;

        std::shared_ptr<ArpEntry> cacheEntry(m_arp.lookup(lookupAddress));
        if (cacheEntry == NULL)
        {
          std::memcpy(new_packet.data(), &ethHdr, sizeof(ethernet_hdr));
          std::shared_ptr<ArpRequest> arpReq = m_arp.queueRequest(new_ipHdr->ip_dst, new_packet, new_iface->name);

          Buffer packet_buf(sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr));
          struct arp_hdr *arp = (struct arp_hdr *)(packet_buf.data() + sizeof(struct ethernet_hdr));
          arp->arp_hrd = htons(arp_hrd_ethernet);
          arp->arp_pro = htons(ethertype_ip);
          arp->arp_hln = ETHER_ADDR_LEN;
          arp->arp_pln = 4;
          arp->arp_op = htons(arp_op_request);
          arp->arp_tip = new_ipHdr->ip_dst;
          arp->arp_sip = new_iface->ip;
          memcpy(arp->arp_sha, (new_iface->addr).data(), ETHER_ADDR_LEN); //sender mac address
          memset(arp->arp_tha, 255, ETHER_ADDR_LEN);
          struct ethernet_hdr *ethHdr = (struct ethernet_hdr *)(packet_buf.data());
          memset(ethHdr->ether_dhost, 255, ETHER_ADDR_LEN);                      //ethernet header destination address
          memcpy(ethHdr->ether_shost, (new_iface->addr).data(), ETHER_ADDR_LEN); //ethernet header source address
          ethHdr->ether_type = htons(ethertype_arp);
          sendPacket(packet_buf, new_iface->name);
          return;
        }

        std::memcpy(ethHdr.ether_dhost, cacheEntry->mac.data(), ETHER_ADDR_LEN);
        std::memcpy(new_packet.data(), &ethHdr, sizeof(ethernet_hdr));
        sendPacket(new_packet, new_iface->name);
        //print_hdrs(new_packet);
        std::cerr << "Forwarded IP pkt to " << new_iface->name << "..." << std::endl;
      }
    }
    //to other host
    else
    {
      //Time Exceeded
      if (ipHdr.ip_ttl - 1 <= 0)
      {
        std::cerr << "Start Time Exceed"<< std::endl;
        Buffer new_packet(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
        std::memcpy(new_packet.data(), packet.data(), sizeof(ethernet_hdr));
        std::memcpy(new_packet.data() + sizeof(ethernet_hdr), &ipHdr, sizeof(ip_hdr));

        icmp_t3_hdr icmp_t3Hdr;
        std::memset(&icmp_t3Hdr, 0, sizeof(icmp_t3_hdr));
        icmp_t3Hdr.icmp_type = 11;
        icmp_t3Hdr.icmp_code = 0;
        std::size_t length = packet.size() - sizeof(ethernet_hdr);
        length = length < ICMP_DATA_SIZE ? length : ICMP_DATA_SIZE;
        std::memcpy(icmp_t3Hdr.data, packet.data() + sizeof(ethernet_hdr), length);
        icmp_t3Hdr.icmp_sum = cksum(&icmp_t3Hdr, sizeof(icmp_t3_hdr));
        std::memcpy(new_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr), &icmp_t3Hdr, sizeof(icmp_t3_hdr));

        ip_hdr *new_ipHdr = (ip_hdr *)(new_packet.data() + sizeof(ethernet_hdr));
        new_ipHdr->ip_sum = 0;
        new_ipHdr->ip_p = ip_protocol_icmp;
        new_ipHdr->ip_len = htons(sizeof(icmp_t3_hdr) + sizeof(ip_hdr));
        new_ipHdr->ip_dst = ipHdr.ip_src;
        new_ipHdr->ip_src = iface->ip;
        new_ipHdr->ip_ttl = 64;
        new_ipHdr->ip_sum = 0;
        new_ipHdr->ip_sum = cksum(new_ipHdr, sizeof(ip_hdr));

        RoutingTableEntry route = m_routingTable.lookup(new_ipHdr->ip_dst);
        const Interface *new_iface = findIfaceByName(route.ifName);
        if (new_iface == nullptr)
        {
          std::cerr << "Cannot find outgoing interface." << std::endl;
          return;
        }

        ethernet_hdr ethHdr;
        std::memcpy(ethHdr.ether_shost, new_iface->addr.data(), ETHER_ADDR_LEN);
        ethHdr.ether_type = htons(ethertype_ip);

        uint32_t lookupAddress = route.mask &&
                                         ((route.dest & route.mask) == (new_iface->ip & route.mask))
                                     ? route.dest
                                     : route.gw;

        std::shared_ptr<ArpEntry> cacheEntry(m_arp.lookup(lookupAddress));
        if (cacheEntry == NULL)
        {
          std::memcpy(new_packet.data(), &ethHdr, sizeof(ethernet_hdr));
          std::shared_ptr<ArpRequest> arpReq = m_arp.queueRequest(new_ipHdr->ip_dst, new_packet, new_iface->name);

          Buffer packet_buf(sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr));
          struct arp_hdr *arp = (struct arp_hdr *)(packet_buf.data() + sizeof(struct ethernet_hdr));
          arp->arp_hrd = htons(arp_hrd_ethernet);
          arp->arp_pro = htons(ethertype_ip);
          arp->arp_hln = ETHER_ADDR_LEN;
          arp->arp_pln = 4;
          arp->arp_op = htons(arp_op_request);
          arp->arp_tip = new_ipHdr->ip_dst;
          arp->arp_sip = new_iface->ip;
          memcpy(arp->arp_sha, (new_iface->addr).data(), ETHER_ADDR_LEN); //sender mac address
          memset(arp->arp_tha, 255, ETHER_ADDR_LEN);
          struct ethernet_hdr *ethHdr = (struct ethernet_hdr *)(packet_buf.data());
          memset(ethHdr->ether_dhost, 255, ETHER_ADDR_LEN);                      //ethernet header destination address
          memcpy(ethHdr->ether_shost, (new_iface->addr).data(), ETHER_ADDR_LEN); //ethernet header source address
          ethHdr->ether_type = htons(ethertype_arp);
          sendPacket(packet_buf, new_iface->name);
          return;
        }

        std::memcpy(ethHdr.ether_dhost, cacheEntry->mac.data(), ETHER_ADDR_LEN);
        std::memcpy(new_packet.data(), &ethHdr, sizeof(ethernet_hdr));
        sendPacket(new_packet, new_iface->name);
        std::cerr << "Forwarded IP pkt to " << new_iface->name << "..." << std::endl;
      }
      //Forwarding
      else
      {
        RoutingTableEntry route = m_routingTable.lookup(ipHdr.ip_dst);
        const Interface *new_iface = findIfaceByName(route.ifName);
        std::shared_ptr<ArpEntry> cacheEntry(m_arp.lookup(route.gw));
        
        std::cerr << "Start Forwarding" <<std::endl;
        ipHdr.ip_ttl -= 1;
        ipHdr.ip_sum = 0;
        ipHdr.ip_sum = cksum(&ipHdr, sizeof(ip_hdr));
        Buffer new_packet(packet.size());
        std::memcpy(new_packet.data(), packet.data(), packet.size());
        std::memcpy(new_packet.data() + sizeof(ethernet_hdr), &ipHdr, sizeof(ip_hdr));
        ip_hdr *new_ipHdr = (ip_hdr *)(new_packet.data() + sizeof(ethernet_hdr));
    
        if (new_iface == NULL)
        {
          std::cerr << "Cannot find outgoing interface." << std::endl;
          return;
        }

        ethernet_hdr ethHdr;
        std::memcpy(ethHdr.ether_shost, new_iface->addr.data(), ETHER_ADDR_LEN);
        ethHdr.ether_type = htons(ethertype_ip);
        if (cacheEntry == NULL)
        {
          std::memcpy(new_packet.data(), &ethHdr, sizeof(ethernet_hdr));
          std::shared_ptr<ArpRequest> arpReq = m_arp.queueRequest(new_ipHdr->ip_dst, new_packet, new_iface->name);
          return;
        }
        std::memcpy(ethHdr.ether_dhost, cacheEntry->mac.data(), ETHER_ADDR_LEN);
        std::memcpy(new_packet.data(), &ethHdr, sizeof(ethernet_hdr));
        sendPacket(new_packet, new_iface->name);
        //print_hdrs(new_packet);
        std::cerr << "Forwarded IP pkt to " << new_iface->name << "..." << std::endl;
      }
    }
  }
  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////

  // You should not need to touch the rest of this code.
  SimpleRouter::SimpleRouter()
      : m_arp(*this)
  {
  }

  void
  SimpleRouter::sendPacket(const Buffer &packet, const std::string &outIface)
  {
    m_pox->begin_sendPacket(packet, outIface);
  }

  bool
  SimpleRouter::loadRoutingTable(const std::string &rtConfig)
  {
    return m_routingTable.load(rtConfig);
  }

  void
  SimpleRouter::loadIfconfig(const std::string &ifconfig)
  {
    std::ifstream iff(ifconfig.c_str());
    std::string line;
    while (std::getline(iff, line))
    {
      std::istringstream ifLine(line);
      std::string iface, ip;
      ifLine >> iface >> ip;

      in_addr ip_addr;
      if (inet_aton(ip.c_str(), &ip_addr) == 0)
      {
        throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
      }

      m_ifNameToIpMap[iface] = ip_addr.s_addr;
    }
  }

  void
  SimpleRouter::printIfaces(std::ostream &os)
  {
    if (m_ifaces.empty())
    {
      os << " Interface list empty " << std::endl;
      return;
    }

    for (const auto &iface : m_ifaces)
    {
      os << iface << "\n";
    }
    os.flush();
  }

  const Interface *
  SimpleRouter::findIfaceByIp(uint32_t ip) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip](const Interface &iface) {
      return iface.ip == ip;
    });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByMac(const Buffer &mac) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac](const Interface &iface) {
      return iface.addr == mac;
    });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByName(const std::string &name) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name](const Interface &iface) {
      return iface.name == name;
    });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  void
  SimpleRouter::reset(const pox::Ifaces &ports)
  {
    std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

    m_arp.clear();
    m_ifaces.clear();

    for (const auto &iface : ports)
    {
      auto ip = m_ifNameToIpMap.find(iface.name);
      if (ip == m_ifNameToIpMap.end())
      {
        std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
        continue;
      }

      m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
    }

    printIfaces(std::cerr);
  }

} // namespace simple_router
