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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router
{
  void
  ArpCache::periodicCheckArpRequestsAndCacheEntries()
  {
    for (const auto &arpRequest : m_arpRequests)
    {
      if ((steady_clock::now() - seconds(1)) > arpRequest->timeSent)
      {
        if (arpRequest->nTimesSent >= MAX_SENT_TIME)
        {
          //extra credit
          int k = 1;
          for (const auto &pending_pkt : arpRequest->packets)
          {
            std::lock_guard<std::mutex> lock(m_mutex);
            printf("start unreachable");
            Buffer packet = pending_pkt.packet;
            ip_hdr ipHdr;
            std::memcpy(&ipHdr, packet.data() + sizeof(ethernet_hdr), sizeof(ip_hdr));
            
            RoutingTableEntry route = m_router.getRoutingTable().lookup(ipHdr.ip_src);
            const Interface *new_iface = m_router.findIfaceByName(route.ifName);

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


            new_ipHdr->ip_src = new_iface->ip;
            new_ipHdr->ip_sum = cksum(new_ipHdr, sizeof(ip_hdr));

            ethernet_hdr ethHdr;
            std::memcpy(ethHdr.ether_shost, new_iface->addr.data(), ETHER_ADDR_LEN);
            ethHdr.ether_type = htons(ethertype_ip);

            if (k == 1)
            {
              std::memcpy(new_packet.data(), &ethHdr, sizeof(ethernet_hdr));
              std::shared_ptr<ArpRequest> arpReq = queueRequest(new_ipHdr->ip_dst, new_packet, new_iface->name);
              print_hdrs(new_packet);
              k++;
            }
            else
            {
              std::memcpy(new_packet.data(), &ethHdr, sizeof(ethernet_hdr));
              m_router.sendPacket(new_packet, new_iface->name);
              print_hdrs(new_packet);
              std::cerr << "Packet Unreachable " << new_iface->name << "..." << std::endl;
              break;
            }
          }
          removeRequest(arpRequest);
        }
        else
        {
          //check arprequest
          printf("start arprequest");
          Buffer packet_buf(sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr));

          std::string interface_name = m_router.getRoutingTable().lookup(arpRequest->ip).ifName;
          const Interface *interface = m_router.findIfaceByName(interface_name);

          struct ethernet_hdr *ethHdr = (struct ethernet_hdr *)(packet_buf.data());
          memset(ethHdr->ether_dhost, 255, ETHER_ADDR_LEN);
          memcpy(ethHdr->ether_shost, interface->addr.data(), ETHER_ADDR_LEN);
          ethHdr->ether_type = htons(ethertype_arp);

          struct arp_hdr *arpHdr = (struct arp_hdr *)(packet_buf.data() + sizeof(struct ethernet_hdr));
          arpHdr->arp_hrd = htons(arp_hrd_ethernet);
          arpHdr->arp_pro = htons(ethertype_ip);
          arpHdr->arp_hln = ETHER_ADDR_LEN;
          arpHdr->arp_pln = 4;
          arpHdr->arp_op = htons(arp_op_request);
          arpHdr->arp_sip = interface->ip;
          memcpy(arpHdr->arp_sha, interface->addr.data(), ETHER_ADDR_LEN);
          memset(arpHdr->arp_tha, 255, ETHER_ADDR_LEN);
          arpHdr->arp_tip = arpRequest->ip;

          m_router.sendPacket(packet_buf, interface->name);

          arpRequest->nTimesSent++;
          arpRequest->timeSent = steady_clock::now();
        }
      }
    }
    //delete unvalid arpcache
    std::vector<std::shared_ptr<ArpEntry>> inval_entry;

    for (auto &cacheEntry : m_cacheEntries)
    {
      if (!cacheEntry->isValid)
        inval_entry.push_back(cacheEntry);
    }
    for (const auto &entry : inval_entry)
    {
      m_cacheEntries.remove(entry);
    }
  }

  // You should not need to touch the rest of this code.

  ArpCache::ArpCache(SimpleRouter &router)
      : m_router(router),
        m_shouldStop(false),
        m_tickerThread(std::bind(&ArpCache::ticker, this))
  {
  }

  ArpCache::~ArpCache()
  {
    m_shouldStop = true;
    m_tickerThread.join();
  }

  std::shared_ptr<ArpEntry>
  ArpCache::lookup(uint32_t ip)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto &entry : m_cacheEntries)
    {
      printf("1");
      if (entry->isValid && entry->ip == ip)
      {
        printf("2");
        return entry;
      }
    }
    printf("3");
    return nullptr;
  }

  std::shared_ptr<ArpRequest>
  ArpCache::queueRequest(uint32_t ip, const Buffer &packet, const std::string &iface)
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                [ip](const std::shared_ptr<ArpRequest> &request) {
                                  return (request->ip == ip);
                                });

    if (request == m_arpRequests.end())
    {
      request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
    }

    // Add the packet to the list of packets for this request
    (*request)->packets.push_back({packet, iface});
    return *request;
  }

  void ArpCache::removeRequest(const std::shared_ptr<ArpRequest> &entry)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_arpRequests.remove(entry);
  }

  std::shared_ptr<ArpRequest>
  ArpCache::insertArpEntry(const Buffer &mac, uint32_t ip)
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto entry = std::make_shared<ArpEntry>();
    entry->mac = mac;
    entry->ip = ip;
    entry->timeAdded = steady_clock::now();
    entry->isValid = true;
    m_cacheEntries.push_back(entry);

    auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                [ip](const std::shared_ptr<ArpRequest> &request) {
                                  return (request->ip == ip);
                                });
    if (request != m_arpRequests.end())
    {
      return *request;
    }
    else
    {
      return nullptr;
    }
  }

  void ArpCache::clear()
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_cacheEntries.clear();
    m_arpRequests.clear();
  }

  void ArpCache::ticker()
  {
    while (!m_shouldStop)
    {
      std::this_thread::sleep_for(std::chrono::seconds(1));

      {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto now = steady_clock::now();

        for (auto &entry : m_cacheEntries)
        {
          if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO))
          {
            entry->isValid = false;
          }
        }

        periodicCheckArpRequestsAndCacheEntries();
      }
    }
  }

  std::ostream &
  operator<<(std::ostream &os, const ArpCache &cache)
  {
    std::lock_guard<std::mutex> lock(cache.m_mutex);

    os << "\nMAC            IP         AGE                       VALID\n"
       << "-----------------------------------------------------------\n";

    auto now = steady_clock::now();
    for (const auto &entry : cache.m_cacheEntries)
    {

      os << macToString(entry->mac) << "   "
         << ipToString(entry->ip) << "   "
         << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
         << entry->isValid
         << "\n";
    }
    os << std::endl;
    return os;
  }

} // namespace simple_router
