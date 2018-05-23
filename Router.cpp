//
// Created by root on 9/5/17.
//

#include <iostream>
#include <random>
//For hash
#include <functional>

#include "Router.hpp"

using namespace Tins;

void Router::readPacket(PDU &pdu, const SimpleRoute &route) {

    IP &ip = pdu.rfind_pdu<IP>();

    //Two options : If the ttl is 0, build the ICMP response.
    //Otherwise, Route the packet. If the destination is reachable, send the packet,
    //else send back a ICMP error

    ip.ttl(ip.ttl() - 1);
    if (ip.ttl() == 0) {
        //Last argument: Code ICMP 0 means TTL exceeded
        //See if we have reached the destination
        auto type = ICMP::Flags::TIME_EXCEEDED;
        auto code = 0;
        //Must check if we are on a route that contains the destination or an intermediate route
        auto ipDestination = route.getDstInfos().first;
        IPv4Address ipAddressResponse;

        if (ipDestination == ip.dst_addr()) {
            //We are on a route that contains the destination, so check if we have reached the destination
            auto routerInterfaceDestination = std::find(interfaces.begin(), interfaces.end(), ip.dst_addr());
            if (routerInterfaceDestination != interfaces.end()) {
                //We have reached the destination, so the ipaddress responding is the destination
                type = ICMP::Flags::DEST_UNREACHABLE;
                //Port unreachable
                code = 3;
                ipAddressResponse = ipDestination;
            } else {
                //We are on an intermediate router, so send the gateway address
                ipAddressResponse = route.getGatewayInfos().first;
            }
        } else {
            //This is an intermediate route, so take the ip destination of the route
            ipAddressResponse = ipDestination;
        }
        IP response = buildICMP(pdu, type, code, ipAddressResponse);
        sendICMP(response);
    } else {
        routePacket(pdu);
    }
}


void Router::sendICMP(Tins::IP &ip) {
    ip.ttl(64);
    packetSender.send(ip, "enp0s3");
}

RawPDU extract_icmp_payload(IP &pdu) {
    PDU::serialization_type buffer = pdu.serialize();
    // Use whole IP + 8 bytes of next header.
    size_t end_index = pdu.header_size() + 8;
    return RawPDU(buffer.begin(), buffer.begin() + end_index);
}

Tins::IP Router::buildICMP(Tins::PDU &pdu, ICMP::Flags type, int code, const Tins::IPv4Address &srcAddress) {
    // Find Ethernet and IP headers.
    IP &receivedIp = pdu.rfind_pdu<IP>();
    //Switch the dest and the src address of the IP packet, the srcAddress is found thanks to the provided parameter
    auto output = IP(receivedIp.src_addr(), srcAddress);
    // Now generate the ICMP layer using the type and code provided.
    ICMP icmp;
    icmp.code(code);
    icmp.type(type);
    receivedIp.ttl(1);
    icmp.inner_pdu(receivedIp);
    // Extract the payload to be used over ICMP. Does not work
    //output /= extract_icmp_payload(receivedIp);
    // Append the ICMP layer to our packet
    output /= icmp;
    return output;
}

void Router::routePacket(Tins::PDU &pdu) {
    //Decrements the TTL
    auto ip = pdu.rfind_pdu<IP>();


    std::vector<SimpleRoute> candidatesRoutes;
    //Check if the destination address is present in the routing table
    std::copy_if(routingTable.begin(), routingTable.end(), std::back_inserter(candidatesRoutes),
                 [&ip](const SimpleRoute &route) {
                     return route.getDstInfos().first == ip.dst_addr();
                 });

    //Load balancing logic to implement with randomness

    //Must give a value to the routes

    if (candidatesRoutes.empty()) {
        //Do something, send an error


    } else if (candidatesRoutes.size() == 1) {
        //If we reached the destination, the destination read the packet
        auto candidateRoute = candidatesRoutes.begin();
        if (candidateRoute->getGatewayInfos().first == IPv4Address()) {
            candidateRoute->getDstInfos().second->readPacket(pdu, *candidateRoute);
        }//Otherwise send it to the gateway
        else {
            //i.e there exist a route between current router and gateway
            auto routerGatewayRoute = std::find_if(
                    routingTable.begin(), routingTable.end(), [candidateRoute](const SimpleRoute &route) {
                        //Check if a route between the gateway and the router exists
                        return route.getDstInfos().second.get() == candidateRoute->getGatewayInfos().second.get();
                    });
            if (routerGatewayRoute != routingTable.end()) {
                candidateRoute->getGatewayInfos().second->readPacket(pdu, *candidateRoute);
            } else {
                std::cerr << "NO ROUTE AVALAILABLE \n";
                throw std::exception();
            }
        }
    } else {

        //Find the flowid
        //Build a string with the five tuple (src, dst, srcport, dstport)
        //Get the port with UDP protocol
        const UDP &udp = pdu.rfind_pdu<UDP>();
        std::stringstream ss;
        ss << ip.src_addr() << ip.dst_addr() << udp.sport() << udp.dport() << ip.protocol();
        size_t hash = std::hash<std::string>()(ss.str());
        //Check if we already got this hash in our map
        auto routeIt = flowsHashed.find(hash);
        if (routeIt != flowsHashed.end()) {
            candidatesRoutes[(*routeIt).second].getGatewayInfos().second->readPacket(pdu,
                                                                                     candidatesRoutes[(*routeIt).second]);
        }
            //If we dont have it, just generate a random choice for this flow
        else{
            std::uniform_int_distribution<> dis(0, candidatesRoutes.size() - 1);
            auto randomRouteIndex = dis(gen);
            //Put the flow in the hashtable.
            flowsHashed.insert(std::make_pair(hash,randomRouteIndex));
            candidatesRoutes[randomRouteIndex].getGatewayInfos().second->readPacket(pdu,
                                                                                    candidatesRoutes[randomRouteIndex]);
        }


    }

}

void Router::addInterface(const Tins::IPv4Address &interface) {
    interfaces.push_back(interface);
}

void Router::addRoute(const SimpleRoute &route) {
    routingTable.push_back(route);
}

const std::vector<SimpleRoute> &Router::getRoutingTable() const {
    return routingTable;
}

const std::vector<IPv4Address> &Router::getInterfaces() const {
    return interfaces;
}

int Router::getSeed() const {
    return seed;
}

void Router::setSeed(int seed) {
    Router::seed = seed;
}

Router::Router() : seed(rd()), gen(seed) {

}

std::unordered_map<size_t, int> &Router::getFlowsHashed() {
    return flowsHashed;
}
