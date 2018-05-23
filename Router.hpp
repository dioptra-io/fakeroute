//
// Created by root on 9/5/17.
//

#ifndef FAKEROUTEC_ROUTER_HPP
#define FAKEROUTEC_ROUTER_HPP
#include <tins/tins.h>
#include <vector>
#include <random>
#include <unordered_map>

// include headers that implement a archive in simple text format
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "SimpleRoute.hpp"

class Router{

public:

    //First member of the pair representing the destination, and the second one the gateway

    //Constructor and configuration
    Router();

    void addInterface(const Tins::IPv4Address &interface);

    const std::vector<SimpleRoute> &getRoutingTable() const;

    //Routing part of the class
    void readPacket(Tins::PDU &pdu, const SimpleRoute &route);

    void addRoute(const SimpleRoute &route);

    void routePacket(Tins::PDU & );

    int getSeed() const;

    void setSeed(int seed);

    std::unordered_map<size_t, int> &getFlowsHashed();


    const std::vector<Tins::IPv4Address> &getInterfaces() const;

    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & interfaces & routingTable & packetSender & flowsHashed & seed;
    }

private:

    Tins::IP buildICMP(Tins::PDU &pdu, Tins::ICMP::Flags type, int code, const Tins::IPv4Address &srcAddress);
    void sendICMP(Tins::IP &icmp);
    std::vector<Tins::IPv4Address> interfaces;
    std::vector<SimpleRoute> routingTable;

    Tins::PacketSender packetSender;

    //Key represents the hashed flow, value represents the associated route.
    std::unordered_map<size_t , int> flowsHashed;

    //Will be used to obtain a seed for the random number engine (himself based on a mersenne from the source code)
    std::random_device rd;
    int seed;
    //Standard mersenne_twister_engine seeded with rd()
    std::mt19937 gen;
};


#endif //FAKEROUTEC_ROUTER_HPP
