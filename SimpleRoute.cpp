//
// Created by root on 9/7/17.
//

#include "SimpleRoute.hpp"


SimpleRoute::SimpleRoute(const std::pair<Tins::IPv4Address, std::shared_ptr<Router>> &srcInfos,
                         const std::pair<Tins::IPv4Address, std::shared_ptr<Router>> &gatewayInfos,
                         const std::pair<Tins::IPv4Address, std::shared_ptr<Router>> &dstInfos) : srcInfos(srcInfos),
                                                                                                  gatewayInfos(
                                                                                                          gatewayInfos),
                                                                                                  dstInfos(dstInfos) {}

const std::pair<Tins::IPv4Address, std::shared_ptr<Router>> &SimpleRoute::getSrcInfos() const {
    return srcInfos;
}

const std::pair<Tins::IPv4Address, std::shared_ptr<Router>> &SimpleRoute::getGatewayInfos() const {
    return gatewayInfos;
}

const std::pair<Tins::IPv4Address, std::shared_ptr<Router>> &SimpleRoute::getDstInfos() const {
    return dstInfos;
}

bool operator == (const SimpleRoute & r1, const SimpleRoute & r2){
    return r1.srcInfos.first == r2.srcInfos.first &&
           r1.srcInfos.second.get() == r2.srcInfos.second.get() &&
           r1.gatewayInfos.first == r2.gatewayInfos.first &&
           r1.gatewayInfos.second.get() == r2.gatewayInfos.second.get() &&
           r1.dstInfos.first == r2.dstInfos.first &&
           r1.dstInfos.second.get() == r2.dstInfos.second.get();
}
