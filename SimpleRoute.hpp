//
// Created by root on 9/7/17.
//

#ifndef FAKEROUTEC_SIMPLEROUTE_HPP
#define FAKEROUTEC_SIMPLEROUTE_HPP

#include <tins/tins.h>
#include "Router.fwd.hpp"

class SimpleRoute {

public:

    //Dummy Route
    SimpleRoute() {}



    const std::pair<Tins::IPv4Address, std::shared_ptr<Router>> &getSrcInfos() const;

    const std::pair<Tins::IPv4Address, std::shared_ptr<Router>> &getGatewayInfos() const;

    const std::pair<Tins::IPv4Address, std::shared_ptr<Router>> &getDstInfos() const;

    //Lets use builder pattern to build a route

    struct RouteBuilder {
        RouteBuilder &srcAddress(const Tins::IPv4Address &address) {
            m_srcAddress = address;
            return *this;
        }

        RouteBuilder &srcRouter(const std::shared_ptr<Router> &Router) {
            m_srcRouter = Router;
            return *this;
        }

        RouteBuilder &gatewayAddress(const Tins::IPv4Address &address) {
            m_gatewayAddress = address;
            return *this;
        }

        RouteBuilder &gatewayRouter(const std::shared_ptr<Router> &Router) {
            m_gatewayRouter = Router;
            return *this;
        }

        RouteBuilder &dstAddress(const Tins::IPv4Address &address) {
            m_dstAddress = address;
            return *this;
        }

        RouteBuilder &dstRouter(const std::shared_ptr<Router> &Router) {
            m_dstRouter = Router;
            return *this;
        }

        SimpleRoute build() {
            return SimpleRoute(std::make_pair(m_srcAddress, m_srcRouter),
                               std::make_pair(m_gatewayAddress, m_gatewayRouter),
                               std::make_pair(m_dstAddress, m_dstRouter));
        }

    private:

        Tins::IPv4Address m_srcAddress;
        std::shared_ptr<Router> m_srcRouter;

        Tins::IPv4Address m_gatewayAddress;
        std::shared_ptr<Router> m_gatewayRouter;

        Tins::IPv4Address m_dstAddress;
        std::shared_ptr<Router> m_dstRouter;
    };


private:
    friend RouteBuilder;

    //Constructor is private, use builder instead to avoid stupid mistakes
    SimpleRoute(const std::pair<Tins::IPv4Address, std::shared_ptr<Router>> &srcInfos,
                const std::pair<Tins::IPv4Address, std::shared_ptr<Router>> &gatewayInfos,
                const std::pair<Tins::IPv4Address, std::shared_ptr<Router>> &dstInfos);

    std::pair<Tins::IPv4Address, std::shared_ptr<Router> > srcInfos;
    std::pair<Tins::IPv4Address, std::shared_ptr<Router> > gatewayInfos;
    std::pair<Tins::IPv4Address, std::shared_ptr<Router> > dstInfos;

    friend bool operator == (const SimpleRoute &, const SimpleRoute &);
};



#endif //FAKEROUTEC_SIMPLEROUTE_HPP
