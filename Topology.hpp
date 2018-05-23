//
// Created by root on 9/11/17.
//

#ifndef FAKEROUTEC_TOPOLOGY_HPP
#define FAKEROUTEC_TOPOLOGY_HPP

#include <memory>
#include <vector>
#include "Router.fwd.hpp"
#include "SimpleRoute.hpp"


class Topology {

public:

    void setRouters(const std::vector<std::shared_ptr<Router>> &routers);
    void setRoutes(const std::vector<SimpleRoute> &routes);
    const std::vector<std::shared_ptr<Router>> &getRouters() const;

    static bool mustResetFlow;
private:
    std::vector<std::shared_ptr<Router>> routers;
    std::vector<SimpleRoute> routes;
};


#endif //FAKEROUTEC_TOPOLOGY_HPP
