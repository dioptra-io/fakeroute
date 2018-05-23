//
// Created by root on 9/11/17.
//

#include "Topology.hpp"
bool Topology::mustResetFlow = false;

void Topology::setRoutes(const std::vector<SimpleRoute> &routes) {
    Topology::routes = routes;
}

void Topology::setRouters(const std::vector<std::shared_ptr<Router>> &routers) {
    Topology::routers = routers;
}

const std::vector<std::shared_ptr<Router>> &Topology::getRouters() const {
    return routers;
}
