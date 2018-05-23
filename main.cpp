#include <iostream>
#include <tins/tins.h>
#include <netinet/in.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <fstream>
#include <sstream>
#include <regex>
#include <math.h>

#include "Router.hpp"
#include "Topology.hpp"

using namespace Tins;
//Anonymous namespace protect against any variable that has the same name in an other compilation unit
namespace {
    std::shared_ptr<Router> router1;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    const IPv4Address localhost{"127.0.0.1"};
    Topology topology;
    std::string destination;
    std::shared_ptr<Router> destinationRouter;
}
/**
 * The following variables are uniquely for testing the new mda
 */
namespace{
    int current_probe_received = 0;
    bool stopResponding = false;
    int default_first_max_probes = 500000;
    int first_max_probes = default_first_max_probes;
    int max_probes_received = first_max_probes;
    double step = 0.1;
    int current_iter = 1;
}

//Handler of the libnetfilter_queue library calling libtins to parse the packet and build icmp reponse

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    int id = 0;


    struct nfqnl_msg_packet_hdr *ph;
    int ret;
    unsigned char *packetData;

    ret = nfq_get_payload(nfa, &packetData);
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        IP mypack(packetData, static_cast<uint32_t>(ret));
        auto it = std::find_if(router1->getRoutingTable().begin(), router1->getRoutingTable().end(),
                               [](const SimpleRoute &route) {
                                   return route.getSrcInfos().first == localhost;
                               });
        EthernetII ethernetII((unsigned char *) buf, rv);
        PDU *pdu = ethernetII.release_inner_pdu();
        delete pdu;
        ethernetII.inner_pdu(mypack);
        //Variable here to see if we have to reset the flows


        //True if we have to reset the flows, reset the number of probe received also
        if (mypack.dst_addr() == IPv4Address("127.1.1.1")) {
            std::for_each(topology.getRouters().begin(), topology.getRouters().end(),
                          [](const std::shared_ptr<Router> &router) {
                              router->getFlowsHashed().clear();
                          });
        } else if (mypack.dst_addr() == IPv4Address("127.1.1.2")){
            ////////////////////////THE FOLLOWING STUFF IS FOR TESTING THE NEW MDA////////////////////
            //Special address to reset the count of probes and multiply by the step
            //number of probes
            if (max_probes_received == default_first_max_probes){
                // We are at the beginning of a test, this is the default value
                max_probes_received = current_probe_received;
                // First time we pass here
                if (first_max_probes == default_first_max_probes){
                    first_max_probes = max_probes_received;
                }

                stopResponding = false;
                max_probes_received = static_cast<int> (first_max_probes - step * current_iter * first_max_probes);
                current_probe_received = 0;
                ++current_iter;
            } else {
                max_probes_received = static_cast<int> (first_max_probes - step * current_iter * first_max_probes);
                current_probe_received = 0;
                ++current_iter;
                std::cout << "Max probes reference:" << first_max_probes << "\n";
                std::cout << "Max probes : " << max_probes_received << "\n";
                std::cout << "Next iteration : " << current_iter << "\n";
                stopResponding = false;
            }
        } else if (mypack.dst_addr() == IPv4Address("127.1.1.3")){
            //Special address to reset the count of probes and set to the first max probes
            std::cout << "Resetting current iter and current_probe_received" <<"\n";
            max_probes_received = first_max_probes;
            current_probe_received = 0;
            stopResponding = false;
            current_iter = 1;
            //////////////////////END OF TESTING PART///////////////////////////////////////////////
        } else if (mypack.dst_addr() == IPv4Address(destination)) {
            // Hack here to do several tries of MDA without relaunching fakeroute
            if (!stopResponding){
                router1->readPacket(ethernetII, *it);
            }

        }
    }

    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}


struct ParsedRoute {
public:
    ParsedRoute(const std::string &src, const std::string &dst) : src(src), dst(dst) {}

    std::string src;
    std::string dst;
};

namespace {
    std::string address{
            "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"};
    std::regex addressRe{address};
}

std::vector<ParsedRoute> parseTopologyFile(const std::string &fileName) {
    std::vector<ParsedRoute> routes;

    std::ifstream stream(fileName);
    //A line is of the following form : *.*.*.* *.*.*.* where * is a number
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) {
            continue;
        }
        //Parse the source address
        auto srcAddress = std::sregex_iterator(line.begin(), line.end(), addressRe);
        std::smatch match = std::smatch(*srcAddress);
        std::string src{match.str()};
        //Parse the dst address
        auto dstAddress = ++srcAddress;
        match = std::smatch(*dstAddress);
        std::string dst(match.str());
        routes.emplace_back(std::move(src), std::move(dst));
    }
    return routes;
}

bool canReachDestination(const std::shared_ptr<Router> &router, std::vector<std::shared_ptr<Router>> &visitedRouters) {
    bool ret = false;
    auto routingTableCopy(router->getRoutingTable());
    std::for_each(routingTableCopy.begin(), routingTableCopy.end(),
                  [&router, &visitedRouters, & ret](const SimpleRoute &route) {
                      std::string strSrc = route.getSrcInfos().first.to_string();
                      std::string gatewaySrc = route.getDstInfos().first.to_string();
                      //Dont take the localhost first route into account
//                      const std::vector<SimpleRoute> & routingTable = router->getRoutingTable();
                      if (route.getSrcInfos().first != localhost) {

                          //Check if we got a cycle, we have already visited this node
                          if (std::find(visitedRouters.begin(), visitedRouters.end(), router) !=
                              visitedRouters.end()) {
                              ret = false;
                          }
                          if (route.getDstInfos().first == IPv4Address(destination)) {
                              ret = true;
                              return;
                          }
                          if (canReachDestination(route.getDstInfos().second, visitedRouters)) {
                              //Add the gateway to the router
                              SimpleRoute::RouteBuilder routeBuilder;
                              routeBuilder.srcAddress(route.getSrcInfos().first).srcRouter(router).gatewayAddress(
                                      route.getDstInfos().first).gatewayRouter(route.getDstInfos().second).dstAddress(
                                      IPv4Address(destination)).dstRouter(destinationRouter);

                              auto routeToAdd = routeBuilder.build();
                              // Check if we already have this route for this router
                              auto routeIt = std::find(router->getRoutingTable().begin(), router->getRoutingTable().end(), routeToAdd);
                              if (routeIt == router->getRoutingTable().end()){
                                  router->addRoute(routeToAdd);
                              }
                              ret = true;
                          }
                      }
                  });
    visitedRouters.push_back(router);
    return ret;
}


//White contract : The provided routes must be direct routes (i.e no gateway).
Topology buildTopologyFromParsedRoute(const std::vector<ParsedRoute> &parsedRoutes) {
    //Algorithm is the following. Let's consider that a route is a route between subnetwork even if the IPs seems to be in the same subnetwork
    //If we already have the address in a route, select the corresponding router and add the route
    //Otherwise create a new router with the route. Same for the destination.
    //Then we determine the possible paths from host to destination and create the necessary gateways.
    std::vector<std::shared_ptr<Router>> routers;
    std::vector<SimpleRoute> routes;
    std::for_each(parsedRoutes.begin(), parsedRoutes.end(),
                  [&routers, &routes](const ParsedRoute &parsedRoute) {
                      IPv4Address srcAddress{parsedRoute.src};
                      IPv4Address dstAddress{parsedRoute.dst};

                      //Check if we already have this src in the topology routers
                      auto srcRouterIt = std::find_if(routers.begin(), routers.end(),
                                                      [&srcAddress, &dstAddress](
                                                              const std::shared_ptr<Router> &router) {
                                                          return std::find(router->getInterfaces().begin(),
                                                                           router->getInterfaces().end(),
                                                                           srcAddress) != router->getInterfaces().end();
                                                      });
                      //Check if we already have this destination in the topology routers
                      auto dstRouterIt = std::find_if(routers.begin(), routers.end(),
                                                      [&srcAddress, &dstAddress](
                                                              const std::shared_ptr<Router> &router) {
                                                          return std::find(router->getInterfaces().begin(),
                                                                           router->getInterfaces().end(),
                                                                           dstAddress) != router->getInterfaces().end();

                                                      });
                      //First case, we do not have the source nor the destination
                      if (srcRouterIt == routers.end() && dstRouterIt == routers.end()) {
                          //Create two routers
                          std::shared_ptr<Router> src{new Router};
                          src->addInterface(srcAddress);
                          std::shared_ptr<Router> dst{new Router};
                          dst->addInterface(dstAddress);

                          //Create the route between them
                          SimpleRoute::RouteBuilder routeBuilder;
                          routeBuilder.srcAddress(srcAddress).srcRouter(src).dstAddress(dstAddress).dstRouter(dst);
                          auto route = routeBuilder.build();
                          src->addRoute(route);
                          routers.push_back(src);
                          routers.push_back(dst);
                          routes.push_back(route);
                      }
                          //Second case, we have only the source
                      else if (srcRouterIt != routers.end() && dstRouterIt == routers.end()) {
                          std::shared_ptr<Router> dst{new Router};
                          dst->addInterface(dstAddress);
                          SimpleRoute::RouteBuilder routeBuilder;
                          routeBuilder.srcAddress(srcAddress).srcRouter(*srcRouterIt).dstAddress(dstAddress).dstRouter(
                                  dst);
                          auto route = routeBuilder.build();
                          (*srcRouterIt)->addRoute(route);
                          //Push back at the end because it invalids the iterators
                          routers.push_back(dst);
                          routes.push_back(route);
                      }
                          //Third case, we have only the destination
                      else if (srcRouterIt == routers.end() && dstRouterIt != routers.end()) {
                          //Create two routers
                          std::shared_ptr<Router> src{new Router};
                          src->addInterface(srcAddress);

                          //Create the route between them
                          SimpleRoute::RouteBuilder routeBuilder;
                          routeBuilder.srcAddress(srcAddress).srcRouter(src).dstAddress(dstAddress).dstRouter(
                                  *dstRouterIt);
                          auto route = routeBuilder.build();
                          src->addRoute(route);
                          routers.push_back(src);
                          routes.push_back(route);
                      }
                          //Last case, we have both
                      else {

                          //Create the route between them
                          SimpleRoute::RouteBuilder routeBuilder;
                          routeBuilder.srcAddress(srcAddress).srcRouter(*srcRouterIt).dstAddress(dstAddress).dstRouter(
                                  *dstRouterIt);
                          auto route = routeBuilder.build();
                          (*srcRouterIt)->addRoute(route);
                          routes.push_back(route);
                      }
                  });


    //Remove the localhost router
    auto localhostRouter = std::find_if(routers.begin(), routers.end(), [](const std::shared_ptr<Router> &router) {
        return std::find_if(router->getInterfaces().begin(), router->getInterfaces().end(),
                            [](const IPv4Address &address) {
                                return localhost == address;
                            }) != router->getInterfaces().end();
    });
    auto firstRoute = (*localhostRouter)->getRoutingTable().begin();
    if (firstRoute == (*localhostRouter)->getRoutingTable().end()) {
        std::cerr << "Bad topology, please put a route between localhost and a router\n";
        throw std::exception();
    }
    //Set router1 as the destinatino of the first route
    router1 = firstRoute->getDstInfos().second;
    router1->addRoute(*firstRoute);

    routers.erase(std::remove_if(routers.begin(), routers.end(), [](const std::shared_ptr<Router> &router) {
        return std::find_if(router->getInterfaces().begin(), router->getInterfaces().end(),
                            [](const IPv4Address &address) {
                                return localhost == address;
                            }) != router->getInterfaces().end();
    }), routers.end());


    //Set the last router
    auto destinationRouterIt = std::find_if(routers.begin(), routers.end(), [](const std::shared_ptr<Router> &router) {
        return std::find(router->getInterfaces().begin(), router->getInterfaces().end(), IPv4Address(destination)) !=
               router->getInterfaces().end();
    });

    if (destinationRouterIt == routers.end()) {
        std::cerr << "Bad topology, please put a route to the destination\n";
        throw std::exception();
    }
    destinationRouter = *destinationRouterIt;

    std::cout << "Routes before filling destination: \n";
    std::for_each(routers.begin(), routers.end(), [](const std::shared_ptr<Router> &router) {
        std::for_each(router->getRoutingTable().begin(), router->getRoutingTable().end(), [](const SimpleRoute &route) {
            std::cout << route.getSrcInfos().first.to_string() << " -> " << route.getDstInfos().first.to_string()
                      << "\n";
        });
    });

    std::cout << " ************************************************************** \n\n\n\n\n\n\n";

    //Now build the routes to the destination
    //Take all the possible routes from localhost to destination
    std::vector<std::shared_ptr<Router>> visitedRouters;
    canReachDestination(router1, visitedRouters);


    std::cout << "Routes after filling destination: \n";
    std::for_each(routers.begin(), routers.end(), [](const std::shared_ptr<Router> &router) {
        std::for_each(router->getRoutingTable().begin(), router->getRoutingTable().end(), [](const SimpleRoute &route) {
            std::cout << route.getSrcInfos().first.to_string() << " -> " << route.getGatewayInfos().first.to_string()
                      << " -> " << route.getDstInfos().first.to_string() << "\n";
        });
    });


    Topology topology;
    topology.setRouters(routers);
    topology.setRoutes(routes);
    return topology;


}

/**
 * Probability to discover 1 more interface knowing that we already discovered j and that there are K interfaces
 * @param j  number of interfaces already discovered
 * @param K number of total interfaces to discover
 * @return
 */
constexpr double probabilityDiagonalTransition(int j, int K) {
    return (K - j) / static_cast<double>(K);
}

/**
 * Probability to not discover 1 interface
 * @param j  number of interfaces already discovered
 * @param K number of total interfaces to discover
 * @return
 */
constexpr double probabilityHorizontalTransition(int j, int K) {
    return j / static_cast<double>(K);
}

/**
 * Probability to reach this state :
 * its the probability to be in the state (i-1, j-1) * probabilityDiagonalTransition(j-1,K)
 * + probability to be in the state (i-1,j) * probabilityHorizontalTransition(j, K)
 * @param i number of probes sent
 * @param j number of interfaces already discovered
 * @param K number of total interfaces to discover
 * @param computedStates already computed states
 * @return
 */

using ProbabilitySpace = std::vector<std::vector<double>>;

ProbabilitySpace populateProbabilitySpace(int K, const std::vector<int> &stoppingPoints) {

    ProbabilitySpace space(K + 1, std::vector<double>(stoppingPoints[stoppingPoints.size() - 1], 0));
    //Init the space with line 1
    //Line 1
    for (int k = 0; k <= stoppingPoints[1]; ++k) {
        space[1][k] = pow(1 / static_cast<double>(K), k - 1);
    }
    //Fill the rest of the space
    for (int j = 2; j <= K; ++j) {
        for (int i = j; i <= stoppingPoints[j]; ++i) {
            //Get the different states that can reach the current state
            double contributions[]{space[j - 1][i - 1] * probabilityDiagonalTransition(j - 1, K),
                                   space[j][i - 1] * probabilityHorizontalTransition(j, K)};

            //If the stopping point is reached, dont take into account his participation to the probability
            // as the transition is not possible
            if (i - 1 != stoppingPoints[j - 1]) {
                space[j][i] += contributions[0];
            }
            space[j][i] += contributions[1];
        }
    }
    return space;
}

/*
 * Lets divide the space into two axis, x represents the number of probes, y represents the number
 * of discovered interfaces
 */
/**
 * Calculate failure probability for a given K
 * @param K real number of interfaces
 * @param nks number of probes to send, pre calculated
 * @return
 */
double failureProbabilityForK(int K, const std::vector<int> &nks) {
    auto space = populateProbabilitySpace(K, nks);
    return 1 - space[space.size() - 1][nks[K - 1]];
}


int main(int argc, char **argv) {

    //Two ways of serializing a topology json file or a visualizable one


/*
    static int mda_stopping_points(unsigned int num_interfaces, unsigned int confidence)
    {
        *
                * number of probes (k) to send to rule out a load-balancer having n hops;
        * 95% failure probability bound level first from 823-augustin-e2emon.pdf, then extended
        * with gmp-based code.
                         * 99% confidence derived with gmp-based code.
                                                                 *
        static const int k[][2] = {
                {   0,   0 }, {   0,   0 }, {   6,   8 }, {  11,  15 }, {  16,  21 },
                {  21,  28 }, {  27,  36 }, {  33,  43 }, {  38,  51 }, {  44,  58 },
                {  51,  66 }, {  57,  74 }, {  63,  82 }, {  70,  90 }, {  76,  98 },
                {  83, 106 }, {  90, 115 }, {  96, 123 }, { 103, 132 }, { 110, 140 },
                { 117, 149 }, { 124, 157 }, { 131, 166 }, { 138, 175 }, { 145, 183 },
                { 152, 192 }, { 159, 201 }, { 167, 210 }, { 174, 219 }, { 181, 228 },
                { 189, 237 }, { 196, 246 }, { 203, 255 }, { 211, 264 }, { 218, 273 },
                { 226, 282 }, { 233, 291 }, { 241, 300 }, { 248, 309 }, { 256, 319 },
                { 264, 328 }, { 271, 337 }, { 279, 347 }, { 287, 356 }, { 294, 365 },
                { 302, 375 }, { 310, 384 }, { 318, 393 }, { 326, 403 }, { 333, 412 },
                { 341, 422 }, { 349, 431 }, { 357, 441 }, { 365, 450 }, { 373, 460 },
                { 381, 470 }, { 389, 479 }, { 397, 489 }, { 405, 499 }, { 413, 508 },
                { 421, 518 }, { 429, 528 }, { 437, 537 }, { 445, 547 }, { 453, 557 },
                { 462, 566 }, { 470, 576 }, { 478, 586 }, { 486, 596 }, { 494, 606 },
                { 502, 616 }, { 511, 625 }, { 519, 635 }, { 527, 645 }, { 535, 655 },
                { 544, 665 }, { 552, 675 }, { 560, 685 }, { 569, 695 }, { 577, 705 },
                { 585, 715 }, { 594, 725 }, { 602, 735 }, { 610, 745 }, { 619, 755 },
                { 627, 765 }, { 635, 775 }, { 644, 785 }, { 652, 795 }, { 661, 805 },
                { 669, 815 }, { 678, 825 }, { 686, 835 }, { 695, 845 }, { 703, 855 },
                { 712, 866 }, { 720, 876 }, { 729, 886 }, { 737, 896 }, { 746, 906 },
        };
    */
    //Calcul the tkK, tkK representing the probability to stop at k successors discovered
    //knowing that there are K real successors
    constexpr int nks[] = {0, 6, 11, 16, 21, 27, 33, 38, 44, 51, 57, 63, 70, 76, 83, 90, 96, 103};

    std::vector<double> failureProbabilities(17);
    for (int i = 1; i < 17; ++i) {
        failureProbabilities[i] = failureProbabilityForK(i, std::vector<int>(std::begin(nks), std::end(nks)));
    }

    //Let's write a parser of topology
    std::vector<ParsedRoute> parsedRoutes = parseTopologyFile(argv[1]);
    destination = argv[2];

    //Setup the topology
    topology = buildTopologyFromParsedRoute(parsedRoutes);

    //Find the number of load balancers in order to calcul the total failure probability
    double totalFailureProbability = 1;
    //The total failure probability is 1 - the probability that we got success at each node
    std::for_each(topology.getRouters().begin(), topology.getRouters().end(),
                  [&totalFailureProbability, &failureProbabilities](const std::shared_ptr<Router> &router) {
                      auto routeGoingToDestination = std::count_if(router->getRoutingTable().begin(),
                                                                   router->getRoutingTable().end(),
                                                                   [](
                                                                           const SimpleRoute &route) {
                                                                       return route.getDstInfos().first ==
                                                                              IPv4Address(destination);
                                                                   });
                      if (routeGoingToDestination > 1) {
                          totalFailureProbability *= (1 - failureProbabilities[routeGoingToDestination]);
                      }
                  });

    totalFailureProbability = 1 - totalFailureProbability;

    std::cout << "Total Failure Probability of the topology : " << totalFailureProbability << "\n";

    //Initialize libnetfilter_queue to intercept packets and do not send them into the outside world
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    int queue_number = std::stoi(argv[3]);

    printf("binding this socket to queue '%d'\n", queue_number);
    qh = nfq_create_queue(h, static_cast<uint16_t >(queue_number), &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }


    fd = nfq_fd(h);
    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            if (max_probes_received <= current_probe_received){
		        std::cout << "Stopping responding..." << "\n";
                stopResponding = true;
            }
            ++current_probe_received;
            printf("%d\n", ++current_probe_received);
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. Please, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

