# FakeRouteC++

This tool has been developped in order to emulate very lightweight routing logic to test [Paris Traceroute](https://paris-traceroute.net/) algorithm on multipaths-detection, see https:// for more information.

## Getting Started
First you need to create your topology:

At the moment, a topology is just a file describing nodes and edges. 

An example is given below : 
```
127.0.0.1 10.0.0.1

10.0.0.1 10.1.2.3
10.0.0.1 2.3.3.3

10.1.2.3 127.1.1.6
2.3.3.3 127.1.1.6
```
The file is composed of lines that are composed of pairs of addresses.

Note that the localhost address (127.0.0.1) is mandatory at first line.

So you have just created your topology, fakerouteC++ will do the calculus for the exact probability failure that you will get, depending of the different load balancers you have put in your topology and the limits of probing that are provided. 

At the moment, the values provided are those that give a failure probability <= 0.05 or <= 0.01 calculated in Paris-Traceroute.

Example of output for the previous topology file : 
```
Total Failure Probability of the topology : 0.03125

```
It then waits for you to launch paris-traceroute tests!

### Prerequisites

In order to use FakeRouteC++, you need to have a C++ modern compiler >= C++ 11. You may also need boost for future versions.

You also need the following C and C++ libraries to be installed : 


[libtins](http://libtins.github.io/download/)
[libnetfilter_queue](https://git.netfilter.org/libnetfilter_queue/)

/!\ libnetfilter_queue needs /!\:

[libmnl](https://git.netfilter.org/libmnl/)

and

[libnfnetlink](https://git.netfilter.org/libnfnetlink/)



You will also need to change your iptables in order to redirect the traffic in libnetfilter_queue

So you need to tap the following commands:
```
sudo iptables -A OUTPUT -j NFQUEUE -d 127.1.1.6 --queue-num 1
sudo iptables -A OUTPUT -j NFQUEUE -d 127.1.1.1 --queue-num 1
```
The first one redirects output traffic that have 127.1.1.6 as a destination into libnetfilter_queue. So that means that all your topologies that you are going to test **must have 127.1.1.6 as destination**.
You can change this parameter in fakerouteC__ as it is one of its arguments, but this also means that you have to Remove the iptables rule with 127.1.1.6 and add yours with the other address.

The second command is a trick to reset the flows id of the router if you want to run several independent tests. (See [TestParisTraceroute] for more information)  

### Installing

The tool is built with cmake.

Create a build folder in the fakeroute directory then launch cmake from there:


```
mkdir ~/fakeroute/build
cd ~/fakeroute/build
cmake ../
make
```
The executable is named fakeRouteC__  and can be found in the build directory.

###Usage

```
fakerouteC__ <topologyFile> <destination> <queue-number>
```

### Break down into end to end tests

To test the tool, you need to have paris-traceroute installed. Then you just have to launch your command and wait for the response to print on the standard output.

Suppose we are in ~/fakeroute/build, launch this command:
```
sudo fakerouteC__ ../resources/2-pathsLoadBalancer 127.1.1.6 1
```

The first argument is the topology file. The second argument is the destination of the traceroute that you want to execute. The third argument is the queue that you have bound in the iptables command.

In another terminal in paris-traceroute folder:
```
sudo paris-traceroute -amda -B95,1,128 127.1.1.6
```
See paris-traceroute for options meanings.

You should see on standard output:
```
mda to 127.1.1.6 (127.1.1.6), 30 hops max, 30 bytes packets
0 None -> 10.0.0.1 [{ 0*1, 0*2, 0*3, 0*4, 0*5, 0*6 } -> {  1*1, 1*2, 1*3, 1*4, 1*5, 1*6 }]
1 10.0.0.1 -> 2.3.3.3 [{ 1*1, 1*2, 1*3, 1*4, 1*5, 1*6, 1*7, 1*8, 1*9, 1*10, 1*11 } -> {  2*1, 2*2, 2*4, 2*6, 2*11, 2?12 }]
2 2.3.3.3 -> 127.1.1.6 [{ 2*1, 2*2, 2*4, 2*6, 2*11, 2?13 } -> {  3 1, 3 2, 3 4, 3 6, 3 11 }]
2 10.1.2.3 -> 127.1.1.6 [{ 2*3, 2*5, 2*7, 2*8, 2*9, 2*10, 2 12 } -> {  3 1, 3 2, 3 4, 3 6, 3 11, 3 3, 3 5, 3 7, 3 8, 3 9, 3 10 }]
2 2.3.3.3 -> 127.1.1.6 [{ 2*1, 2*2, 2*4, 2*6, 2*11, 2*13 } -> {  3 1, 3 2, 3 4, 3 6, 3 11, 3 3, 3 5, 3 7, 3 8, 3 9, 3 10, 3 13 }]
Lattice:
None -> [ 10.0.0.1 ]
10.0.0.1 -> [ 2.3.3.3, 10.1.2.3 ]
2.3.3.3 -> [ 127.1.1.6 ]
127.1.1.6
10.1.2.3 -> [ 127.1.1.6 ]
127.1.1.6
```

If you want to test the statistics about failure, see  [TestParisTraceroute](https://)