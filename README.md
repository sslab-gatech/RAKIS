# RAKIS: Secure Fast I/O Primitives Across Trust Boundaries on Intel SGX
RAKIS is a comprehensive system that securely enables SGX enclave programs
to leverage fast IO Linux kernel primitives without modifying user applications.
RAKIS achieves performance advantages without sacrificing TCB size or introducing
deployment intricacies and demonstrates significant improvements in
benchmark tests with a 4.6x increase in UDP network throughput compared
to state-of-the-art SGX enclave LibOS [Gramine](https://github.com/gramineproject/gramine).
In addition, RAKIS was shown to achieve an average performance improvement
of 2.8x compared to Gramine across four real-world programs: Memcached,
Curl, Redis, and MCrypt.

RAKIS was published in [EuroSys'25](https://2025.eurosys.org/accepted-papers.html).
Please read our paper for full details on RAKIS.

## Building
### Building Gramine
RAKIS is a fork of Gramine. So before starting with RAKIS, we suggest that you
go on to Gramine to setup the SGX environment and make sure you are able to
build and run example programs on `gramine-sgx`. Luckily, they have a rich
[documentation](https://gramine.readthedocs.io/en/stable/devel/building.html)
on how to setup everything you need.

## System requirements
In addition to the system requirements of Gramine, RAKIS uses Linux kernel IO
primitives that are only available on recent kernels:
[AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html)
and
[io_uring](https://unixism.net/loti/what_is_io_uring.html).
In fact, many aspects of both of those IO primitives are actively being
developed and improved with each Linux kernel release, so the most recent
Linux kernel is really recommended. However, RAKIS was developed and tested
only on Linux kernel 6.2.

## Hardware requirement
RAKIS does not enforce any hardware requirements. However, some NICs have better
support for XDP feature, i.e. enabling zero-copy mode. With XDP, the Linux
kernel will have an emulated mode for NICs that dont have support for XDP, in
that case, however, performance may not be optimal.

### Building RAKIS
Configure:
```shell
meson setup build-release/ --buildtype=release \
   -Ddirect=enabled -Dsgx=enabled -Drakis=enabled \
   --prefix=$HOME/.local/gramine
```

Build:
```shell
ninja -C build-release/ install
```

### Environment setup
We will explain how we setup our environment for the experiments showcased on
our RAKIS paper.

#### Network configuration
We employed one NIC that have two Ethernet interfaces (ens1f0 & ens1f1) which
are wired in a loopback configuration. Next, in order to avoid any Linux kernel
optimization on send/recv of packets within the same system, we placed one of
the interfaces (ens1f1) in a separate network namespace:
```shell
# create new namespace
sudo ip netns add client_ns;

# move ens1f1 to client_ns namespace
sudo ip link set ens1f1 netns client_ns;
sudo ip netns exec client_ns ip addr add 10.50.0.2/24 dev ens1f1;
sudo ip netns exec client_ns ip link set dev ens1f1 up;
sudo ip netns exec client_ns ip link set dev lo up;

# set ip for ens1f0 in the same network for routing
sudo ip address add 10.50.0.1/24 dev ens1f0;

# test reachability
ping 10.50.0.2 -c3;
sudo ip netns exec client_ns ping 10.50.0.1 -c3;
```

#### XDP configuration
We use interface ens1f0 for loading and attaching XDP programs. Network packets
arrive at the interfaces in many different queues. The number of queues can be
checked using:
```shell
sudo ethtool -l ens1f0;
```

However, we will be attaching our XDP program to only a subset of those queues.
This is a problem because packets intended for us may arrive to queues that we
are not attached to, and so we miss them. This problem can be solved either by
using a NIC that have hardware capabilities to send packets to specific queues
based on packet data (i.e. UDP port) ([See here](https://docs.kernel.org/networking/scaling.html)).
Or, to make things easier for us, we will just combine all queues of our
interface into a small number of queues that we will attach to all of them:
```shell
sudo ethtool -L ens1f0 combined 1;
```

#### RAKIS configuration
RAKIS is easy to configure. The file
[iperf3.manifest.template](CI-Examples/iperf3/iperf3.manifest.template)
has example configurations for RAKIS with explanation for each option. In
addition, RAKIS needs the XDP program to be already loaded and will just receive the
xsk socket fd from a unix socket. We created an XDP program that we
used for all of our experimentation. To make things flexible, we keep this
utility in a separate small program so that users can choose the behavior of the
loaded XDP programs. Please check [rakis-xdp-ctrl](CI-Examples/rakis-xdp-ctrl)
for more details.

## Running
We use iperf3 as an example of how to run RAKIS. We start by navigating to
`CI-Examples/rakis-xdp-ctrl` and run `make`. This will compile our xdp loader
tool and the xdp ebpf program. We run the tool in the background with:
```
sudo ./rakis-xdp-def-ctrl -i ens1f0 -p /tmp/rakis-xdp-def-ctrl &
```
We can check that our XDP program is loaded with: `ip a` and reading the
interface information:
```
.....
8: ens1f0: ..... xdp/id:1021 ......
    link/ether 40:a6:b7:40:37:f8 brd ff:ff:ff:ff:ff:ff
.....
```
Now we head over to iperf3 in `CI-Examples/iperf3`. To compile iperf3
and prepare everything:
```
make SGX=1
```
After compilation is done, we should find the iperf3 binary within the
`CI-Examples/iperf3` directory.
To run the server within SGX we can simply do:
```shell
sudo $HOME/.local/gramine/bin/gramine-sgx ./iperf3 -s -p 57344 -4 -V -B 10.50.0.1 --forceflush
```

Note that you can configure your Linux user to avoid using sudo here. But lets
move on.
Now you should have iperf3 running on port 57344. Please make sure the port you
choose is within the range of rakis. That range by default is >= 0xe000. 

In a separate terminal, lets run iperf3 in the client_ns network namespace:
```
sudo ip netns exec client_ns ./iperf3 -c 10.50.0.1 -p 57344 -4 -V --get-server-output --udp-counters-64bit -B 10.50.0.2 --forceflush -O 3 -t 10 -u -b 25G -l 1460 -f m
```
I will leave the explanation of the iperf3 options used here for `iperf3 --help`
but thats it with RAKIS!

## Eurosys artifact reviewers
We organized our artifact walkthrough to facilitate ease of reproduction.
The process guides reviewers to individual directories for each experiment detailed in
our paper.
Each directory contains a README.md file with a section titled
"Eurosys Artifact Reviewers",
which specifies the exact commands required to run
the experiments.
To streamline execution and ensure transparency, we also
provide Makefiles with the `eurosys-reproduce` target.
These Makefile targets simplify
the process of running the experiments and clearly display the commands being
executed.

### SSH access
In accordance with Eurosys artifact evaluation committee guidelines for projects
requiring Intel SGX, we are providing SSH access to our machine for reviewers.
Please contact us via HotCRP to request access.

### Environment setup
You do not need to set up the environment on our machine, as it has already been
configured.

### Start here!
Once you login to our machine,
clone this repository
```
git clone https://github.com/sslab-gatech/RAKIS.git
```
and run (in the top-level directory):
```
make eurosys-reproduce
```
It will build and install RAKIS & Gramine in ~/.local.
If the build process prompts for a password, please use the password provided.
This is necessary to enable certain user capabilities for the RAKIS binary to
load and attach XDP programs.

Our environment also has a XDP loader process running in the background which
you can use directly. So there is no need
to execute any of the steps in
[CI-Examples/rakis-xdp-ctrl](CI-Examples/rakis-xdp-ctrl).

Now, you are ready to start with the experiments.
For each of the following workloads, please skip over to the "Eurosys artifact
reviewers" section in the README.md file within
for instructions.
Do not execute the instructions before that as it might be already setup in our
server.
Artifact evaluation experiments:
- E1: [CI-Examples/iperf3](CI-Examples/iperf3).
- E2: [CI-Examples/curl](CI-Examples/curl).
- E3: [CI-Examples/memcached](CI-Examples/memcached).
- E4: [CI-Examples/unix-benchmark](CI-Examples/unix-benchmark).
- E5: [CI-Examples/redis](CI-Examples/redis).
- E5: [CI-Examples/mcrypt](CI-Examples/mcrypt).

## Bibtex
```
@inproceedings{10.1145/3689031.3696090,
author = {Mansour Alharthi and Fan Sang and Dmitrii Kuvaiskii and Mona Vij and Taesoo Kim},
title = {RAKIS: Secure Fast I/O Primitives Across Trust Boundaries on Intel SGX},
booktitle = {Proceedings of Twentieth European Conference on Computer Systems},
year = {2025},
}
```
