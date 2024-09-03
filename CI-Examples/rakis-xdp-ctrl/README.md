# XDP socket program loader

This is a sample XDP socket loader for RAKIS. Basically, it will load the
`rakis-xdp-prog` BPF program to the kernel and attach it to the interface
provided in the commandline. After that, this utility program will wait on
UNIX socket at `ctrl-sock-path` that is provided in the commandline so that
it will send the XDP socket fd to the RAKIS within Gramine. This functionality,
while it could be integrated within Gramine itself, has been separated in this
utility for now due to the required linux user capabilities that the program
must acquire. We did not want to give RAKIS higher user capabilities so this is
the alternative.

Simply run with:
```shell
./rakis-xdp-def-ctrl -i ETHERNET_INTERFACE -p PATH_TO_CTRL_SOCK_PATH
```

You can also unload XDP programs and remove the UNIX sockets using the `-u`
flag.

## RAKIS XDP program
The XDP program RAKIS loads by default is located in `rakis-xdp-prog.c`. The
logic of this sample program is very easy, and the code is heavily commented so
that it is easier to understand which packets are forwarded to RAKIS (UDP
packets with in port range) and which packets are forwarded to host kernel
(everything else). So that RAKIS shares the network interface with host OS
without disturbance.
