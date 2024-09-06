# iperf3 benchmarks

Network performance testing utility. Makefile will clone the iperf repo and
apply the `iperf3_tcp_info.patch` patch to disable the use of TCP_INFO as it is
not supported by Gramine.

Use `SGX=1 make` to prepare Gramine's manifest file for SGX.

`iperf3.manifest.template` contains an explanation for Rakis's specific
configurations.

Example running for server instance:
```
make clean && SGX=1 DEBUG=0 make && gramine-sgx ./iperf3 -s -p 57344 -4 -V -B 10.50.0.1 --forceflush
```

Example running for client instance in separate network namespace (in a different terminal):
```
sudo ip netns exec client_ns ./iperf3 -c 10.50.0.1 -p 57344 -4 -V --get-server-output --udp-counters-64bit -B 10.50.0.2 --forceflush -O 3 -t 10 -u -b 25G -l 1460 -f m
```

## Eurosys artifact reviewers
You need two terminals to run this experiment: one to run the iperf3 server,
and another to run the iperf3 client.

In addition, we need to run the server iperf3 under five different settings:
native, Gramine-SGX, Gramine-Direct, Rakis-SGX and Rakis-Direct.

We provide Makefile targets that will make this easier and less confusing:

| Target | Setting |
| ------- | -------- |
| eurosys-reproduce-server-native | native |
| eurosys-reproduce-server-gramine-sgx | Gramine-SGX |
| eurosys-reproduce-server-gramine-direct | Gramine-Direct |
| eurosys-reproduce-server-rakis-sgx | Rakis-SGX |
| eurosys-reproduce-server-rakis-direct | Rakis-direct |

Example command:
```
make eurosys-reproduce-server-native
```

By the end of this command, you should have the iperf3 server running and ready
for the experiment on 10.50.0.1:57344.

Now, from a separate terminal, we can run the iperf3 client. Navigate to
CI-Examples/iperf3 and run:
```
./run-tests.bash -n EXAMPLE_EXPERIMENT_NAME -v -i 5 -- -c 10.50.0.1 -p 57344 -4 -V --get-server-output --udp-counters-64bit -B 10.50.0.2 --forceflush -O 3 -t 10 -u -b 25G
```

This will run the experiment. Replace EXP_NAME with a unique name for the
experiment (we suggest something indicative of the server setting being tested
i.e. GRAMINE_SGX). After it is done, a csv results file will be produced for the
iperf3 runs with different block sizes.

After the experiment is complete kill the iperf3 server and try with another
server setting using the Makefile targets in the above table. All results will
be appended to the same file with the name of the experiment in the table.
