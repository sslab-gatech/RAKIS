# Memcached

This directory contains the Makefile and the template manifest for the most
recent version of Memcached as of this writing (v1.5.21).

# Prerequisites

Please install `libevent-dev` package. If you want to benchmark with memcslap,
also install `libmemcached-tools`.

# Quick Start

```sh
# build Memcached and the final manifest
make SGX=1

# run original Memcached against a benchmark (memtier_benchmark,
# install the benchmark on your host OS first)
./memcached &
memtier_benchmark --port=11211 --protocol=memcache_binary --hide-histogram
kill %%

# run Memcached in non-SGX Gramine against a benchmark
gramine-direct memcached &
memtier_benchmark --port=11211 --protocol=memcache_binary --hide-histogram
kill %%

# run Memcached in Gramine-SGX against a benchmark
gramine-sgx memcached &
memtier_benchmark --port=11211 --protocol=memcache_binary --hide-histogram
kill %%
```


# RAKIS Memcached Experiments
The Makefile will clone libevent and compile it without `epoll` as it is not yet
supported by Rakis/Gramine. Simply running `make SGX=1` should be enough to prepare
everything for Rakis's experiment.

Example running for memcached server instance:
```
make clean && make DEBUG=0 SGX=1 && gramine-sgx ./memcached -u nobody -U 57344 -l 10.50.1.1 -p 57344 -A -k -t NUM_OF_THREADS
```

Example running for memaslap client instance in separate network namespace (in a different terminal):
```
sudo ip netns exec client_ns ./memaslap -s 10.50.1.1:57344 -U -t 60s -T 4 -c 32 -S 1s -v 1
```

## Eurosys artifact reviewers

You need two terminals to run this experiment: one to run the memcached server,
and another to run the memaslap client.

In addition, we need to run the server under five different settings:
native, Gramine-SGX, Gramine-Direct, Rakis-SGX and Rakis-Direct.

We provide Makefile targets that will make this easier and less confusing:

| Target | Setting |
| ------- | -------- |
| eurosys-reproduce-server-native | native |
| eurosys-reproduce-server-gramine-sgx | Gramine-SGX |
| eurosys-reproduce-server-gramine-direct | Gramine-Direct |
| eurosys-reproduce-server-rakis-sgx | Rakis-SGX |
| eurosys-reproduce-server-rakis-direct | Rakis-direct |

To set the number of threads of the server, simply set the
`EUROSYS_EXP_NUM_THREADS` environment variable before invoking make. The
default number of threads is 4.

For example, to use Rakis-SGX to run memcached with 2 threads:
```
EUROSYS_EXP_NUM_THREADS=2 make eurosys-reproduce-server-rakis-sgx
```

By the end of this command, you should have the memcached server running and ready
for the experiment on 10.50.1.1:57344.

Now, from a separate terminal, we can run the memaslap benchmark client. Navigate to
CI-Examples/memcached and run:
```
sudo ip netns exec client_ns ./memaslap -s 10.50.1.1:57344 -U -t 60s -T 4 -c 32 -S 1s -v 1
```

By the end the experiment, we report the final TPS shown by memaslap at the
bottom line of the output, normalized to the native execution TPS.
