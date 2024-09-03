# Redis

This directory contains the Makefile and the template manifest for the most
recent version of Redis (as of this writing, version 6.0.5).

The Makefile and the template manifest contain extensive comments and are made
self-explanatory. Please review them to gain understanding of Gramine and
requirements for applications running under Gramine. If you want to contribute a
new example to Gramine and you take this Redis example as a template, we
recommend to remove the comments from your copies as they only add noise (see
e.g. Memcached for a "stripped-down" example).


# Quick Start

```sh
# build Redis and the final manifest
make SGX=1

# run original Redis against a benchmark (redis-benchmark supplied with Redis)
./redis-server --save '' &
src/src/redis-benchmark
kill %%

# run Redis in non-SGX Gramine against a benchmark (args are hardcoded in manifest)
gramine-direct redis-server &
src/src/redis-benchmark
kill %%

# run Redis in Gramine-SGX against a benchmark (args are hardcoded in manifest)
gramine-sgx redis-server &
src/src/redis-benchmark
kill %%
```

# Why this Redis configuration?

Notice that we run Redis with the `save ''` setting. This setting disables
saving DB to disk (both RDB snapshots and AOF logs). We use this setting
because:

- saving DB to disk is a slow operation (Redis uses fork internally which is
  implemented as a slow checkpoint-and-restore in Gramine and requires creating
  a new SGX enclave);
- saved RDB snapshots and AOF logs must be encrypted and integrity-protected for
  DB confidentiality reasons, which requires marking the corresponding
  directories and files as `encrypted` in Gramine manifest; we skip it for
  simplicity.

In Gramine case, this setting is hardcoded in the manifest file, see
`loader.argv` there.

# Redis with Select

By default, Redis uses the epoll mechanism of Linux to monitor client
connections. To test Redis with select, add `USE_SELECT=1`, e.g., `make SGX=1
USE_SELECT=1`.



# RAKIS experiment
We start by compiling with USE_SELECT=1 as RAKIS is not yet supporting epoll.
The full command to build and run redis with `gramine-sgx` is:
```
make clean && make SGX=1 USE_SELECT=1 && gramine-sgx ./redis-server
```

Then to run the benchmark client we run:
```
./redis-benchmark -t ping,set,get -n 100000 -q
```

Note that in this experiment, we dont really care for putting the client and
server in different network namespace; as redis uses TCP, which is forwarded to
host kernel through RAKIS's io_uring, rather than processed completely within
RAKIS, any optimization the kernel does due to same network namespace will be same
in all settings.


## Eurosys artifact reviewers

You need two terminals to run this experiment: one to run the redis server,
and another to run the ./redis-benchmark client.

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

For example, to use Rakis-SGX to run redis:
```
make eurosys-reproduce-server-rakis-sgx
```

By the end of this command, you should have the redis server running and ready
for the experiment on the default redis port (6379) on 127.0.0.1

Now, from a separate terminal, we can run the ./redis-benchmark client. Navigate to
CI-Examples/redis and run:
```
./redis-benchmark -t ping,set,get -n 100000 -q
```

By the end of the experiment, we report the PING_BULK, SET and GET numbers shown by
redis-benchmark tool,
normalized to the native execution TPS.

## Note on not running the client from client_ns
In this experiment, redis is only using TCP. So all traffic will go through the
same route for any settings (either RAKIS via io_uring or using just regular
syscalls for other settings). So we are not really keen on running the client
from a different network namespace. One can easily setup the required routing
rules here and have redis server on 10.50.0.1 for example.
