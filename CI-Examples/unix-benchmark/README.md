# fstime (Rakis experiment)

We use the fstime benchmark from [unix benchmark](https://github.com/kdlucas/byte-unixbench.git).

The goal here is evaluate the performance of the read/write syscalls for files.

To build, simply run `make SGX=1`. This will build and copy the `fstime` tool to
this directory. Note that we patch `fstime` with the patch in `fstime.patch`.
The patch is needed because:
    - We increase the max buffer size used for reading/writing the file.
    - Gramine does not allow creating new files in the host filesystem, so we
      comment out the lines that create the new files for each `fstime` run.
    - Gramine does not support the `sync` syscall, so we comment that out as
      well.

Once compilation finishes, we run the experiment:
```
make clean && make SGX=1 && gramine-sgx fstime -w -t TIME_DURATION -b BLOCK_SIZE
```

## Eurosys artifact reviewers

We provide Makefile targets that will run the fstime under the different runtime
settings and block sizes:

| Target | Setting |
| ------- | -------- |
| eurosys-reproduce-fstime-native | native |
| eurosys-reproduce-fstime-gramine-sgx | Gramine-SGX |
| eurosys-reproduce-fstime-gramine-direct | Gramine-Direct |
| eurosys-reproduce-fstime-rakis-sgx | Rakis-SGX |
| eurosys-reproduce-fstime-rakis-direct | Rakis-direct |

To set the block size, simply set the
`EUROSYS_EXP_BLOCK_SIZE` environment variable before invoking make. The
default block size 2048.

For example, to use Rakis-SGX with block size 1024:
```
EUROSYS_EXP_BLOCK_SIZE=1024 make eurosys-reproduce-fstime-rakis-sgx
```

Each experiment is 10 seconds of duration. The score in the output is the
throughput which we report in our evaluation figures.

## Note on use of xfs filesystem
io_uring is faster with xfs filesystem. This is because it supports
doing the write operations in the same calling thread, rather than using
io workers which would make it slower. 
See here for more details: https://lwn.net/Articles/896909/
