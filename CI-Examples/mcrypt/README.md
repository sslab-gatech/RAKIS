# MCrypt (Rakis experiment)

We use MCrypt tool to encrypt a dummy file and check its encryption time.

Since we want the file write block size to be variable (x) in our experiments,
we adjust the BUFFER_SIZE compile time configuration for MCrypt for each run
with different size (check the setbufsize target in Makefile).

One patch we apply to MCrypt is to comment out lines 564-575 in `src/mcrypt.c`.
Those lines check if there is a file with a similar name of the tool output file
and will refuse to override. This is a problem as Gramine does not allow
creating new files in the host file system. So, as a workaround we create empty
files and pass them to MCrypt as output files and MCrypt have to override them.

To build, simply run `make SGX=1`. This will build and copy the `mcrypt` tool to
this directory. To change the size of the file write buffer, use the Makefile
like: `make setbufsize MCRYPT_BUFFSIZE=___NEW_SIZE___` and then run `make SGX=1`
again to compile with the new buffer size.

Once compilation finishes, we run the experiment:
```
make clean && make SGX=1 && gramine-sgx ./mcrypt dump -k RANDOM_ENC_KEY -t
```

## Eurosys artifact reviewers

We provide Makefile targets that will run the mcrypt under the different runtime
settings and block sizes:

| Target | Setting |
| ------- | -------- |
| eurosys-reproduce-mcrypt-native | native |
| eurosys-reproduce-mcrypt-gramine-sgx | Gramine-SGX |
| eurosys-reproduce-mcrypt-gramine-direct | Gramine-Direct |
| eurosys-reproduce-mcrypt-rakis-sgx | Rakis-SGX |
| eurosys-reproduce-mcrypt-rakis-direct | Rakis-direct |

To set the block size, simply set the
`EUROSYS_EXP_BLOCK_SIZE` environment variable before invoking make. The
default block size 2048.

For example, to use Rakis-SGX with block size 1024:
```
EUROSYS_EXP_BLOCK_SIZE=1024 make eurosys-reproduce-mcrypt-rakis-sgx
```

The time reported in the output is the encryption time which we report in our
evaluation figures.

## Note on use of xfs filesystem
io_uring is faster with xfs filesystem. This is because it supports
doing the write operations in the same calling thread, rather than using
io workers which would make it slower. 
See here for more details: https://lwn.net/Articles/896909/
