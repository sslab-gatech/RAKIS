# Curl (Rakis experiment)

We use curl to test the performance of UDP in RAKIS. Basically, we try to
download files of different sizes using the quic protocol which uses UDP.
Unfortunately, as quic is still experimental in Curl, we have to build it from
source with all of its dependencies, as well as a proxy server that can serve
files over quic protocol.

Running `make SGX=1` should be enough to build everything. It may take time so
grab a cup of coffee.

Once the build process is done, we should see two binaries: `curl` and
`nghttpx`.

In addition to this build process, we need an http server that can run behind
`nghttpx` and do the actual serving of files. For our purpose, we will use
`apache`. You can choose whatever server you like.

Lets first take care of running the server and the proxy `nghttpx`.
We want our http server and proxy to reside on the client_ns network namespace;
excuse the confusing name of the network namespace as it will be hosting the
server part of the experiment but it really does not matter as long as we have
client part and server in two different network namespace. To do that, first we
run apache as follows:
```
APACHE_STARTED_BY_SYSTEMD=true sudo -E ip netns exec client_ns /usr/sbin/apachectl start
```

Then, we run the `nghttpx` proxy server in-front of it also within the
client_ns namespace. For the certificates, we will just use the sample
certificates provided in curl source code:
```
sudo ip netns exec client_ns ./nghttpx /home/mansour/rakis/CI-Examples/curl/curl-src/tests/stunnel.pem /home/mansour/rakis/CI-Examples/curl/curl-src/tests/stunnel.pem --backend=0.0.0.0,80  --frontend="10.50.0.2,9443;quic"
```

With that, our server should be ready to serve files with quic protocol in the
client_ns.

Now we run curl:
```
gramine-sgx ./curl --http3-only https://10.50.0.2:9443/dump1G --insecure -o out -w "@curl-format.txt" -Z
```

## Eurosys artifact reviewers

Our server already has `apache` and the `nghttpx` proxy running on the client_ns
network namespace. So you can skip setting up the server and only worry about
running the curl process with different runtime settings.

We provide Makefile targets that will make this easier and less confusing:

| Target | Setting |
| ------- | -------- |
| eurosys-reproduce-curl-native | native |
| eurosys-reproduce-curl-gramine-sgx | Gramine-SGX |
| eurosys-reproduce-curl-gramine-direct | Gramine-Direct |
| eurosys-reproduce-curl-rakis-sgx | Rakis-SGX |
| eurosys-reproduce-curl-rakis-direct | Rakis-direct |

To set the size of the file to download, simply set the
`EUROSYS_EXP_DOWNLOAD_SIZE` environment variable before invoking make. The
default file to download is of size 1G.

For example, to use Rakis-SGX to download 100M file you can run:
```
EUROSYS_EXP_DOWNLOAD_SIZE=100M make eurosys-reproduce-curl-rakis-sgx
```

The make command will take a long time for the first run to compile everything
(about 10 mins) needed but will just run curl for later runs. The total_time in
the output is what we used to report in the paper, normalized to the native
execution download times.
