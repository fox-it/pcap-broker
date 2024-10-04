# pcap-broker

`pcap-broker` is a tool to capture network traffic and make this available to one or more clients via PCAP-over-IP.

PCAP-over-IP can be useful in situations where low latency is a priority, for example during Attack and Defend CTFs.
More information on PCAP-over-IP can be found here:

 * https://www.netresec.com/?page=Blog&month=2022-08&post=What-is-PCAP-over-IP

`pcap-broker` supports the following features:

 * Distributing packet data to one or more PCAP-over-IP listeners
 * Execute a command to capture traffic, usually `tcpdump` (expects stdout to be pcap data)
 * `pcap-broker` will exit if the capture command exits

## Building

Building `pcap-broker` requires the `libpcap` development headers, on Debian you can install it with:

```shell
$ apt install libpcap-dev
```

To build from source, clone this repository and run:

```shell
$ go build .
$ ./pcap-broker --help
```

Or you can build the Docker container:

```shell
$ docker build -t pcap-broker .
$ docker run -it pcap-broker --help
```

Alternatively, install directly using `go`:

```shell
$ go install github.com/fox-it/pcap-broker@latest
$ pcap-broker --help
```

## Running

```shell
$ ./pcap-broker --help
Usage of ./pcap-broker:
  -cmd string
        command to execute for pcap data (eg: tcpdump -i eth0 -n --immediate-mode -s 65535 -U -w -)
  -debug
        enable debug logging
  -json
        enable json logging
  -listen string
        listen address for pcap-over-ip (eg: localhost:4242)
  -n    disable reverse lookup of connecting PCAP-over-IP client IP address
```

Arguments can be passed via commandline:

```shell
$ ./pcap-broker -cmd "sudo tcpdump -i eth0 -n --immediate-mode -s 65535 -U -w -"
```

Or alternatively via environment variables:

```shell
LISTEN_ADDRESS=:4242 PCAP_COMMAND='sudo tcpdump -i eth0 -n --immediate-mode -s 65535 -U -w -' ./pcap-broker
```

Using environment variables is useful when you are using `pcap-broker` in a Docker setup.

Now you can connect to it via TCP and stream PCAP data using `nc` and `tcpdump`:

```shell
$ nc -v localhost 4242 | tcpdump -nr -
```

Or use a tool that natively supports PCAP-over-IP, for example `tshark`:

```shell
$ tshark -i TCP@localhost:4242
```

# Acquiring PCAP data over SSH

One use case is to acquire PCAP from a remote machine over SSH and make this available via PCAP-over-IP.
Such a use case, including an example SSH command to bootstrap this, has been documented in the `docker-compose.yml.example` file:

```yaml
version: "3.2"

services:
  pcap-broker-remote-host:
    image: pcap-broker:latest
    restart: always
    volumes:
      # mount local user's SSH key into container
      - ~/.ssh/id_ed25519:/root/.ssh/id_ed25519:ro 
    ports:
      # make the PCAP-over-IP port also available on the host on port 4200
      - 4200:4242
    environment:
      # Command to SSH into remote-host and execute tcpdump and filter out it's own SSH client traffic
      PCAP_COMMAND: ssh root@remote-host -o StrictHostKeyChecking=no 'IFACE=$$(ip route show to default | grep -Po1 "dev \K\w+") && BPF=$$(echo $$SSH_CLIENT | awk "{printf \"not (host %s and port %s and %s)\", \$$1, \$$2, \$$3;}") && tcpdump -U --immediate-mode -ni $$IFACE $$BPF -s 65535 -w -'                                 
      LISTEN_ADDRESS: "0.0.0.0:4242"
```

## Background

This tool was initially written for Attack & Defend CTF purposes but can be useful in other situations where low latency is preferred, or whenever a no-nonsense PCAP-over-IP server is needed. During the CTF that Fox-IT participated in, `pcap-broker` allowed the Blue Team to capture network data once and disseminate this to other tools that natively support PCAP-over-IP, such as:

* [Arkime](https://arkime.com/)
* [Tulip](https://github.com/OpenAttackDefenseTools/tulip) (after we did some custom patches)
* WireShark's dumpcap and tshark
