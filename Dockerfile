FROM golang:alpine

COPY . /app

WORKDIR /app

RUN apk add --no-cache make build-base libpcap-dev openssh-client tcpdump

RUN go mod download
RUN go build ./cmd/pcap-broker

ENTRYPOINT ["./pcap-broker"]
