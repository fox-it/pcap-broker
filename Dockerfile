FROM golang:alpine

RUN apk add --no-cache make build-base libpcap-dev openssh-client tcpdump

WORKDIR /app
COPY . /app

RUN go mod download
RUN go build .

ENTRYPOINT ["./pcap-broker"]
