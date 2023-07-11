package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/google/shlex"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type PcapClient struct {
	writer       *pcapgo.Writer
	totalPackets uint64
	totalBytes   uint64
}

func lookupHostnameWithTimeout(addr net.Addr, timeout time.Duration) (string, string, error) {
	// Extract the IP address and port from the Addr object
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return "", "", fmt.Errorf("unsupported address type: %T", addr)
	}
	ip := tcpAddr.IP.String()
	port := fmt.Sprintf("%d", tcpAddr.Port)

	// Create a new context with the given timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create a new Resolver and perform the IP lookup with the given context
	resolver := net.Resolver{}
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil {
		return "", "", err
	}
	if len(names) == 0 {
		return "", "", fmt.Errorf("no hostnames found for %s", ip)
	}

	// Return the first IP address found and the original port
	return names[0], port, nil
}

func main() {

	pcapCommand := flag.String("cmd", "", "command to execute for pcap data (eg: tcpdump -i eth0 -n --immediate-mode -s 65535 -U -w -)")
	listenAddress := flag.String("listen", "", "listen address for pcap-over-ip (eg: localhost:4242)")
	noReverseLookup := flag.Bool("n", false, "disable reverse lookup of connecting PCAP-over-IP client IP address")
	flag.Parse()

	if *pcapCommand == "" {
		*pcapCommand = os.Getenv("PCAP_COMMAND")
		if *pcapCommand == "" {
			log.Fatalf("Error: PCAP_COMMAND or -cmd not set, see --help for usage")
		}
	}

	if *listenAddress == "" {
		*listenAddress = os.Getenv("LISTEN_ADDRESS")
		if *listenAddress == "" {
			*listenAddress = "localhost:4242"
		}
	}

	log.Printf("config PCAP_COMMAND = %q", *pcapCommand)
	log.Printf("config LISTEN_ADDRESS = %q", *listenAddress)

	// Create connections to PcapClient map
	var connMap = map[net.Conn]PcapClient{}

	// Create a pipe for the command to write to, will be read by pcap.OpenOfflineFile
	rStdout, wStdout, err := os.Pipe()
	if err != nil {
		log.Fatal(err)
	}

	// Important or these will eventually be garbage collected and the pipe will close
	defer rStdout.Close()
	defer wStdout.Close()

	// Acquire pcap data
	args, err := shlex.Split(*pcapCommand)
	if err != nil {
		log.Fatal(err)
	}
	cmd := exec.Command(args[0], args[1:]...)
	log.Printf("cmd = %v", cmd.Args)
	cmd.Stdout = wStdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("PID %v", cmd.Process.Pid)
	go func() {
		err := cmd.Wait()
		if err != nil {
			log.Fatal("Process exited with error: ", err)
		}
		log.Printf("process exited")
		os.Exit(0)
	}()

	// Read from process stdout pipe
	handle, err := pcap.OpenOfflineFile(rStdout)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true
	go processPackets(packetSource, connMap)

	log.Printf("PCAP-over-IP server listening on %v", *listenAddress)
	l, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		if *noReverseLookup {
			log.Printf("PCAP-over-IP connection from %v", conn.RemoteAddr())
		} else {
			ip, port, err := lookupHostnameWithTimeout(conn.RemoteAddr(), 100*time.Millisecond)
			if err != nil {
				log.Printf("PCAP-over-IP connection from %v", conn.RemoteAddr())
			} else {
				log.Printf("PCAP-over-IP connection from %s:%s", ip, port)
			}
		}

		writer := pcapgo.NewWriter(conn)

		// Write pcap header
		writer.WriteFileHeader(65535, handle.LinkType())

		// add connection to map
		connMap[conn] = PcapClient{writer: writer}
	}
}

func processPackets(packetSource *gopacket.PacketSource, connMap map[net.Conn]PcapClient) {
	for packet := range packetSource.Packets() {
		for conn, stats := range connMap {
			ci := packet.Metadata().CaptureInfo
			err := stats.writer.WritePacket(ci, packet.Data())
			if err != nil {
				log.Println(err)
				delete(connMap, conn)
				conn.Close()
				continue
			}
			stats.totalPackets += 1
			stats.totalBytes += uint64(ci.CaptureLength)
		}
	}
}
