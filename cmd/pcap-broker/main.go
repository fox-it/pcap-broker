package pcap_broker

import (
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/google/shlex"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type PcapClient struct {
	writer       *pcapgo.Writer
	totalPackets uint64
	totalBytes   uint64
}

var (
	pcapCommand     = flag.String("cmd", "", "command to execute for pcap data (eg: tcpdump -i eth0 -n --immediate-mode -s 65535 -U -w -)")
	listenAddress   = flag.String("listen", "", "listen address for pcap-over-ip (eg: localhost:4242)")
	noReverseLookup = flag.Bool("n", false, "disable reverse lookup of connecting PCAP-over-IP client IP address")
	debug           = flag.Bool("debug", false, "enable debug logging")
	json            = flag.Bool("json", false, "enable json logging")
)

func Main() {
	flag.Parse()

	if !*json {
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC3339,
		})
	}

	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	if *pcapCommand == "" {
		*pcapCommand = os.Getenv("PCAP_COMMAND")
		if *pcapCommand == "" {
			log.Fatal().Msg("PCAP_COMMAND or -cmd not set, see --help for usage")
		}
	}

	if *listenAddress == "" {
		*listenAddress = os.Getenv("LISTEN_ADDRESS")
		if *listenAddress == "" {
			*listenAddress = "localhost:4242"
		}
	}

	log.Debug().Str("pcapCommand", *pcapCommand).Send()
	log.Debug().Str("listenAddress", *listenAddress).Send()

	ctx, cancelFunc := signal.NotifyContext(context.Background(), os.Interrupt)

	// Create connections to PcapClient map
	connMap := map[net.Conn]PcapClient{}

	// Create a pipe for the command to write to, will be read by pcap.OpenOfflineFile
	rStdout, wStdout, err := os.Pipe()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create pipe")
	}

	// Acquire pcap data
	args, err := shlex.Split(*pcapCommand)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse PCAP_COMMAND")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	log.Debug().Strs("args", args).Send()

	cmd.Stdout = wStdout
	cmd.Stderr = log.Logger.Hook(zerolog.HookFunc(func(e *zerolog.Event, level zerolog.Level, msg string) {
		e.Str(zerolog.LevelFieldName, zerolog.LevelTraceValue)
	}))

	err = cmd.Start()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to start command")
	}

	log.Debug().Int("pid", cmd.Process.Pid).Msg("started process")

	// close context on process exit
	go func() {
		err := cmd.Wait()
		if err != nil {
			log.Fatal().Err(err).Msg("command exited with error")
		}
		cancelFunc()
	}()

	// Read from process stdout pipe
	handle, err := pcap.OpenOfflineFile(rStdout)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open pcap file")
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true

	go processPackets(ctx, packetSource, connMap)

	log.Info().Msgf("PCAP-over-IP server listening on %v. press CTRL-C to exit", *listenAddress)

	config := net.ListenConfig{}
	l, err := config.Listen(ctx, "tcp", *listenAddress)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to listen")
	}

	// close listener on context cancel
	go func() {
		<-ctx.Done()
		cancelFunc()
		err := l.Close()
		if err != nil {
			log.Err(err).Msg("failed to close listener")
		}
	}()

	for {
		conn, err := l.Accept()
		if err != nil && ctx.Err() == nil {
			log.Fatal().Err(err).Msg("failed to accept connection")
		} else if errors.Is(ctx.Err(), context.Canceled) {
			break
		}

		if *noReverseLookup {
			log.Info().Msgf("PCAP-over-IP connection from %v", conn.RemoteAddr())
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			ipAddr := conn.RemoteAddr().(*net.TCPAddr).IP.String()
			names, _ := net.DefaultResolver.LookupAddr(ctx, ipAddr)
			if len(names) == 0 {
				log.Info().Msgf("PCAP-over-IP connection from %v", conn.RemoteAddr())
			} else {
				log.Info().Msgf("PCAP-over-IP connection from %v (%v)", conn.RemoteAddr(), names[0])
			}
		}

		writer := pcapgo.NewWriter(conn)

		// Write pcap header
		err = writer.WriteFileHeader(65535, handle.LinkType())
		if err != nil {
			log.Err(err).Msg("failed to write pcap header")
			err := conn.Close()
			if err != nil {
				log.Err(err).Msg("failed to close connection")
			}

			continue
		}

		// add connection to map
		connMap[conn] = PcapClient{writer: writer}
	}

	log.Info().Msg("PCAP-over-IP server exiting")

	err = rStdout.Close()
	if err != nil {
		log.Err(err).Msg("failed to close read pipe")
	}

	err = wStdout.Close()
	if err != nil {
		log.Err(err).Msg("failed to close write pipe")
	}
}

func processPackets(
	ctx context.Context,
	packetSource *gopacket.PacketSource,
	connMap map[net.Conn]PcapClient,
) {
	for packet := range packetSource.Packets() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		for conn, stats := range connMap {
			ci := packet.Metadata().CaptureInfo
			err := stats.writer.WritePacket(ci, packet.Data())
			if err != nil {
				log.Err(err).Msg("failed to write packet to connection")
				delete(connMap, conn)
				err := conn.Close()
				if err != nil {
					log.Err(err).Msg("failed to close connection")
				}
				continue
			}
			stats.totalPackets += 1
			stats.totalBytes += uint64(ci.CaptureLength)
		}
	}
}
