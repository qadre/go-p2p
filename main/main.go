package main

import (
	"context"
	"flag"
	"github.com/libp2p/go-libp2p-core/network"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	p2p "github.com/qadre/go-p2p"
	"go.uber.org/zap"
)

var (
	hostName      string
	port          int
	extHostName   string
	extPort       int
	secureIO      bool
	gossip        bool
	bootstrapAddr string
	frequency     int64
	slowStart     int64
	broadcast     bool
)

var (
	receiveCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "broadcast_message_receive_audit",
			Help: "Broadcast message_receive_audit",
		},
		[]string{"from", "to"},
	)
	sendCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "broadcast_message_send_audit",
			Help: "Broadcast message_send_audit",
		},
		[]string{"from"},
	)
)

func init() {
	flag.StringVar(&hostName, "host", "127.0.0.1", "Host name or IP address")
	flag.IntVar(&port, "port", 30001, "Port number")
	flag.StringVar(&extHostName, "exthost", "", "Host name or IP address seen from external")
	flag.IntVar(&extPort, "extport", 30001, "Port number seen from external")
	flag.BoolVar(&secureIO, "secureio", false, "Use secure I/O")
	flag.BoolVar(&gossip, "gossip", false, "Use Gossip protocol")
	flag.StringVar(&bootstrapAddr, "bootstrapaddr", "", "Bootstrap node address")
	flag.Int64Var(&frequency, "frequency", 1000, "How frequent (in ms) to send a message")
	flag.Int64Var(&slowStart, "slowstart", 10, "Wait some time (in sec) before sending a message")
	flag.BoolVar(&broadcast, "broadcast", true, "Broadcast or unicast the messages only to the neighbors")
	flag.Parse()

	prometheus.MustRegister(receiveCounter)
	prometheus.MustRegister(sendCounter)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(":8080", mux); err != nil {
			p2p.Logger().Error("Error when serving performance profiling data.", zap.Error(err))
		}
	}()
}

func main() {
	if ipFromEnv, ok := os.LookupEnv("P2P_IP"); ok {
		hostName = ipFromEnv
	}
	if portFromEnv, ok := os.LookupEnv("P2P_PORT"); ok {
		portIntFromEvn, err := strconv.Atoi(portFromEnv)
		if err != nil {
			p2p.Logger().Panic("Error when parsing port number from ENV.", zap.Error(err))
		}
		port = portIntFromEvn

	}

	options := []p2p.Option{
		p2p.HostName(hostName),
		p2p.Port(port),
		p2p.ExternalHostName(extHostName),
		p2p.ExternalPort(extPort),
	}

	if gossip {
		options = append(options, p2p.Gossip())
	}
	options = append(options, p2p.MasterKey("123"))
	options = append(options, p2p.SecureIO())

	host, err := p2p.NewHost(context.Background(), options...)
	if err != nil {
		p2p.Logger().Panic("Error when instantiating a host.", zap.Error(err))
	}

	audit := make(map[string]int)
	var mutex sync.Mutex

	// nolint
	HandleMsg := func(_ context.Context, data []byte) error {
		mutex.Lock()
		defer mutex.Unlock()

		id := string(data)
		audit[id] += 1
		if audit[id]%100 == 0 {
			p2p.Logger().Info("Received messages.", zap.String("id", id), zap.Int("num", audit[id]))
		}
		receiveCounter.WithLabelValues(id, host.HostIdentity()).Inc()
		return nil
	}
	if err := host.AddBroadcastPubSub("measurement", HandleMsg); err != nil {
		p2p.Logger().Panic("Error when adding broadcast pubsub.", zap.Error(err))
	}
	if err := host.AddUnicastPubSub("measurement", func(stream network.Stream) {
		bytes, err := ioutil.ReadAll(stream)
		if err != nil {
			panic(err)
		}
		err = HandleMsg(context.Background(), bytes)
		if err != nil {
			panic(err)
		}
	}); err != nil {
		p2p.Logger().Panic("Error when adding unicast pubsub", zap.Error(err))
	}

	if bootstrapAddr != "" {
		ma, err := multiaddr.NewMultiaddr(bootstrapAddr)
		if err != nil {
			p2p.Logger().Panic("Error when parsing to the bootstrap node address", zap.Error(err))
		}
		if err := host.ConnectWithMultiaddr(context.Background(), ma); err != nil {
			p2p.Logger().Panic("Error when connecting to the bootstrap node", zap.Error(err))
		}
		host.JoinOverlay(context.Background())
	}

	tick := time.Tick(time.Duration(frequency) * time.Millisecond)
	for range tick {
		var err error
		if broadcast {
			err = host.Broadcast("measurement", []byte(host.HostIdentity()))
		} else {
			var neighbors []peer.AddrInfo
			neighbors, err = host.Neighbors(context.Background())
			if err != nil {
				p2p.Logger().Error("Error when getting neighbors.", zap.Error(err))
			}

			for _, neighbor := range neighbors {
				_, err = host.Unicast(
					context.Background(),
					neighbor,
					"measurement",
					[]byte(host.HostIdentity()),
				)
				p2p.Logger().Panic("Error when performing unicase measurement on neighbour", zap.Error(err))
			}
		}

		if err != nil {
			p2p.Logger().Error("Error when broadcasting a message.", zap.Error(err))
		} else {
			sendCounter.WithLabelValues(host.HostIdentity()).Inc()
		}
	}
}
