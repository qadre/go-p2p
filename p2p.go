package p2p

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p"
	core "github.com/libp2p/go-libp2p-core"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	discovery "github.com/libp2p/go-libp2p-discovery"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multihash"
	"go.uber.org/zap"
)

// HandleBroadcast defines the callback function triggered when a broadcast message reaches a host
type HandleBroadcast func(ctx context.Context, data []byte) error

// HandleUnicast defines the callback function triggered when a unicast message reaches a host
type HandleUnicast func(ctx context.Context, w io.Writer, data []byte) error

// Config enumerates the configs required by a host
type Config struct {
	HostName         string        `yaml:"hostName"`
	Port             int           `yaml:"port"`
	ExternalHostName string        `yaml:"externalHostName"`
	ExternalPort     int           `yaml:"externalPort"`
	SecureIO         bool          `yaml:"secureIO"`
	Gossip           bool          `yaml:"gossip"`
	ConnectTimeout   time.Duration `yaml:"connectTimeout"`
	MasterKey        string        `yaml:"masterKey"`
	PrivateKey       string
	ConnLowWater     int           `yaml:"connLowWater"`
	ConnHighWater    int           `yaml:"connHighWater"`
	ConnGracePeriod  time.Duration `yaml:"connGracePeriod"`
	Bootnode         bool
}

// DefaultConfig is a set of default configs
var DefaultConfig = Config{
	HostName:         "127.0.0.1",
	Port:             7000,
	ExternalHostName: "",
	ExternalPort:     7000,
	SecureIO:         false,
	Gossip:           false,
	ConnectTimeout:   time.Minute,
	MasterKey:        "",
	PrivateKey:       "",
	ConnLowWater:     200,
	ConnHighWater:    500,
	ConnGracePeriod:  0,
}

// Option defines the option function to modify the config for a host
type Option func(cfg *Config) error

// HostName is the option to override the host name or IP address
func HostName(hostName string) Option {
	return func(cfg *Config) error {
		cfg.HostName = hostName
		return nil
	}
}

// Port is the option to override the port number
func Port(port int) Option {
	return func(cfg *Config) error {
		cfg.Port = port
		return nil
	}
}

// ExternalHostName is the option to set the host name or IP address seen from external
func ExternalHostName(externalHostName string) Option {
	return func(cfg *Config) error {
		cfg.ExternalHostName = externalHostName
		return nil
	}
}

// ExternalPort is the option to set the port number seen from external
func ExternalPort(externalPort int) Option {
	return func(cfg *Config) error {
		cfg.ExternalPort = externalPort
		return nil
	}
}

// SecureIO is to indicate using secured I/O
func SecureIO() Option {
	return func(cfg *Config) error {
		cfg.SecureIO = true
		return nil
	}
}

// Gossip is to indicate using gossip protocol
func Gossip() Option {
	return func(cfg *Config) error {
		cfg.Gossip = true
		return nil
	}
}

// BootNode determines whether this libp2p host is a bootnode.
func BootNode() Option {
	return func(cfg *Config) error {
		cfg.Bootnode = true
		return nil
	}
}

// ConnectTimeout is the option to override the connect timeout
func ConnectTimeout(timout time.Duration) Option {
	return func(cfg *Config) error {
		cfg.ConnectTimeout = timout
		return nil
	}
}

// MasterKey is to determine network identifier
func MasterKey(masterKey string) Option {
	return func(cfg *Config) error {
		cfg.MasterKey = masterKey
		return nil
	}
}

// PrivateKey is to determine private key to use for addressing
func PrivateKey(privateKey string) Option {
	return func(cfg *Config) error {
		cfg.PrivateKey = privateKey
		return nil
	}
}

// WithConnectionManagerConfig set configuration for connection manager.
func WithConnectionManagerConfig(lo, hi int, grace time.Duration) Option {
	return func(cfg *Config) error {
		cfg.ConnLowWater = lo
		cfg.ConnHighWater = hi
		cfg.ConnGracePeriod = grace
		return nil
	}
}

// HostOperator defines the peer to peer functionality available
type HostOperator interface {
	AddBroadcastPubSub(topic string, callback HandleBroadcast) error
	AddUnicastPubSub(topic string, callback HandleUnicast) error
	Addresses() []multiaddr.Multiaddr
	Broadcast(topic string, data []byte) error
	Close() error
	ConnectWithMultiaddr(ctx context.Context, ma multiaddr.Multiaddr) error
	Connect(ctx context.Context, target peer.AddrInfo) error
	Discover(ctx context.Context, dht *dht.IpfsDHT, rendezvous string)
	DHT() *dht.IpfsDHT
	HostIdentity() string
	Info() peer.AddrInfo
	JoinOverlay(ctx context.Context)
	Neighbors(ctx context.Context) ([]peer.AddrInfo, error)
	OverlayIdentity() string
	Unicast(ctx context.Context, target peer.AddrInfo, topic string, data []byte) error
}

// Host is the main struct that represents a host that communicating with the rest of the P2P networks
type Host struct {
	host   core.Host
	cfg    Config
	topics map[string]*pubsub.Topic
	kad    *dht.IpfsDHT
	kadKey cid.Cid
	pubSub *pubsub.PubSub
	close  chan interface{}
	ctx    context.Context
}

// NewHost constructs a host struct
func NewHost(ctx context.Context, options ...Option) (*Host, error) {
	cfg := DefaultConfig
	for _, option := range options {
		if err := option(&cfg); err != nil {
			return nil, err
		}
	}
	ip, err := EnsureIPv4(cfg.HostName)
	if err != nil {
		return nil, err
	}
	masterKey := cfg.MasterKey
	// If ID is not given use network address instead
	if masterKey == "" {
		masterKey = fmt.Sprintf("%s:%d", ip, cfg.Port)
	}

	var sk crypto.PrivKey
	if cfg.PrivateKey == "" {
		sk, _, err = generateKeyPair()
		if err != nil {
			return nil, err
		}
	} else {
		var keyBytes []byte
		keyBytes, err = base64.StdEncoding.DecodeString(cfg.PrivateKey)
		if err != nil {
			return nil, err
		}

		sk, err = crypto.UnmarshalEd25519PrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}
	}

	var extMultiAddr multiaddr.Multiaddr
	// Set external address and replace private key it external host name is given
	if cfg.ExternalHostName != "" {
		var extIP string
		extIP, err = EnsureIPv4(cfg.ExternalHostName)
		if err != nil {
			return nil, err
		}
		masterKey = cfg.MasterKey
		// If ID is not given use network address instead
		if masterKey == "" {
			masterKey = fmt.Sprintf("%s:%d", cfg.ExternalHostName, cfg.ExternalPort)
		}

		sk, _, err = generateKeyPair()
		if err != nil {
			return nil, err
		}
		extMultiAddr, err = multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", extIP, cfg.ExternalPort))
		if err != nil {
			return nil, err
		}
	}
	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/%s/tcp/%d", ip, cfg.Port)),
		libp2p.AddrsFactory(func(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			if extMultiAddr != nil {
				return append(addrs, extMultiAddr)
			}
			return addrs
		}),
		libp2p.Identity(sk),
		libp2p.DefaultTransports,
		libp2p.DefaultMuxers,
	}
	if !cfg.SecureIO {
		opts = append(opts, libp2p.NoSecurity)
	}

	host, err := libp2p.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	var dhtOpts []dht.Option
	if cfg.Bootnode {
		zap.S().Debug("configuring server mode for DHT on bootnode")
		dhtOpts = append(dhtOpts, dht.Mode(dht.ModeServer))
	}

	kad, err := dht.New(ctx, host, dhtOpts...)
	if err != nil {
		return nil, err
	}

	if err = kad.Bootstrap(ctx); err != nil {
		return nil, err
	}

	newPubSub, err := pubsub.NewFloodSub(context.Background(), host)
	if err != nil {
		return nil, err
	}
	if cfg.Gossip {
		newPubSub, err = pubsub.NewGossipSub(context.Background(), host)
		if err != nil {
			return nil, err
		}
	}

	v1b := cid.V1Builder{Codec: cid.Raw, MhType: multihash.SHA2_256}
	cid, err := v1b.Sum([]byte(masterKey))
	if err != nil {
		return nil, err
	}

	myHost := Host{
		host:   host,
		cfg:    cfg,
		topics: make(map[string]*pubsub.Topic),
		kad:    kad,
		kadKey: cid,
		pubSub: newPubSub,
		close:  make(chan interface{}),
		ctx:    ctx,
	}

	addrs := make([]string, 0)
	for _, ma := range myHost.Addresses() {
		addrs = append(addrs, ma.String())
	}
	Logger().Info("p2p host started.",
		zap.Strings("address", addrs),
		zap.Bool("secureIO", myHost.cfg.SecureIO),
		zap.Bool("gossip", myHost.cfg.Gossip))

	return &myHost, nil
}

// DHT returns the DHT of the host.
func (h *Host) DHT() *dht.IpfsDHT {
	return h.kad
}

// Discover discovers peers on the network.
func (h *Host) Discover(ctx context.Context, dht *dht.IpfsDHT, rendezvous string) {
	zap.S().Infof("attempting to discovery peers on %s", rendezvous)
	var routingDiscovery = discovery.NewRoutingDiscovery(dht)
	discovery.Advertise(ctx, routingDiscovery, rendezvous)

	ticker := time.NewTimer(time.Second * 1)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			peers, err := discovery.FindPeers(ctx, routingDiscovery, rendezvous)
			if err != nil {
				zap.S().Fatal(err)
			}
			zap.S().Debugf("found %d peers in network", len(peers))

			for _, p := range peers {
				if p.ID.Pretty() == h.HostIdentity() {
					continue
				}

				if h.host.Network().Connectedness(p.ID) != network.Connected {
					_, err = h.host.Network().DialPeer(ctx, p.ID)
					zap.S().Infof("Connected to peer %s\n", p.ID.Pretty())
					if err != nil {
						continue
					}
				}
			}
		}
	}
}

// JoinOverlay triggers the host to join the DHT overlay
func (h *Host) JoinOverlay(ctx context.Context) {
	routingDiscovery := discovery.NewRoutingDiscovery(h.kad)
	discovery.Advertise(ctx, routingDiscovery, h.kadKey.String())
}

// AddUnicastPubSub adds a unicast topic that the host will pay attention to
func (h *Host) AddUnicastPubSub(topic string, callback HandleUnicast) error {
	if _, ok := h.topics[topic]; ok {
		zap.S().Warnf("topic %s already exists, skipping", topic)
		return nil
	}

	h.host.SetStreamHandler(core.ProtocolID(topic), func(stream network.Stream) {
		defer func() {
			if err := stream.Close(); err != nil {
				Logger().Error("Error when closing a unicast stream.", zap.Error(err))
			}
		}()

		data, err := ioutil.ReadAll(stream)
		if err != nil {
			Logger().Error("Error when subscribing a unicast message.", zap.Error(err))
			return
		}
		ctx := context.WithValue(context.Background(), unicastCtxKey{}, stream)
		if err := callback(ctx, stream, data); err != nil {
			Logger().Error("Error when processing a unicast message.", zap.Error(err))
		}
	})

	// reset the topic so we can receive more than 1 unicast msg
	h.topics[topic] = nil
	return nil
}

// AddBroadcastPubSub adds a broadcast topic that the host will pay attention to. This need to be called before using
// Connect/JoinOverlay. Otherwise, pubsub may not be aware of the existing overlay topology
func (h *Host) AddBroadcastPubSub(topic string, callback HandleBroadcast) error {
	t, err := h.pubSub.Join(topic)
	if err != nil {
		return err
	}

	topicSub, err := t.Subscribe()
	if err != nil {
		return err
	}

	h.topics[topic] = t
	go func() {
		for {
			select {
			case <-h.close:
				return
			default:
				msg, err := topicSub.Next(h.ctx)
				if err != nil {
					Logger().Error(
						"Error when subscribing to broadcast",
						zap.Error(err), zap.String("topic", topic))
					continue
				}
				ctx := context.WithValue(h.ctx, broadcastCtxKey{}, msg)
				if err := callback(ctx, msg.Data); err != nil {
					Logger().Error("Error when processing a broadcast message.", zap.Error(err))
				}
			}
		}
	}()

	return nil
}

// ConnectWithMultiaddr connects a peer given the multi address
func (h *Host) ConnectWithMultiaddr(ctx context.Context, ma multiaddr.Multiaddr) error {
	target, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return err
	}
	if err := h.host.Connect(ctx, *target); err != nil {
		return err
	}
	Logger().Debug(
		"P2P peer connected.",
		zap.String("multiAddress", ma.String()),
	)

	return nil
}

// Connect connects a peer.
func (h *Host) Connect(ctx context.Context, target peer.AddrInfo) error {
	if err := h.host.Connect(ctx, target); err != nil {
		return err
	}
	Logger().Debug(
		"P2P peer connected.",
		zap.String("peer", fmt.Sprintf("%+v", target)),
	)

	return nil
}

// Broadcast sends a message to the hosts who subscribe the topic
func (h *Host) Broadcast(topic string, data []byte) error {
	t, ok := h.topics[topic]
	if !ok {
		zap.S().Warnf("topic %s doesnt exist, unable to broadcast msg", topic)
		return nil
	}
	zap.S().Debugf("broadcasting to %d peers", len(h.host.Peerstore().Peers()))
	return t.Publish(context.Background(), data)
}

// Unicast sends a message to a peer on the given address
func (h *Host) Unicast(ctx context.Context, target peer.AddrInfo, topic string, data []byte) error {
	if err := h.Connect(ctx, target); err != nil {
		return err
	}

	stream, err := h.host.NewStream(ctx, target.ID, core.ProtocolID(topic))
	if err != nil {
		return err
	}

	defer func() { err = stream.Close() }()
	if _, err = stream.Write(data); err != nil {
		return err
	}

	return nil
}

// HostIdentity returns the host identity string
func (h *Host) HostIdentity() string { return h.host.ID().Pretty() }

// OverlayIdentity returns the overlay identity string
func (h *Host) OverlayIdentity() string { return h.kadKey.String() }

// Addresses returns the multi address
func (h *Host) Addresses() []multiaddr.Multiaddr {
	hostID, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ipfs/%s", h.HostIdentity()))
	addrs := make([]multiaddr.Multiaddr, 0)
	for _, addr := range h.host.Addrs() {
		addrs = append(addrs, addr.Encapsulate(hostID))
	}

	return addrs
}

// Info returns host's peer info.
func (h *Host) Info() peer.AddrInfo {
	return peer.AddrInfo{ID: h.host.ID(), Addrs: h.host.Addrs()}
}

// Neighbors returns the closest peer addresses
func (h *Host) Neighbors(ctx context.Context) ([]peer.AddrInfo, error) {
	peers := h.host.Peerstore().Peers()
	dedupedPeers := make(map[string]peer.ID)
	for _, p := range peers {
		idStr := p.Pretty()
		if idStr == h.host.ID().Pretty() || idStr == "" {
			continue
		}
		dedupedPeers[idStr] = p
	}
	neighbors := make([]peer.AddrInfo, 0)
	for _, p := range dedupedPeers {
		neighbors = append(neighbors, h.kad.FindLocal(p))
	}

	return neighbors, nil
}

// Close closes the host
func (h *Host) Close() error {
	close(h.close)

	if err := h.kad.Close(); err != nil {
		return err
	}
	if err := h.host.Close(); err != nil {
		return err
	}
	return nil
}

// generateKeyPair generates the public key and private key by network address
func generateKeyPair() (crypto.PrivKey, crypto.PubKey, error) {
	return crypto.GenerateKeyPairWithReader(crypto.Ed25519, 2048, rand.Reader)
}
