package server

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
)

const (
	// https://datatracker.ietf.org/doc/html/rfc5881
	//   The source port MUST be in the range 49152 through 65535
	bfdSourcePortMin = 49152
	bfdSourcePortMax = 65535

	// Some default values
	defaultMultiplier = 3
	defaultRxInterval = 1000 * time.Millisecond
	defaultTxInterval = 1000 * time.Millisecond

	// https://datatracker.ietf.org/doc/html/rfc5880#section-6.8.3
	//   When bfd.SessionState is not Up, the system MUST set
	//   bfd.DesiredMinTxInterval to a value of not less than one second
	//   (1,000,000 microseconds).
	bfdSlowTxInterval = time.Second
)

type bfdPeerStats struct {
	rxPacket             atomic.Uint64
	txPacket             atomic.Uint64
	txDrop               atomic.Uint64
	txError              atomic.Uint64
	invalidDiscriminator atomic.Uint64
	invalidMultiplier    atomic.Uint64
	expired              atomic.Uint64
}

type bfdPeer struct {
	peerState     peerState
	logger        *slog.Logger
	peerAddress   netip.Addr
	peerPort      int
	bindInterface string

	udpClient *net.UDPConn

	expiryInterval time.Duration

	state             atomic.Int32
	myDiscriminator   uint32
	yourDiscriminator uint32
	multiplier        uint8
	rxInterval        time.Duration
	txInterval        time.Duration

	// desiredMinTx is the RFC's bfd.DesiredMinTxInterval: the value advertised in
	// transmitted packets and one of the two terms of the transmit interval (see
	// effectiveTxInterval). txInterval keeps its current meaning: the configured
	// value, immutable after construction. Confined to the peer's loop goroutine, or
	// to NewBfdPeer before that goroutine starts — same discipline as
	// yourDiscriminator/expiryInterval, so no atomics.
	desiredMinTx time.Duration
	// remoteMinRxInterval is the RFC's bfd.RemoteMinRxInterval (Section 6.8.1): the
	// peer's advertised Required Min RX Interval, the other term of the transmit
	// interval. Same confinement as desiredMinTx.
	remoteMinRxInterval time.Duration
	// lastTx is when tx() last ran (peer creation time until the first run). It
	// anchors the pacing deadline; see armTx. Same confinement as desiredMinTx.
	lastTx time.Time
	// pollSequence is true while a Poll Sequence is in flight: the P bit is set on
	// periodic transmissions until a Final is received. Same confinement as desiredMinTx.
	pollSequence bool

	eventStart    *time.Ticker
	eventRxPacket chan *bfd.BFDHeader
	eventTx       *time.Timer
	eventExpiry   *time.Ticker
	eventShutdown chan struct{}
	shutdownOnce  sync.Once
	shutdownWait  sync.WaitGroup
	stopped       atomic.Bool

	stats bfdPeerStats
}

func NewBfdPeer(ps peerState, logger *slog.Logger, peerAddress netip.Addr, config oc.BfdConfig, bindInterface string) *bfdPeer {
	peerPort := int(config.Port)
	if peerPort == 0 {
		peerPort = BfdServerPort
	}

	p := &bfdPeer{
		peerState:     ps,
		logger:        logger,
		peerAddress:   peerAddress,
		peerPort:      peerPort,
		bindInterface: bindInterface,

		myDiscriminator: randomBFDMyDiscriminator(),
		multiplier:      defaultMultiplier,
		rxInterval:      defaultRxInterval,
		txInterval:      defaultTxInterval,
		// RFC 5880 Section 6.8.1: bfd.RemoteMinRxInterval MUST be initialized
		// to 1. Not the Go zero value: Section 6.8.7 reserves zero to mean the
		// peer wants no periodic packets, which this implementation does not
		// support. The distinction is currently inert — desiredMinTx is always
		// at least 1 microsecond — but keeps the variable faithful to the RFC
		// so zero can later be given its Section 6.8.7 meaning.
		remoteMinRxInterval: time.Microsecond,

		eventStart:    time.NewTicker(time.Second),
		eventRxPacket: make(chan *bfd.BFDHeader, 1),
		eventShutdown: make(chan struct{}),
	}

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_DOWN))

	if config.DetectionMultiplier > 0 {
		p.multiplier = config.DetectionMultiplier
	}

	if config.RequiredMinimumReceive > 0 {
		p.rxInterval = time.Duration(config.RequiredMinimumReceive) * time.Microsecond
	}

	if config.DesiredMinimumTxInterval > 0 {
		p.txInterval = time.Duration(config.DesiredMinimumTxInterval) * time.Microsecond
	}

	p.expiryInterval = time.Duration(p.multiplier) * p.rxInterval

	// The session starts Down, so the 6.8.3 floor applies from construction. This is
	// the initial value, not a change, so set it directly rather than through
	// setDesiredMinTx: there is no Poll Sequence to initiate for it.
	p.desiredMinTx = max(p.txInterval, bfdSlowTxInterval)
	p.lastTx = time.Now()
	p.eventTx = time.NewTimer(p.jitteredTxInterval())

	p.eventExpiry = time.NewTicker(p.expiryInterval)
	p.eventExpiry.Stop()

	p.shutdownWait.Add(1)
	go p.loop()
	return p
}

func (p *bfdPeer) Rx(packet *bfd.BFDHeader) bool {
	if p.stopped.Load() {
		return false
	}

	select {
	case p.eventRxPacket <- packet:
		return true
	case <-p.eventShutdown:
		return false
	default:
		return false
	}
}

func (p *bfdPeer) Stop() {
	p.shutdownOnce.Do(func() {
		p.stopped.Store(true)
		close(p.eventShutdown)
		p.shutdownWait.Wait()
	})
}

func (p *bfdPeer) loop() {
	defer p.shutdownWait.Done()

	for {
		select {
		case <-p.eventStart.C:
			success := p.start()
			if success {
				p.eventStart.Stop()
			}
		case bfdPacket := <-p.eventRxPacket:
			p.rxPacket(bfdPacket)
		case <-p.eventTx.C:
			p.tx()
		case <-p.eventExpiry.C:
			p.expiry()
		case <-p.eventShutdown:
			p.shutdown()
			return
		}
	}
}

func (p *bfdPeer) start() bool {
	if p.udpClient == nil {
		p.startClient()
	}

	return p.udpClient != nil
}

func (p *bfdPeer) stop() {
	if p.udpClient == nil {
		return
	}

	err := p.udpClient.Close()
	if err != nil {
		p.logger.Warn("Can't close UDP",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
		)
	}

	p.udpClient = nil

	p.logger.Debug("BFD client is stopped",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)
}

// remoteUDPAddr builds the BFD peer's UDP address. The zone is preserved so a link-local peer
// (fe80::…%iface, as used by unnumbered single-hop BFD per RFC 5881) can be reached — dialing a
// link-local address without its zone fails.
func (p *bfdPeer) remoteUDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   p.peerAddress.AsSlice(),
		Zone: p.peerAddress.Zone(),
		Port: p.peerPort,
	}
}

func (p *bfdPeer) startClient() {
	localAddress := &net.UDPAddr{
		Port: randRange(bfdSourcePortMin, bfdSourcePortMax),
	}

	remoteAddress := p.remoteUDPAddr()

	var err error

	dialer := net.Dialer{
		LocalAddr: localAddress,
		Control: func(network, address string, c syscall.RawConn) error {
			if p.bindInterface != "" {
				return netutils.SetBindToDevSockopt(c, p.bindInterface)
			}

			return nil
		},
	}

	conn, err := dialer.Dial("udp", remoteAddress.String())
	if err != nil {
		p.logger.Warn("Can't dial UDP",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
			slog.String("LocalAddress", localAddress.String()),
			slog.String("RemoteAddress", remoteAddress.String()),
			slog.Any("Error", err),
		)

		return
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		p.logger.Warn("Can't dial UDP",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
			slog.String("LocalAddress", localAddress.String()),
			slog.String("RemoteAddress", remoteAddress.String()),
			slog.Any("Error", "connection is not a UDP connection"),
		)

		return
	}

	p.udpClient = udpConn

	// https://datatracker.ietf.org/doc/html/rfc5881
	//   If BFD authentication is not in use on a session, all BFD Control
	//   packets for the session MUST be sent with a Time to Live (TTL) or Hop
	//   Limit value of 255
	err = netutils.SetUDPTTLSockopt(p.udpClient, 255)
	if err != nil {
		p.logger.Error("Can't set TTL to 255",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
			slog.String("LocalAddress", localAddress.String()),
			slog.String("RemoteAddress", remoteAddress.String()),
			slog.Any("Error", err),
		)

		err = p.udpClient.Close()
		if err != nil {
			p.logger.Warn("Can't close UDP",
				slog.String("Topic", "bfd"),
				slog.String("Peer", p.peerAddress.String()),
			)
		}

		p.udpClient = nil
		return
	}

	p.logger.Debug("BFD client is started",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
		slog.String("LocalAddress", localAddress.String()),
		slog.String("RemoteAddress", remoteAddress.String()),
	)
}

// effectiveTxInterval is the interval GoBGP actually transmits at.
//
// RFC 5880 Section 6.8.7: a system MUST NOT transmit BFD Control packets at an
// interval less than the larger of bfd.DesiredMinTxInterval and
// bfd.RemoteMinRxInterval. desiredMinTx carries the Section 6.8.3 not-Up floor,
// so the floor reaches the pacing through it.
func (p *bfdPeer) effectiveTxInterval() time.Duration {
	return max(p.desiredMinTx, p.remoteMinRxInterval)
}

// armTx re-arms the transmit timer at the absolute pacing deadline
// lastTx + jitteredTxInterval, or transmits at once if that deadline has
// already passed. Every change to either term of the interval goes through here.
// The jitter is drawn afresh on each call, so under a stream of received packets
// the deadline wanders within the 75%-100% window Section 6.8.7 allows and never
// leaves it.
//
// Anchoring on the last transmission rather than on the present instant is what
// keeps the pacing safe against a peer that floods packets or flaps its
// advertised value: repeated calls converge on the same deadline instead of
// pushing it out, so the deadline moves only when a requirement changes, never
// by mere packet arrival.
//
// When the deadline has already passed, RFC 5880 Section 6.8.3 requires the
// next packet "as soon as practicable". Sending it here does not starve either:
// tx() moves lastTx to now and re-arms a full period, so the anchor advances
// with every send and a flood can trigger at most one immediate transmission
// per interval. Re-arming from the present instant without sending is the
// design that starves, because that anchor never advances. Go 1.23+ timer
// semantics mean Reset discards any expiry already pending, so an overdue
// receive landing on a fire cannot produce two packets.
func (p *bfdPeer) armTx() {
	remaining := time.Until(p.lastTx.Add(p.jitteredTxInterval()))
	if remaining <= 0 {
		p.tx()
		return
	}
	p.eventTx.Reset(remaining)
}

func (p *bfdPeer) rxPacket(h *bfd.BFDHeader) {
	// RFC 5880 Section 6.8.6: if the Detect Mult field is zero, the packet
	// MUST be discarded.
	if h.DetectTimeMultiplier == 0 {
		p.stats.invalidMultiplier.Add(1)
		return
	}

	// RFC 5880 Section 6.8.6: if the My Discriminator field is zero, the
	// packet MUST be discarded.
	if h.MyDiscriminator == 0 {
		p.stats.invalidDiscriminator.Add(1)
		return
	}

	// RFC 5880 Section 6.8.6: a nonzero Your Discriminator selects the
	// session and MUST match ours. A zero Your Discriminator carries no
	// session binding, so it is only accepted from a remote system that has
	// not learned our discriminator yet, i.e. one in Down or AdminDown.
	if h.YourDiscriminator != 0 {
		if h.YourDiscriminator != p.myDiscriminator {
			p.stats.invalidDiscriminator.Add(1)
			return
		}
	} else {
		if h.State != bfd.StateDown && h.State != bfd.StateAdminDown {
			p.stats.invalidDiscriminator.Add(1)
			return
		}

		// Once the remote discriminator is bound, a packet that omits Your
		// Discriminator still has to come from that same remote system, or
		// it can tear the session down without ever having seen it.
		if p.yourDiscriminator != 0 && h.MyDiscriminator != p.yourDiscriminator {
			p.stats.invalidDiscriminator.Add(1)
			return
		}
	}

	p.stats.rxPacket.Add(1)

	// RFC 5880 Section 6.8.4: Detection Time is the remote Detect Mult
	// multiplied by the negotiated receive interval, i.e. the greater of our
	// RequiredMinRxInterval and the remote DesiredMinTxInterval.
	negotiatedRx := p.rxInterval
	if remoteTx := time.Duration(h.DesiredMinTxInterval) * time.Microsecond; remoteTx > negotiatedRx {
		negotiatedRx = remoteTx
	}
	p.expiryInterval = time.Duration(h.DetectTimeMultiplier) * negotiatedRx

	// RFC 5880 Section 6.8.6: "Set bfd.RemoteMinRxInterval to the value of
	// Required Min RX Interval." A received zero is stored verbatim; this
	// implementation deliberately does not implement Section 6.8.7's meaning for
	// zero (stop periodic transmission). The timer is re-armed once at the end
	// of this function, after the state machine has run.
	p.remoteMinRxInterval = time.Duration(h.RequiredMinRxInterval) * time.Microsecond

	// RFC 5880 Section 6.8.6: "If a Poll Sequence is being transmitted by the local
	// system and the Final (F) bit in the received packet is set, the Poll Sequence
	// MUST be terminated." This must run before the state switch below: a single
	// packet that carries Final while also signaling Down has to terminate the OLD
	// sequence here, so that the Down transition below starts a NEW one.
	if h.Final && p.pollSequence {
		p.pollSequence = false
	}

	switch h.State {
	case bfd.StateAdminDown:
		if p.sessionState() != api.BfdSessionState_BFD_SESSION_STATE_DOWN {
			p.remoteDown()
		}
	case bfd.StateDown:
		switch p.sessionState() {
		case api.BfdSessionState_BFD_SESSION_STATE_DOWN:
			p.setStateInit(h.MyDiscriminator)
		case api.BfdSessionState_BFD_SESSION_STATE_UP:
			p.remoteDown()
		}
	case bfd.StateInit:
		switch p.sessionState() {
		case api.BfdSessionState_BFD_SESSION_STATE_DOWN, api.BfdSessionState_BFD_SESSION_STATE_INIT:
			p.setStateUp(h.MyDiscriminator)
		}
	case bfd.StateUp:
		if p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_INIT {
			p.setStateUp(h.MyDiscriminator)
		}
	}

	if h.Poll {
		p.sendPacket(p.sessionStateToWire(), false, true, h.MyDiscriminator)
	}

	if p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_INIT ||
		p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_UP {
		p.eventExpiry.Reset(p.expiryInterval)
	}

	// The peer's advertised requirement may have moved the transmit interval.
	// Re-arm here, after the state machine, so an overdue transmission goes out
	// carrying the state this packet left us in, not the one it found us in. A
	// state transition above may already have armed through setDesiredMinTx;
	// armTx converges on the same deadline, so the second call is harmless.
	p.armTx()
}

// jitteredTxInterval returns the interval to wait before sending the next
// periodic BFD Control packet: the transmit interval (effectiveTxInterval) less
// a fresh per-packet random reduction.
//
// RFC 5880 Section 6.8.7: the transmit interval MUST be reduced per packet
// by a random value of 0 to 25%; when the detect multiplier is 1, the
// interval MUST be no more than 90% and no less than 75% of the negotiated
// interval.
func (p *bfdPeer) jitteredTxInterval() time.Duration {
	maxPct := 100
	if p.multiplier == 1 {
		maxPct = 90
	}
	return p.effectiveTxInterval() * time.Duration(randRange(75, maxPct)) / 100
}

// tx sends the periodic BFD Control packet for the current state and re-arms the
// jittered transmit interval from this moment. It runs on every timer fire, and
// from armTx when the pacing deadline is already overdue. Between fires, armTx
// moves the deadline only to lastTx + jitteredTxInterval, which changes only when
// one of the interval's terms does.
func (p *bfdPeer) tx() {
	p.lastTx = time.Now()
	p.eventTx.Reset(p.jitteredTxInterval())

	switch p.sessionState() {
	case api.BfdSessionState_BFD_SESSION_STATE_UP:
		p.sendPacket(bfd.StateUp, p.pollSequence, false, p.yourDiscriminator)
	case api.BfdSessionState_BFD_SESSION_STATE_INIT:
		p.sendPacket(bfd.StateInit, p.pollSequence, false, p.yourDiscriminator)
	default:
		p.sendPacket(bfd.StateDown, p.pollSequence, false, 0)
	}
}

func (p *bfdPeer) expiry() {
	if p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_DOWN {
		p.eventExpiry.Stop()
		return
	}

	p.logger.Warn("Expired",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.stats.expired.Add(1)

	p.resetPeer()
	p.setStateDown()
}

func (p *bfdPeer) shutdown() {
	p.stop()
	p.eventStart.Stop()
	p.eventTx.Stop()
	p.eventExpiry.Stop()
}

func (p *bfdPeer) remoteDown() {
	p.logger.Warn("Remote peer signaled BFD down",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.resetPeer()
	p.setStateDown()
}

func (p *bfdPeer) resetPeer() {
	if err := p.peerState.ResetPeer(context.Background(), &api.ResetPeerRequest{
		Address:       p.peerAddress.String(),
		Communication: "BFD is down",
		Soft:          false,
	}); err != nil {
		p.logger.Warn("ResetPeer failed",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
			slog.String("Err", err.Error()),
		)
	}
}

func (p *bfdPeer) sendPacket(state bfd.StateType, poll bool, final bool, yourDiscriminator uint32) {
	if p.udpClient == nil {
		p.stats.txDrop.Add(1)
		return
	}

	packet := &bfd.BFDHeader{
		Version:               1,
		State:                 state,
		Poll:                  poll,
		Final:                 final,
		DetectTimeMultiplier:  p.multiplier,
		MyDiscriminator:       p.myDiscriminator,
		YourDiscriminator:     yourDiscriminator,
		DesiredMinTxInterval:  uint32(p.desiredMinTx.Microseconds()),
		RequiredMinRxInterval: uint32(p.rxInterval.Microseconds()),
	}

	buffer, err := packet.MarshalBinary()
	if err != nil {
		// should never happen
		p.logger.Error("MarshalBinary",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
		)
		return
	}

	_, err = p.udpClient.Write(buffer)
	if err != nil {
		p.logger.Debug("Can't send UDP packet",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
		)

		p.stats.txError.Add(1)
		return
	}

	p.stats.txPacket.Add(1)
}

func (p *bfdPeer) sessionState() api.BfdSessionState {
	return api.BfdSessionState(p.state.Load())
}

func (p *bfdPeer) sessionStateToWire() bfd.StateType {
	switch p.sessionState() {
	case api.BfdSessionState_BFD_SESSION_STATE_UP:
		return bfd.StateUp
	case api.BfdSessionState_BFD_SESSION_STATE_INIT:
		return bfd.StateInit
	case api.BfdSessionState_BFD_SESSION_STATE_ADMIN_DOWN:
		return bfd.StateAdminDown
	default:
		return bfd.StateDown
	}
}

// setDesiredMinTx applies a change to bfd.DesiredMinTxInterval: it initiates the Poll
// Sequence that RFC 5880 Section 6.8.3 requires for the change and re-arms the transmit
// timer through armTx. The new interval takes effect immediately: Section 6.8.3 only
// forbids that for an increase made while the session is Up, and the only increase here
// happens on the transition out of Up.
func (p *bfdPeer) setDesiredMinTx(d time.Duration) {
	if d == p.desiredMinTx {
		return
	}
	p.desiredMinTx = d
	p.pollSequence = true
	p.armTx()
}

func (p *bfdPeer) setStateDown() {
	p.logger.Debug("Set state to DOWN",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_DOWN))
	p.yourDiscriminator = 0

	// RFC 5880 Section 6.8.3: "When bfd.SessionState is not Up, the system MUST set
	// bfd.DesiredMinTxInterval to a value of not less than one second (1,000,000
	// microseconds)."
	p.setDesiredMinTx(max(p.txInterval, bfdSlowTxInterval))

	p.eventExpiry.Stop()
}

func (p *bfdPeer) setStateInit(yourDiscriminator uint32) {
	p.logger.Debug("Set state to INIT",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_INIT))
	p.yourDiscriminator = yourDiscriminator

	// desiredMinTx is left untouched here: Init is only ever entered from Down
	// (rxPacket's bfd.StateDown case), and Down already carries the RFC 5880 Section
	// 6.8.3 not-Up floor, which still applies.
}

func (p *bfdPeer) setStateUp(yourDiscriminator uint32) {
	p.logger.Debug("Set state to UP",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_UP))
	p.yourDiscriminator = yourDiscriminator

	// RFC 5880 Section 6.8.3: Up lifts the not-Up floor, restoring the configured
	// interval — a change that starts a Poll Sequence unless it's a no-op. The first
	// Up packet is not sent off-schedule here: armTx (through setDesiredMinTx) sends
	// it at once when the shorter interval has already elapsed since the last packet,
	// which after a one-second Down cadence it nearly always has, and otherwise waits
	// out the remainder. Section 6.8.7's "MUST NOT transmit at an interval less than"
	// has no exception for state changes.
	p.setDesiredMinTx(p.txInterval)

	p.eventExpiry.Reset(p.expiryInterval)
}
