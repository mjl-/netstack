// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package udp_test

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/checker"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/link/channel"
	"github.com/google/netstack/tcpip/link/sniffer"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/network/ipv6"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/tcpip/transport/udp"
	"github.com/google/netstack/waiter"
)

// Addresses and ports used for testing. It is recommended that tests stick to
// using these addresses as it allows using the testFlow helper.
// Naming rules: 'stack*'' denotes local addresses and ports, while 'test*'
// represents the remote endpoint.
const (
	v4MappedAddrPrefix    = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff"
	stackV6Addr           = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	testV6Addr            = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	stackV4MappedAddr     = v4MappedAddrPrefix + stackAddr
	testV4MappedAddr      = v4MappedAddrPrefix + testAddr
	multicastV4MappedAddr = v4MappedAddrPrefix + multicastAddr
	broadcastV4MappedAddr = v4MappedAddrPrefix + broadcastAddr
	v4MappedWildcardAddr  = v4MappedAddrPrefix + "\x00\x00\x00\x00"

	stackAddr       = "\x0a\x00\x00\x01"
	stackPort       = 1234
	testAddr        = "\x0a\x00\x00\x02"
	testPort        = 4096
	multicastAddr   = "\xe8\x2b\xd3\xea"
	multicastV6Addr = "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	broadcastAddr   = header.IPv4Broadcast

	// defaultMTU is the MTU, in bytes, used throughout the tests, except
	// where another value is explicitly used. It is chosen to match the MTU
	// of loopback interfaces on linux systems.
	defaultMTU = 65536
)

// header4Tuple stores the 4-tuple {src-IP, src-port, dst-IP, dst-port} used in
// a packet header. These values are used to populate a header or verify one.
// Note that because they are used in packet headers, the addresses are never in
// a V4-mapped format.
type header4Tuple struct {
	srcAddr tcpip.FullAddress
	dstAddr tcpip.FullAddress
}

// testFlow implements a helper type used for sending and receiving test
// packets. A given test flow value defines 1) the socket endpoint used for the
// test and 2) the type of packet send or received on the endpoint. E.g., a
// multicastV6Only flow is a V6 multicast packet passing through a V6-only
// endpoint. The type provides helper methods to characterize the flow (e.g.,
// isV4) as well as return a proper header4Tuple for it.
type testFlow int

const (
	unicastV4       testFlow = iota // V4 unicast on a V4 socket
	unicastV4in6                    // V4-mapped unicast on a V6-dual socket
	unicastV6                       // V6 unicast on a V6 socket
	unicastV6Only                   // V6 unicast on a V6-only socket
	multicastV4                     // V4 multicast on a V4 socket
	multicastV4in6                  // V4-mapped multicast on a V6-dual socket
	multicastV6                     // V6 multicast on a V6 socket
	multicastV6Only                 // V6 multicast on a V6-only socket
	broadcast                       // V4 broadcast on a V4 socket
	broadcastIn6                    // V4-mapped broadcast on a V6-dual socket
)

func (flow testFlow) String() string {
	switch flow {
	case unicastV4:
		return "unicastV4"
	case unicastV6:
		return "unicastV6"
	case unicastV6Only:
		return "unicastV6Only"
	case unicastV4in6:
		return "unicastV4in6"
	case multicastV4:
		return "multicastV4"
	case multicastV6:
		return "multicastV6"
	case multicastV6Only:
		return "multicastV6Only"
	case multicastV4in6:
		return "multicastV4in6"
	case broadcast:
		return "broadcast"
	case broadcastIn6:
		return "broadcastIn6"
	default:
		return "unknown"
	}
}

// packetDirection explains if a flow is incoming (read) or outgoing (write).
type packetDirection int

const (
	incoming packetDirection = iota
	outgoing
)

// header4Tuple returns the header4Tuple for the given flow and direction. Note
// that the tuple contains no mapped addresses as those only exist at the socket
// level but not at the packet header level.
func (flow testFlow) header4Tuple(d packetDirection) header4Tuple {
	var h header4Tuple
	if flow.isV4() {
		if d == outgoing {
			h = header4Tuple{
				srcAddr: tcpip.FullAddress{Addr: stackAddr, Port: stackPort},
				dstAddr: tcpip.FullAddress{Addr: testAddr, Port: testPort},
			}
		} else {
			h = header4Tuple{
				srcAddr: tcpip.FullAddress{Addr: testAddr, Port: testPort},
				dstAddr: tcpip.FullAddress{Addr: stackAddr, Port: stackPort},
			}
		}
		if flow.isMulticast() {
			h.dstAddr.Addr = multicastAddr
		} else if flow.isBroadcast() {
			h.dstAddr.Addr = broadcastAddr
		}
	} else { // IPv6
		if d == outgoing {
			h = header4Tuple{
				srcAddr: tcpip.FullAddress{Addr: stackV6Addr, Port: stackPort},
				dstAddr: tcpip.FullAddress{Addr: testV6Addr, Port: testPort},
			}
		} else {
			h = header4Tuple{
				srcAddr: tcpip.FullAddress{Addr: testV6Addr, Port: testPort},
				dstAddr: tcpip.FullAddress{Addr: stackV6Addr, Port: stackPort},
			}
		}
		if flow.isMulticast() {
			h.dstAddr.Addr = multicastV6Addr
		}
	}
	return h
}

func (flow testFlow) getMcastAddr() tcpip.Address {
	if flow.isV4() {
		return multicastAddr
	}
	return multicastV6Addr
}

// mapAddrIfApplicable converts the given V4 address into its V4-mapped version
// if it is applicable to the flow.
func (flow testFlow) mapAddrIfApplicable(v4Addr tcpip.Address) tcpip.Address {
	if flow.isMapped() {
		return v4MappedAddrPrefix + v4Addr
	}
	return v4Addr
}

// netProto returns the protocol number used for the network packet.
func (flow testFlow) netProto() tcpip.NetworkProtocolNumber {
	if flow.isV4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

// sockProto returns the protocol number used when creating the socket
// endpoint for this flow.
func (flow testFlow) sockProto() tcpip.NetworkProtocolNumber {
	switch flow {
	case unicastV4in6, unicastV6, unicastV6Only, multicastV4in6, multicastV6, multicastV6Only, broadcastIn6:
		return ipv6.ProtocolNumber
	case unicastV4, multicastV4, broadcast:
		return ipv4.ProtocolNumber
	default:
		panic(fmt.Sprintf("invalid testFlow given: %d", flow))
	}
}

func (flow testFlow) checkerFn() func(*testing.T, []byte, ...checker.NetworkChecker) {
	if flow.isV4() {
		return checker.IPv4
	}
	return checker.IPv6
}

func (flow testFlow) isV6() bool { return !flow.isV4() }
func (flow testFlow) isV4() bool {
	return flow.sockProto() == ipv4.ProtocolNumber || flow.isMapped()
}

func (flow testFlow) isV6Only() bool {
	switch flow {
	case unicastV6Only, multicastV6Only:
		return true
	case unicastV4, unicastV4in6, unicastV6, multicastV4, multicastV4in6, multicastV6, broadcast, broadcastIn6:
		return false
	default:
		panic(fmt.Sprintf("invalid testFlow given: %d", flow))
	}
}

func (flow testFlow) isMulticast() bool {
	switch flow {
	case multicastV4, multicastV4in6, multicastV6, multicastV6Only:
		return true
	case unicastV4, unicastV4in6, unicastV6, unicastV6Only, broadcast, broadcastIn6:
		return false
	default:
		panic(fmt.Sprintf("invalid testFlow given: %d", flow))
	}
}

func (flow testFlow) isBroadcast() bool {
	switch flow {
	case broadcast, broadcastIn6:
		return true
	case unicastV4, unicastV4in6, unicastV6, unicastV6Only, multicastV4, multicastV4in6, multicastV6, multicastV6Only:
		return false
	default:
		panic(fmt.Sprintf("invalid testFlow given: %d", flow))
	}
}

func (flow testFlow) isMapped() bool {
	switch flow {
	case unicastV4in6, multicastV4in6, broadcastIn6:
		return true
	case unicastV4, unicastV6, unicastV6Only, multicastV4, multicastV6, multicastV6Only, broadcast:
		return false
	default:
		panic(fmt.Sprintf("invalid testFlow given: %d", flow))
	}
}

type testContext struct {
	t      *testing.T
	linkEP *channel.Endpoint
	s      *stack.Stack

	ep tcpip.Endpoint
	wq waiter.Queue
}

func newDualTestContext(t *testing.T, mtu uint32) *testContext {
	t.Helper()

	s := stack.New([]string{ipv4.ProtocolName, ipv6.ProtocolName}, []string{udp.ProtocolName}, stack.Options{})

	id, linkEP := channel.New(256, mtu, "")
	if testing.Verbose() {
		id = sniffer.New(id)
	}
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, stackAddr); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	if err := s.AddAddress(1, ipv6.ProtocolNumber, stackV6Addr); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         1,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         1,
		},
	})

	return &testContext{
		t:      t,
		s:      s,
		linkEP: linkEP,
	}
}

func (c *testContext) cleanup() {
	if c.ep != nil {
		c.ep.Close()
	}
}

func (c *testContext) createEndpoint(proto tcpip.NetworkProtocolNumber) {
	c.t.Helper()

	var err *tcpip.Error
	c.ep, err = c.s.NewEndpoint(udp.ProtocolNumber, proto, &c.wq)
	if err != nil {
		c.t.Fatal("NewEndpoint failed: ", err)
	}
}

func (c *testContext) createEndpointForFlow(flow testFlow) {
	c.t.Helper()

	c.createEndpoint(flow.sockProto())
	if flow.isV6Only() {
		if err := c.ep.SetSockOpt(tcpip.V6OnlyOption(1)); err != nil {
			c.t.Fatalf("SetSockOpt failed: %v", err)
		}
	} else if flow.isBroadcast() {
		if err := c.ep.SetSockOpt(tcpip.BroadcastOption(1)); err != nil {
			c.t.Fatal("SetSockOpt failed:", err)
		}
	}
}

// getPacketAndVerify reads a packet from the link endpoint and verifies the
// header against expected values from the given test flow. In addition, it
// calls any extra checker functions provided.
func (c *testContext) getPacketAndVerify(flow testFlow, checkers ...checker.NetworkChecker) []byte {
	c.t.Helper()

	select {
	case p := <-c.linkEP.C:
		if p.Proto != flow.netProto() {
			c.t.Fatalf("Bad network protocol: got %v, wanted %v", p.Proto, flow.netProto())
		}
		b := make([]byte, len(p.Header)+len(p.Payload))
		copy(b, p.Header)
		copy(b[len(p.Header):], p.Payload)

		h := flow.header4Tuple(outgoing)
		checkers := append(
			checkers,
			checker.SrcAddr(h.srcAddr.Addr),
			checker.DstAddr(h.dstAddr.Addr),
			checker.UDP(checker.DstPort(h.dstAddr.Port)),
		)
		flow.checkerFn()(c.t, b, checkers...)
		return b

	case <-time.After(2 * time.Second):
		c.t.Fatalf("Packet wasn't written out")
	}

	return nil
}

// injectPacket creates a packet of the given flow and with the given payload,
// and injects it into the link endpoint.
func (c *testContext) injectPacket(flow testFlow, payload []byte) {
	c.t.Helper()

	h := flow.header4Tuple(incoming)
	if flow.isV4() {
		c.injectV4Packet(payload, &h)
	} else {
		c.injectV6Packet(payload, &h)
	}
}

// injectV6Packet creates a V6 test packet with the given payload and header
// values, and injects it into the link endpoint.
func (c *testContext) injectV6Packet(payload []byte, h *header4Tuple) {
	// Allocate a buffer for data and headers.
	buf := buffer.NewView(header.UDPMinimumSize + header.IPv6MinimumSize + len(payload))
	copy(buf[len(buf)-len(payload):], payload)

	// Initialize the IP header.
	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(header.UDPMinimumSize + len(payload)),
		NextHeader:    uint8(udp.ProtocolNumber),
		HopLimit:      65,
		SrcAddr:       h.srcAddr.Addr,
		DstAddr:       h.dstAddr.Addr,
	})

	// Initialize the UDP header.
	u := header.UDP(buf[header.IPv6MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: h.srcAddr.Port,
		DstPort: h.dstAddr.Port,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})

	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, h.srcAddr.Addr, h.dstAddr.Addr, uint16(len(u)))

	// Calculate the UDP checksum and set it.
	xsum = header.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))

	// Inject packet.
	c.linkEP.Inject(ipv6.ProtocolNumber, buf.ToVectorisedView())
}

// injectV6Packet creates a V4 test packet with the given payload and header
// values, and injects it into the link endpoint.
func (c *testContext) injectV4Packet(payload []byte, h *header4Tuple) {
	// Allocate a buffer for data and headers.
	buf := buffer.NewView(header.UDPMinimumSize + header.IPv4MinimumSize + len(payload))
	copy(buf[len(buf)-len(payload):], payload)

	// Initialize the IP header.
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
		TotalLength: uint16(len(buf)),
		TTL:         65,
		Protocol:    uint8(udp.ProtocolNumber),
		SrcAddr:     h.srcAddr.Addr,
		DstAddr:     h.dstAddr.Addr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// Initialize the UDP header.
	u := header.UDP(buf[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: h.srcAddr.Port,
		DstPort: h.dstAddr.Port,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})

	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, h.srcAddr.Addr, h.dstAddr.Addr, uint16(len(u)))

	// Calculate the UDP checksum and set it.
	xsum = header.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))

	// Inject packet.
	c.linkEP.Inject(ipv4.ProtocolNumber, buf.ToVectorisedView())
}

func newPayload() []byte {
	b := make([]byte, 30+rand.Intn(100))
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

func TestBindPortReuse(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpoint(ipv6.ProtocolNumber)

	var eps [5]tcpip.Endpoint
	reusePortOpt := tcpip.ReusePortOption(1)

	pollChannel := make(chan tcpip.Endpoint)
	for i := 0; i < len(eps); i++ {
		// Try to receive the data.
		wq := waiter.Queue{}
		we, ch := waiter.NewChannelEntry(nil)
		wq.EventRegister(&we, waiter.EventIn)
		defer wq.EventUnregister(&we)
		defer close(ch)

		var err *tcpip.Error
		eps[i], err = c.s.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
		if err != nil {
			c.t.Fatalf("NewEndpoint failed: %v", err)
		}

		go func(ep tcpip.Endpoint) {
			for range ch {
				pollChannel <- ep
			}
		}(eps[i])

		defer eps[i].Close()
		if err := eps[i].SetSockOpt(reusePortOpt); err != nil {
			c.t.Fatalf("SetSockOpt failed failed: %v", err)
		}
		if err := eps[i].Bind(tcpip.FullAddress{Addr: stackV6Addr, Port: stackPort}); err != nil {
			t.Fatalf("ep.Bind(...) failed: %v", err)
		}
	}

	npackets := 100000
	nports := 10000
	ports := make(map[uint16]tcpip.Endpoint)
	stats := make(map[tcpip.Endpoint]int)
	for i := 0; i < npackets; i++ {
		// Send a packet.
		port := uint16(i % nports)
		payload := newPayload()
		c.injectV6Packet(payload, &header4Tuple{
			srcAddr: tcpip.FullAddress{Addr: testV6Addr, Port: testPort + port},
			dstAddr: tcpip.FullAddress{Addr: stackV6Addr, Port: stackPort},
		})

		var addr tcpip.FullAddress
		ep := <-pollChannel
		_, _, err := ep.Read(&addr)
		if err != nil {
			c.t.Fatalf("Read failed: %v", err)
		}
		stats[ep]++
		if i < nports {
			ports[uint16(i)] = ep
		} else {
			// Check that all packets from one client are handled
			// by the same socket.
			if ports[port] != ep {
				t.Fatalf("Port mismatch")
			}
		}
	}

	if len(stats) != len(eps) {
		t.Fatalf("Only %d(expected %d) sockets received packets", len(stats), len(eps))
	}

	// Check that a packet distribution is fair between sockets.
	for _, c := range stats {
		n := float64(npackets) / float64(len(eps))
		// The deviation is less than 10%.
		if math.Abs(float64(c)-n) > n/10 {
			t.Fatal(c, n)
		}
	}
}

// testRead sends a packet of the given test flow into the stack by injecting it
// into the link endpoint. It then reads it from the UDP endpoint and verifies
// its correctness.
func testRead(c *testContext, flow testFlow) {
	c.t.Helper()

	payload := newPayload()
	c.injectPacket(flow, payload)

	// Try to receive the data.
	we, ch := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&we, waiter.EventIn)
	defer c.wq.EventUnregister(&we)

	var addr tcpip.FullAddress
	v, _, err := c.ep.Read(&addr)
	if err == tcpip.ErrWouldBlock {
		// Wait for data to become available.
		select {
		case <-ch:
			v, _, err = c.ep.Read(&addr)
			if err != nil {
				c.t.Fatalf("Read failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			c.t.Fatalf("Timed out waiting for data")
		}
	}

	// Check the peer address.
	h := flow.header4Tuple(incoming)
	if addr.Addr != h.srcAddr.Addr {
		c.t.Fatalf("Unexpected remote address: got %v, want %v", addr.Addr, h.srcAddr)
	}

	// Check the payload.
	if !bytes.Equal(payload, v) {
		c.t.Fatalf("Bad payload: got %x, want %x", v, payload)
	}
}

func TestBindEphemeralPort(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpoint(ipv6.ProtocolNumber)

	if err := c.ep.Bind(tcpip.FullAddress{}); err != nil {
		t.Fatalf("ep.Bind(...) failed: %v", err)
	}
}

func TestBindReservedPort(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpoint(ipv6.ProtocolNumber)

	if err := c.ep.Connect(tcpip.FullAddress{Addr: testV6Addr, Port: testPort}); err != nil {
		c.t.Fatalf("Connect failed: %v", err)
	}

	addr, err := c.ep.GetLocalAddress()
	if err != nil {
		t.Fatalf("GetLocalAddress failed: %v", err)
	}

	// We can't bind the address reserved by the connected endpoint above.
	{
		ep, err := c.s.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &c.wq)
		if err != nil {
			t.Fatalf("NewEndpoint failed: %v", err)
		}
		defer ep.Close()
		if got, want := ep.Bind(addr), tcpip.ErrPortInUse; got != want {
			t.Fatalf("got ep.Bind(...) = %v, want = %v", got, want)
		}
	}

	func() {
		ep, err := c.s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &c.wq)
		if err != nil {
			t.Fatalf("NewEndpoint failed: %v", err)
		}
		defer ep.Close()
		// We can't bind ipv4-any on the port reserved by the connected endpoint
		// above, since the endpoint is dual-stack.
		if got, want := ep.Bind(tcpip.FullAddress{Port: addr.Port}), tcpip.ErrPortInUse; got != want {
			t.Fatalf("got ep.Bind(...) = %v, want = %v", got, want)
		}
		// We can bind an ipv4 address on this port, though.
		if err := ep.Bind(tcpip.FullAddress{Addr: stackAddr, Port: addr.Port}); err != nil {
			t.Fatalf("ep.Bind(...) failed: %v", err)
		}
	}()

	// Once the connected endpoint releases its port reservation, we are able to
	// bind ipv4-any once again.
	c.ep.Close()
	func() {
		ep, err := c.s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &c.wq)
		if err != nil {
			t.Fatalf("NewEndpoint failed: %v", err)
		}
		defer ep.Close()
		if err := ep.Bind(tcpip.FullAddress{Port: addr.Port}); err != nil {
			t.Fatalf("ep.Bind(...) failed: %v", err)
		}
	}()
}

func TestV4ReadOnV6(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpointForFlow(unicastV4in6)

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testRead(c, unicastV4in6)
}

func TestV4ReadOnBoundToV4MappedWildcard(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpointForFlow(unicastV4in6)

	// Bind to v4 mapped wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Addr: v4MappedWildcardAddr, Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testRead(c, unicastV4in6)
}

func TestV4ReadOnBoundToV4Mapped(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpointForFlow(unicastV4in6)

	// Bind to local address.
	if err := c.ep.Bind(tcpip.FullAddress{Addr: stackV4MappedAddr, Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testRead(c, unicastV4in6)
}

func TestV6ReadOnV6(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpointForFlow(unicastV6)

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testRead(c, unicastV6)
}

func TestV4ReadOnV4(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpointForFlow(unicastV4)

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testRead(c, unicastV4)
}

// TestReadOnBoundToMulticast checks that an endpoint can bind to a multicast
// address and receive data sent to that address.
func TestReadOnBoundToMulticast(t *testing.T) {
	// FIXME(b/128189410): multicastV4in6 currently doesn't work as
	// AddMembershipOption doesn't handle V4in6 addresses.
	for _, flow := range []testFlow{multicastV4, multicastV6, multicastV6Only} {
		t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
			c := newDualTestContext(t, defaultMTU)
			defer c.cleanup()

			c.createEndpointForFlow(flow)

			// Bind to multicast address.
			mcastAddr := flow.mapAddrIfApplicable(flow.getMcastAddr())
			if err := c.ep.Bind(tcpip.FullAddress{Addr: mcastAddr, Port: stackPort}); err != nil {
				c.t.Fatal("Bind failed:", err)
			}

			// Join multicast group.
			ifoptSet := tcpip.AddMembershipOption{NIC: 1, MulticastAddr: mcastAddr}
			if err := c.ep.SetSockOpt(ifoptSet); err != nil {
				c.t.Fatal("SetSockOpt failed:", err)
			}

			testRead(c, flow)
		})
	}
}

// TestV4ReadOnBoundToBroadcast checks that an endpoint can bind to a broadcast
// address and receive broadcast data on it.
func TestV4ReadOnBoundToBroadcast(t *testing.T) {
	for _, flow := range []testFlow{broadcast, broadcastIn6} {
		t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
			c := newDualTestContext(t, defaultMTU)
			defer c.cleanup()

			c.createEndpointForFlow(flow)

			// Bind to broadcast address.
			bcastAddr := flow.mapAddrIfApplicable(broadcastAddr)
			if err := c.ep.Bind(tcpip.FullAddress{Addr: bcastAddr, Port: stackPort}); err != nil {
				c.t.Fatalf("Bind failed: %s", err)
			}

			// Test acceptance.
			testRead(c, flow)
		})
	}
}

// testFailingWrite sends a packet of the given test flow into the UDP endpoint
// and verifies it fails with the provided error code.
func testFailingWrite(c *testContext, flow testFlow, wantErr *tcpip.Error) {
	c.t.Helper()

	h := flow.header4Tuple(outgoing)
	writeDstAddr := flow.mapAddrIfApplicable(h.dstAddr.Addr)

	payload := buffer.View(newPayload())
	_, _, gotErr := c.ep.Write(tcpip.SlicePayload(payload), tcpip.WriteOptions{
		To: &tcpip.FullAddress{Addr: writeDstAddr, Port: h.dstAddr.Port},
	})
	if gotErr != wantErr {
		c.t.Fatalf("Write returned unexpected error: got %v, want %v", gotErr, wantErr)
	}
}

// testWrite sends a packet of the given test flow from the UDP endpoint to the
// flow's destination address:port. It then receives it from the link endpoint
// and verifies its correctness including any additional checker functions
// provided.
func testWrite(c *testContext, flow testFlow, checkers ...checker.NetworkChecker) uint16 {
	c.t.Helper()
	return testWriteInternal(c, flow, true, checkers...)
}

// testWriteWithoutDestination sends a packet of the given test flow from the
// UDP endpoint without giving a destination address:port. It then receives it
// from the link endpoint and verifies its correctness including any additional
// checker functions provided.
func testWriteWithoutDestination(c *testContext, flow testFlow, checkers ...checker.NetworkChecker) uint16 {
	c.t.Helper()
	return testWriteInternal(c, flow, false, checkers...)
}

func testWriteInternal(c *testContext, flow testFlow, setDest bool, checkers ...checker.NetworkChecker) uint16 {
	c.t.Helper()

	writeOpts := tcpip.WriteOptions{}
	if setDest {
		h := flow.header4Tuple(outgoing)
		writeDstAddr := flow.mapAddrIfApplicable(h.dstAddr.Addr)
		writeOpts = tcpip.WriteOptions{
			To: &tcpip.FullAddress{Addr: writeDstAddr, Port: h.dstAddr.Port},
		}
	}
	payload := buffer.View(newPayload())
	n, _, err := c.ep.Write(tcpip.SlicePayload(payload), writeOpts)
	if err != nil {
		c.t.Fatalf("Write failed: %v", err)
	}
	if n != int64(len(payload)) {
		c.t.Fatalf("Bad number of bytes written: got %v, want %v", n, len(payload))
	}

	// Received the packet and check the payload.
	b := c.getPacketAndVerify(flow, checkers...)
	var udp header.UDP
	if flow.isV4() {
		udp = header.UDP(header.IPv4(b).Payload())
	} else {
		udp = header.UDP(header.IPv6(b).Payload())
	}
	if !bytes.Equal(payload, udp.Payload()) {
		c.t.Fatalf("Bad payload: got %x, want %x", udp.Payload(), payload)
	}

	return udp.SourcePort()
}

func testDualWrite(c *testContext) uint16 {
	c.t.Helper()

	v4Port := testWrite(c, unicastV4in6)
	v6Port := testWrite(c, unicastV6)
	if v4Port != v6Port {
		c.t.Fatalf("expected v4 and v6 ports to be equal: got v4Port = %d, v6Port = %d", v4Port, v6Port)
	}

	return v4Port
}

func TestDualWriteUnbound(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpoint(ipv6.ProtocolNumber)

	testDualWrite(c)
}

func TestDualWriteBoundToWildcard(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpoint(ipv6.ProtocolNumber)

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	p := testDualWrite(c)
	if p != stackPort {
		c.t.Fatalf("Bad port: got %v, want %v", p, stackPort)
	}
}

func TestDualWriteConnectedToV6(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpoint(ipv6.ProtocolNumber)

	// Connect to v6 address.
	if err := c.ep.Connect(tcpip.FullAddress{Addr: testV6Addr, Port: testPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	testWrite(c, unicastV6)

	// Write to V4 mapped address.
	testFailingWrite(c, unicastV4in6, tcpip.ErrNetworkUnreachable)
}

func TestDualWriteConnectedToV4Mapped(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpoint(ipv6.ProtocolNumber)

	// Connect to v4 mapped address.
	if err := c.ep.Connect(tcpip.FullAddress{Addr: testV4MappedAddr, Port: testPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	testWrite(c, unicastV4in6)

	// Write to v6 address.
	testFailingWrite(c, unicastV6, tcpip.ErrInvalidEndpointState)
}

func TestV4WriteOnV6Only(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpointForFlow(unicastV6Only)

	// Write to V4 mapped address.
	testFailingWrite(c, unicastV4in6, tcpip.ErrNoRoute)
}

func TestV6WriteOnBoundToV4Mapped(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpoint(ipv6.ProtocolNumber)

	// Bind to v4 mapped address.
	if err := c.ep.Bind(tcpip.FullAddress{Addr: stackV4MappedAddr, Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Write to v6 address.
	testFailingWrite(c, unicastV6, tcpip.ErrInvalidEndpointState)
}

func TestV6WriteOnConnected(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpoint(ipv6.ProtocolNumber)

	// Connect to v6 address.
	if err := c.ep.Connect(tcpip.FullAddress{Addr: testV6Addr, Port: testPort}); err != nil {
		c.t.Fatalf("Connect failed: %v", err)
	}

	testWriteWithoutDestination(c, unicastV6)
}

func TestV4WriteOnConnected(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpoint(ipv6.ProtocolNumber)

	// Connect to v4 mapped address.
	if err := c.ep.Connect(tcpip.FullAddress{Addr: testV4MappedAddr, Port: testPort}); err != nil {
		c.t.Fatalf("Connect failed: %v", err)
	}

	testWriteWithoutDestination(c, unicastV4)
}

// TestWriteOnBoundToV4Multicast checks that we can send packets out of a socket
// that is bound to a V4 multicast address.
func TestWriteOnBoundToV4Multicast(t *testing.T) {
	for _, flow := range []testFlow{unicastV4, multicastV4, broadcast} {
		t.Run(fmt.Sprintf("%s", flow), func(t *testing.T) {
			c := newDualTestContext(t, defaultMTU)
			defer c.cleanup()

			c.createEndpointForFlow(flow)

			// Bind to V4 mcast address.
			if err := c.ep.Bind(tcpip.FullAddress{Addr: multicastAddr, Port: stackPort}); err != nil {
				c.t.Fatal("Bind failed:", err)
			}

			testWrite(c, flow)
		})
	}
}

// TestWriteOnBoundToV4MappedMulticast checks that we can send packets out of a
// socket that is bound to a V4-mapped multicast address.
func TestWriteOnBoundToV4MappedMulticast(t *testing.T) {
	for _, flow := range []testFlow{unicastV4in6, multicastV4in6, broadcastIn6} {
		t.Run(fmt.Sprintf("%s", flow), func(t *testing.T) {
			c := newDualTestContext(t, defaultMTU)
			defer c.cleanup()

			c.createEndpointForFlow(flow)

			// Bind to V4Mapped mcast address.
			if err := c.ep.Bind(tcpip.FullAddress{Addr: multicastV4MappedAddr, Port: stackPort}); err != nil {
				c.t.Fatalf("Bind failed: %s", err)
			}

			testWrite(c, flow)
		})
	}
}

// TestWriteOnBoundToV6Multicast checks that we can send packets out of a
// socket that is bound to a V6 multicast address.
func TestWriteOnBoundToV6Multicast(t *testing.T) {
	for _, flow := range []testFlow{unicastV6, multicastV6} {
		t.Run(fmt.Sprintf("%s", flow), func(t *testing.T) {
			c := newDualTestContext(t, defaultMTU)
			defer c.cleanup()

			c.createEndpointForFlow(flow)

			// Bind to V6 mcast address.
			if err := c.ep.Bind(tcpip.FullAddress{Addr: multicastV6Addr, Port: stackPort}); err != nil {
				c.t.Fatalf("Bind failed: %s", err)
			}

			testWrite(c, flow)
		})
	}
}

// TestWriteOnBoundToV6Multicast checks that we can send packets out of a
// V6-only socket that is bound to a V6 multicast address.
func TestWriteOnBoundToV6OnlyMulticast(t *testing.T) {
	for _, flow := range []testFlow{unicastV6Only, multicastV6Only} {
		t.Run(fmt.Sprintf("%s", flow), func(t *testing.T) {
			c := newDualTestContext(t, defaultMTU)
			defer c.cleanup()

			c.createEndpointForFlow(flow)

			// Bind to V6 mcast address.
			if err := c.ep.Bind(tcpip.FullAddress{Addr: multicastV6Addr, Port: stackPort}); err != nil {
				c.t.Fatalf("Bind failed: %s", err)
			}

			testWrite(c, flow)
		})
	}
}

// TestWriteOnBoundToBroadcast checks that we can send packets out of a
// socket that is bound to the broadcast address.
func TestWriteOnBoundToBroadcast(t *testing.T) {
	for _, flow := range []testFlow{unicastV4, multicastV4, broadcast} {
		t.Run(fmt.Sprintf("%s", flow), func(t *testing.T) {
			c := newDualTestContext(t, defaultMTU)
			defer c.cleanup()

			c.createEndpointForFlow(flow)

			// Bind to V4 broadcast address.
			if err := c.ep.Bind(tcpip.FullAddress{Addr: broadcastAddr, Port: stackPort}); err != nil {
				c.t.Fatal("Bind failed:", err)
			}

			testWrite(c, flow)
		})
	}
}

// TestWriteOnBoundToV4MappedBroadcast checks that we can send packets out of a
// socket that is bound to the V4-mapped broadcast address.
func TestWriteOnBoundToV4MappedBroadcast(t *testing.T) {
	for _, flow := range []testFlow{unicastV4in6, multicastV4in6, broadcastIn6} {
		t.Run(fmt.Sprintf("%s", flow), func(t *testing.T) {
			c := newDualTestContext(t, defaultMTU)
			defer c.cleanup()

			c.createEndpointForFlow(flow)

			// Bind to V4Mapped mcast address.
			if err := c.ep.Bind(tcpip.FullAddress{Addr: broadcastV4MappedAddr, Port: stackPort}); err != nil {
				c.t.Fatalf("Bind failed: %s", err)
			}

			testWrite(c, flow)
		})
	}
}

func TestReadIncrementsPacketsReceived(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	// Create IPv4 UDP endpoint
	c.createEndpoint(ipv6.ProtocolNumber)

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	testRead(c, unicastV4)

	var want uint64 = 1
	if got := c.s.Stats().UDP.PacketsReceived.Value(); got != want {
		c.t.Fatalf("Read did not increment PacketsReceived: got %v, want %v", got, want)
	}
}

func TestWriteIncrementsPacketsSent(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createEndpoint(ipv6.ProtocolNumber)

	testDualWrite(c)

	var want uint64 = 2
	if got := c.s.Stats().UDP.PacketsSent.Value(); got != want {
		c.t.Fatalf("Write did not increment PacketsSent: got %v, want %v", got, want)
	}
}

func TestTTL(t *testing.T) {
	for _, flow := range []testFlow{unicastV4, unicastV4in6, unicastV6, unicastV6Only, multicastV4, multicastV4in6, multicastV6, broadcast, broadcastIn6} {
		t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
			c := newDualTestContext(t, defaultMTU)
			defer c.cleanup()

			c.createEndpointForFlow(flow)

			const multicastTTL = 42
			if err := c.ep.SetSockOpt(tcpip.MulticastTTLOption(multicastTTL)); err != nil {
				c.t.Fatalf("SetSockOpt failed: %v", err)
			}

			var wantTTL uint8
			if flow.isMulticast() {
				wantTTL = multicastTTL
			} else {
				var p stack.NetworkProtocol
				if flow.isV4() {
					p = ipv4.NewProtocol()
				} else {
					p = ipv6.NewProtocol()
				}
				ep, err := p.NewEndpoint(0, tcpip.AddressWithPrefix{}, nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				wantTTL = ep.DefaultTTL()
				ep.Close()
			}

			testWrite(c, flow, checker.TTL(wantTTL))
		})
	}
}

func TestMulticastInterfaceOption(t *testing.T) {
	for _, flow := range []testFlow{multicastV4, multicastV4in6, multicastV6, multicastV6Only} {
		t.Run(fmt.Sprintf("flow:%s", flow), func(t *testing.T) {
			for _, bindTyp := range []string{"bound", "unbound"} {
				t.Run(bindTyp, func(t *testing.T) {
					for _, optTyp := range []string{"use local-addr", "use NICID", "use local-addr and NIC"} {
						t.Run(optTyp, func(t *testing.T) {
							h := flow.header4Tuple(outgoing)
							mcastAddr := h.dstAddr.Addr
							localIfAddr := h.srcAddr.Addr

							var ifoptSet tcpip.MulticastInterfaceOption
							switch optTyp {
							case "use local-addr":
								ifoptSet.InterfaceAddr = localIfAddr
							case "use NICID":
								ifoptSet.NIC = 1
							case "use local-addr and NIC":
								ifoptSet.InterfaceAddr = localIfAddr
								ifoptSet.NIC = 1
							default:
								t.Fatal("unknown test variant")
							}

							c := newDualTestContext(t, defaultMTU)
							defer c.cleanup()

							c.createEndpoint(flow.sockProto())

							if bindTyp == "bound" {
								// Bind the socket by connecting to the multicast address.
								// This may have an influence on how the multicast interface
								// is set.
								addr := tcpip.FullAddress{
									Addr: flow.mapAddrIfApplicable(mcastAddr),
									Port: stackPort,
								}
								if err := c.ep.Connect(addr); err != nil {
									c.t.Fatalf("Connect failed: %v", err)
								}
							}

							if err := c.ep.SetSockOpt(ifoptSet); err != nil {
								c.t.Fatalf("SetSockOpt failed: %v", err)
							}

							// Verify multicast interface addr and NIC were set correctly.
							// Note that NIC must be 1 since this is our outgoing interface.
							ifoptWant := tcpip.MulticastInterfaceOption{NIC: 1, InterfaceAddr: ifoptSet.InterfaceAddr}
							var ifoptGot tcpip.MulticastInterfaceOption
							if err := c.ep.GetSockOpt(&ifoptGot); err != nil {
								c.t.Fatalf("GetSockOpt failed: %v", err)
							}
							if ifoptGot != ifoptWant {
								c.t.Errorf("got GetSockOpt() = %#v, want = %#v", ifoptGot, ifoptWant)
							}
						})
					}
				})
			}
		})
	}
}
