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

// Package stack_test contains tests for the stack. It is in its own package so
// that the tests can also validate that all definitions needed to implement
// transport and network protocols are properly exported by the stack package.
package stack_test

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/link/channel"
	"github.com/google/netstack/tcpip/stack"
)

const (
	fakeNetNumber        tcpip.NetworkProtocolNumber = math.MaxUint32
	fakeNetHeaderLen                                 = 12
	fakeDefaultPrefixLen                             = 8

	// fakeControlProtocol is used for control packets that represent
	// destination port unreachable.
	fakeControlProtocol tcpip.TransportProtocolNumber = 2

	// defaultMTU is the MTU, in bytes, used throughout the tests, except
	// where another value is explicitly used. It is chosen to match the MTU
	// of loopback interfaces on linux systems.
	defaultMTU = 65536
)

// fakeNetworkEndpoint is a network-layer protocol endpoint. It counts sent and
// received packets; the counts of all endpoints are aggregated in the protocol
// descriptor.
//
// Headers of this protocol are fakeNetHeaderLen bytes, but we currently only
// use the first three: destination address, source address, and transport
// protocol. They're all one byte fields to simplify parsing.
type fakeNetworkEndpoint struct {
	nicid      tcpip.NICID
	id         stack.NetworkEndpointID
	prefixLen  int
	proto      *fakeNetworkProtocol
	dispatcher stack.TransportDispatcher
	linkEP     stack.LinkEndpoint
}

func (f *fakeNetworkEndpoint) MTU() uint32 {
	return f.linkEP.MTU() - uint32(f.MaxHeaderLength())
}

func (f *fakeNetworkEndpoint) NICID() tcpip.NICID {
	return f.nicid
}

func (f *fakeNetworkEndpoint) PrefixLen() int {
	return f.prefixLen
}

func (*fakeNetworkEndpoint) DefaultTTL() uint8 {
	return 123
}

func (f *fakeNetworkEndpoint) ID() *stack.NetworkEndpointID {
	return &f.id
}

func (f *fakeNetworkEndpoint) HandlePacket(r *stack.Route, vv buffer.VectorisedView) {
	// Increment the received packet count in the protocol descriptor.
	f.proto.packetCount[int(f.id.LocalAddress[0])%len(f.proto.packetCount)]++

	// Consume the network header.
	b := vv.First()
	vv.TrimFront(fakeNetHeaderLen)

	// Handle control packets.
	if b[2] == uint8(fakeControlProtocol) {
		nb := vv.First()
		if len(nb) < fakeNetHeaderLen {
			return
		}

		vv.TrimFront(fakeNetHeaderLen)
		f.dispatcher.DeliverTransportControlPacket(tcpip.Address(nb[1:2]), tcpip.Address(nb[0:1]), fakeNetNumber, tcpip.TransportProtocolNumber(nb[2]), stack.ControlPortUnreachable, 0, vv)
		return
	}

	// Dispatch the packet to the transport protocol.
	f.dispatcher.DeliverTransportPacket(r, tcpip.TransportProtocolNumber(b[2]), buffer.View([]byte{}), vv)
}

func (f *fakeNetworkEndpoint) MaxHeaderLength() uint16 {
	return f.linkEP.MaxHeaderLength() + fakeNetHeaderLen
}

func (f *fakeNetworkEndpoint) PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber, dstAddr tcpip.Address) uint16 {
	return 0
}

func (f *fakeNetworkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return f.linkEP.Capabilities()
}

func (f *fakeNetworkEndpoint) WritePacket(r *stack.Route, gso *stack.GSO, hdr buffer.Prependable, payload buffer.VectorisedView, protocol tcpip.TransportProtocolNumber, _ uint8, loop stack.PacketLooping) *tcpip.Error {
	// Increment the sent packet count in the protocol descriptor.
	f.proto.sendPacketCount[int(r.RemoteAddress[0])%len(f.proto.sendPacketCount)]++

	// Add the protocol's header to the packet and send it to the link
	// endpoint.
	b := hdr.Prepend(fakeNetHeaderLen)
	b[0] = r.RemoteAddress[0]
	b[1] = f.id.LocalAddress[0]
	b[2] = byte(protocol)

	if loop&stack.PacketLoop != 0 {
		views := make([]buffer.View, 1, 1+len(payload.Views()))
		views[0] = hdr.View()
		views = append(views, payload.Views()...)
		vv := buffer.NewVectorisedView(len(views[0])+payload.Size(), views)
		f.HandlePacket(r, vv)
	}
	if loop&stack.PacketOut == 0 {
		return nil
	}

	return f.linkEP.WritePacket(r, gso, hdr, payload, fakeNetNumber)
}

func (*fakeNetworkEndpoint) WriteHeaderIncludedPacket(r *stack.Route, payload buffer.VectorisedView, loop stack.PacketLooping) *tcpip.Error {
	return tcpip.ErrNotSupported
}

func (*fakeNetworkEndpoint) Close() {}

type fakeNetGoodOption bool

type fakeNetBadOption bool

type fakeNetInvalidValueOption int

type fakeNetOptions struct {
	good bool
}

// fakeNetworkProtocol is a network-layer protocol descriptor. It aggregates the
// number of packets sent and received via endpoints of this protocol. The index
// where packets are added is given by the packet's destination address MOD 10.
type fakeNetworkProtocol struct {
	packetCount     [10]int
	sendPacketCount [10]int
	opts            fakeNetOptions
}

func (f *fakeNetworkProtocol) Number() tcpip.NetworkProtocolNumber {
	return fakeNetNumber
}

func (f *fakeNetworkProtocol) MinimumPacketSize() int {
	return fakeNetHeaderLen
}

func (f *fakeNetworkProtocol) DefaultPrefixLen() int {
	return fakeDefaultPrefixLen
}

func (*fakeNetworkProtocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	return tcpip.Address(v[1:2]), tcpip.Address(v[0:1])
}

func (f *fakeNetworkProtocol) NewEndpoint(nicid tcpip.NICID, addrWithPrefix tcpip.AddressWithPrefix, linkAddrCache stack.LinkAddressCache, dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint) (stack.NetworkEndpoint, *tcpip.Error) {
	return &fakeNetworkEndpoint{
		nicid:      nicid,
		id:         stack.NetworkEndpointID{LocalAddress: addrWithPrefix.Address},
		prefixLen:  addrWithPrefix.PrefixLen,
		proto:      f,
		dispatcher: dispatcher,
		linkEP:     linkEP,
	}, nil
}

func (f *fakeNetworkProtocol) SetOption(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case fakeNetGoodOption:
		f.opts.good = bool(v)
		return nil
	case fakeNetInvalidValueOption:
		return tcpip.ErrInvalidOptionValue
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

func (f *fakeNetworkProtocol) Option(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case *fakeNetGoodOption:
		*v = fakeNetGoodOption(f.opts.good)
		return nil
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

func TestNetworkReceive(t *testing.T) {
	// Create a stack with the fake network protocol, one nic, and two
	// addresses attached to it: 1 & 2.
	id, linkEP := channel.New(10, defaultMTU, "")
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x02"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	buf := buffer.NewView(30)

	// Make sure packet with wrong address is not delivered.
	buf[0] = 3
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 0 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 0)
	}
	if fakeNet.packetCount[2] != 0 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 0)
	}

	// Make sure packet is delivered to first endpoint.
	buf[0] = 1
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 0 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 0)
	}

	// Make sure packet is delivered to second endpoint.
	buf[0] = 2
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 1 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 1)
	}

	// Make sure packet is not delivered if protocol number is wrong.
	linkEP.Inject(fakeNetNumber-1, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 1 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 1)
	}

	// Make sure packet that is too small is dropped.
	buf.CapLength(2)
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 1 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 1)
	}
}

func sendTo(t *testing.T, s *stack.Stack, addr tcpip.Address, payload buffer.View) {
	r, err := s.FindRoute(0, "", addr, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatal("FindRoute failed:", err)
	}
	defer r.Release()

	hdr := buffer.NewPrependable(int(r.MaxHeaderLength()))
	if err := r.WritePacket(nil /* gso */, hdr, payload.ToVectorisedView(), fakeTransNumber, 123); err != nil {
		t.Error("WritePacket failed:", err)
	}
}

func TestNetworkSend(t *testing.T) {
	// Create a stack with the fake network protocol, one nic, and one
	// address: 1. The route table sends all packets through the only
	// existing nic.
	id, linkEP := channel.New(10, defaultMTU, "")
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatal("NewNIC failed:", err)
	}

	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	// Make sure that the link-layer endpoint received the outbound packet.
	sendTo(t, s, "\x03", nil)
	if c := linkEP.Drain(); c != 1 {
		t.Errorf("packetCount = %d, want %d", c, 1)
	}
}

func TestNetworkSendMultiRoute(t *testing.T) {
	// Create a stack with the fake network protocol, two nics, and two
	// addresses per nic, the first nic has odd address, the second one has
	// even addresses.
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})

	id1, linkEP1 := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id1); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x03"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	id2, linkEP2 := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(2, id2); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(2, fakeNetNumber, "\x02"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	if err := s.AddAddress(2, fakeNetNumber, "\x04"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	// Set a route table that sends all packets with odd destination
	// addresses through the first NIC, and all even destination address
	// through the second one.
	{
		subnet0, err := tcpip.NewSubnet("\x00", "\x01")
		if err != nil {
			t.Fatal(err)
		}
		subnet1, err := tcpip.NewSubnet("\x01", "\x01")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{
			{Destination: subnet1, Gateway: "\x00", NIC: 1},
			{Destination: subnet0, Gateway: "\x00", NIC: 2},
		})
	}

	// Send a packet to an odd destination.
	sendTo(t, s, "\x05", nil)

	if c := linkEP1.Drain(); c != 1 {
		t.Errorf("packetCount = %d, want %d", c, 1)
	}

	// Send a packet to an even destination.
	sendTo(t, s, "\x06", nil)

	if c := linkEP2.Drain(); c != 1 {
		t.Errorf("packetCount = %d, want %d", c, 1)
	}
}

func testRoute(t *testing.T, s *stack.Stack, nic tcpip.NICID, srcAddr, dstAddr, expectedSrcAddr tcpip.Address) {
	r, err := s.FindRoute(nic, srcAddr, dstAddr, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatal("FindRoute failed:", err)
	}

	defer r.Release()

	if r.LocalAddress != expectedSrcAddr {
		t.Fatalf("Bad source address: expected %v, got %v", expectedSrcAddr, r.LocalAddress)
	}

	if r.RemoteAddress != dstAddr {
		t.Fatalf("Bad destination address: expected %v, got %v", dstAddr, r.RemoteAddress)
	}
}

func testNoRoute(t *testing.T, s *stack.Stack, nic tcpip.NICID, srcAddr, dstAddr tcpip.Address) {
	_, err := s.FindRoute(nic, srcAddr, dstAddr, fakeNetNumber, false /* multicastLoop */)
	if err != tcpip.ErrNoRoute {
		t.Fatalf("FindRoute returned unexpected error, got = %v, want = %s", err, tcpip.ErrNoRoute)
	}
}

func TestRoutes(t *testing.T) {
	// Create a stack with the fake network protocol, two nics, and two
	// addresses per nic, the first nic has odd address, the second one has
	// even addresses.
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})

	id1, _ := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id1); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x03"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	id2, _ := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(2, id2); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(2, fakeNetNumber, "\x02"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	if err := s.AddAddress(2, fakeNetNumber, "\x04"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	// Set a route table that sends all packets with odd destination
	// addresses through the first NIC, and all even destination address
	// through the second one.
	{
		subnet0, err := tcpip.NewSubnet("\x00", "\x01")
		if err != nil {
			t.Fatal(err)
		}
		subnet1, err := tcpip.NewSubnet("\x01", "\x01")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{
			{Destination: subnet1, Gateway: "\x00", NIC: 1},
			{Destination: subnet0, Gateway: "\x00", NIC: 2},
		})
	}

	// Test routes to odd address.
	testRoute(t, s, 0, "", "\x05", "\x01")
	testRoute(t, s, 0, "\x01", "\x05", "\x01")
	testRoute(t, s, 1, "\x01", "\x05", "\x01")
	testRoute(t, s, 0, "\x03", "\x05", "\x03")
	testRoute(t, s, 1, "\x03", "\x05", "\x03")

	// Test routes to even address.
	testRoute(t, s, 0, "", "\x06", "\x02")
	testRoute(t, s, 0, "\x02", "\x06", "\x02")
	testRoute(t, s, 2, "\x02", "\x06", "\x02")
	testRoute(t, s, 0, "\x04", "\x06", "\x04")
	testRoute(t, s, 2, "\x04", "\x06", "\x04")

	// Try to send to odd numbered address from even numbered ones, then
	// vice-versa.
	testNoRoute(t, s, 0, "\x02", "\x05")
	testNoRoute(t, s, 2, "\x02", "\x05")
	testNoRoute(t, s, 0, "\x04", "\x05")
	testNoRoute(t, s, 2, "\x04", "\x05")

	testNoRoute(t, s, 0, "\x01", "\x06")
	testNoRoute(t, s, 1, "\x01", "\x06")
	testNoRoute(t, s, 0, "\x03", "\x06")
	testNoRoute(t, s, 1, "\x03", "\x06")
}

func TestAddressRemoval(t *testing.T) {
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})

	id, linkEP := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	buf := buffer.NewView(30)

	// Write a packet, and check that it gets delivered.
	fakeNet.packetCount[1] = 0
	buf[0] = 1
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}

	// Remove the address, then check that packet doesn't get delivered
	// anymore.
	if err := s.RemoveAddress(1, "\x01"); err != nil {
		t.Fatal("RemoveAddress failed:", err)
	}

	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}

	// Check that removing the same address fails.
	if err := s.RemoveAddress(1, "\x01"); err != tcpip.ErrBadLocalAddress {
		t.Fatalf("RemoveAddress returned unexpected error, got = %v, want = %s", err, tcpip.ErrBadLocalAddress)
	}
}

func TestDelayedRemovalDueToRoute(t *testing.T) {
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})

	id, linkEP := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	buf := buffer.NewView(30)

	// Write a packet, and check that it gets delivered.
	fakeNet.packetCount[1] = 0
	buf[0] = 1
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}

	// Get a route, check that packet is still deliverable.
	r, err := s.FindRoute(0, "", "\x02", fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatal("FindRoute failed:", err)
	}

	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 2 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 2)
	}

	// Remove the address, then check that packet is still deliverable
	// because the route is keeping the address alive.
	if err := s.RemoveAddress(1, "\x01"); err != nil {
		t.Fatal("RemoveAddress failed:", err)
	}

	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 3 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 3)
	}

	// Check that removing the same address fails.
	if err := s.RemoveAddress(1, "\x01"); err != tcpip.ErrBadLocalAddress {
		t.Fatalf("RemoveAddress returned unexpected error, got = %v, want = %s", err, tcpip.ErrBadLocalAddress)
	}

	// Release the route, then check that packet is not deliverable anymore.
	r.Release()
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 3 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 3)
	}
}

func TestPromiscuousMode(t *testing.T) {
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})

	id, linkEP := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	buf := buffer.NewView(30)

	// Write a packet, and check that it doesn't get delivered as we don't
	// have a matching endpoint.
	fakeNet.packetCount[1] = 0
	buf[0] = 1
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 0 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 0)
	}

	// Set promiscuous mode, then check that packet is delivered.
	if err := s.SetPromiscuousMode(1, true); err != nil {
		t.Fatal("SetPromiscuousMode failed:", err)
	}

	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}

	// Check that we can't get a route as there is no local address.
	_, err := s.FindRoute(0, "", "\x02", fakeNetNumber, false /* multicastLoop */)
	if err != tcpip.ErrNoRoute {
		t.Fatalf("FindRoute returned unexpected error: got = %v, want = %s", err, tcpip.ErrNoRoute)
	}

	// Set promiscuous mode to false, then check that packet can't be
	// delivered anymore.
	if err := s.SetPromiscuousMode(1, false); err != nil {
		t.Fatal("SetPromiscuousMode failed:", err)
	}

	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
}

func TestAddressSpoofing(t *testing.T) {
	srcAddr := tcpip.Address("\x01")
	dstAddr := tcpip.Address("\x02")

	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})

	id, _ := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, dstAddr); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	// With address spoofing disabled, FindRoute does not permit an address
	// that was not added to the NIC to be used as the source.
	r, err := s.FindRoute(0, srcAddr, dstAddr, fakeNetNumber, false /* multicastLoop */)
	if err == nil {
		t.Errorf("FindRoute succeeded with route %+v when it should have failed", r)
	}

	// With address spoofing enabled, FindRoute permits any address to be used
	// as the source.
	if err := s.SetSpoofing(1, true); err != nil {
		t.Fatal("SetSpoofing failed:", err)
	}
	r, err = s.FindRoute(0, srcAddr, dstAddr, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatal("FindRoute failed:", err)
	}
	if r.LocalAddress != srcAddr {
		t.Errorf("Route has wrong local address: got %v, wanted %v", r.LocalAddress, srcAddr)
	}
	if r.RemoteAddress != dstAddr {
		t.Errorf("Route has wrong remote address: got %v, wanted %v", r.RemoteAddress, dstAddr)
	}
}

func TestBroadcastNeedsNoRoute(t *testing.T) {
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})

	id, _ := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}
	s.SetRouteTable([]tcpip.Route{})

	// If there is no endpoint, it won't work.
	if _, err := s.FindRoute(1, header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, false /* multicastLoop */); err != tcpip.ErrNetworkUnreachable {
		t.Fatalf("got FindRoute(1, %v, %v, %v) = %v, want = %s", header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, err, tcpip.ErrNetworkUnreachable)
	}

	if err := s.AddAddress(1, fakeNetNumber, header.IPv4Any); err != nil {
		t.Fatalf("AddAddress(%v, %v) failed: %s", fakeNetNumber, header.IPv4Any, err)
	}
	r, err := s.FindRoute(1, header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(1, %v, %v, %v) failed: %v", header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, err)
	}

	if r.LocalAddress != header.IPv4Any {
		t.Errorf("Bad local address: got %v, want = %v", r.LocalAddress, header.IPv4Any)
	}

	if r.RemoteAddress != header.IPv4Broadcast {
		t.Errorf("Bad remote address: got %v, want = %v", r.RemoteAddress, header.IPv4Broadcast)
	}

	// If the NIC doesn't exist, it won't work.
	if _, err := s.FindRoute(2, header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, false /* multicastLoop */); err != tcpip.ErrNetworkUnreachable {
		t.Fatalf("got FindRoute(2, %v, %v, %v) = %v want = %v", header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, err, tcpip.ErrNetworkUnreachable)
	}
}

func TestMulticastOrIPv6LinkLocalNeedsNoRoute(t *testing.T) {
	for _, tc := range []struct {
		name        string
		routeNeeded bool
		address     tcpip.Address
	}{
		// IPv4 multicast address range: 224.0.0.0 - 239.255.255.255
		//                <=>  0xe0.0x00.0x00.0x00 - 0xef.0xff.0xff.0xff
		{"IPv4 Multicast 1", false, "\xe0\x00\x00\x00"},
		{"IPv4 Multicast 2", false, "\xef\xff\xff\xff"},
		{"IPv4 Unicast 1", true, "\xdf\xff\xff\xff"},
		{"IPv4 Unicast 2", true, "\xf0\x00\x00\x00"},
		{"IPv4 Unicast 3", true, "\x00\x00\x00\x00"},

		// IPv6 multicast address is 0xff[8] + flags[4] + scope[4] + groupId[112]
		{"IPv6 Multicast 1", false, "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Multicast 2", false, "\xff\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Multicast 3", false, "\xff\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"},

		// IPv6 link-local address starts with fe80::/10.
		{"IPv6 Unicast Link-Local 1", false, "\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Unicast Link-Local 2", false, "\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
		{"IPv6 Unicast Link-Local 3", false, "\xfe\x80\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff"},
		{"IPv6 Unicast Link-Local 4", false, "\xfe\xbf\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Unicast Link-Local 5", false, "\xfe\xbf\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"},

		// IPv6 addresses that are neither multicast nor link-local.
		{"IPv6 Unicast Not Link-Local 1", true, "\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Unicast Not Link-Local 2", true, "\xf0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"},
		{"IPv6 Unicast Not Link-local 3", true, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Unicast Not Link-Local 4", true, "\xfe\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Unicast Not Link-Local 5", true, "\xfe\xdf\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Unicast Not Link-Local 6", true, "\xfd\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Unicast Not Link-Local 7", true, "\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := stack.New([]string{"fakeNet"}, nil, stack.Options{})

			id, _ := channel.New(10, defaultMTU, "")
			if err := s.CreateNIC(1, id); err != nil {
				t.Fatal("CreateNIC failed:", err)
			}

			s.SetRouteTable([]tcpip.Route{})

			var anyAddr tcpip.Address
			if len(tc.address) == header.IPv4AddressSize {
				anyAddr = header.IPv4Any
			} else {
				anyAddr = header.IPv6Any
			}

			want := tcpip.ErrNetworkUnreachable
			if tc.routeNeeded {
				want = tcpip.ErrNoRoute
			}

			// If there is no endpoint, it won't work.
			if _, err := s.FindRoute(1, anyAddr, tc.address, fakeNetNumber, false /* multicastLoop */); err != want {
				t.Fatalf("got FindRoute(1, %v, %v, %v) = %v, want = %v", anyAddr, tc.address, fakeNetNumber, err, want)
			}

			if err := s.AddAddress(1, fakeNetNumber, anyAddr); err != nil {
				t.Fatalf("AddAddress(%v, %v) failed: %v", fakeNetNumber, anyAddr, err)
			}

			if r, err := s.FindRoute(1, anyAddr, tc.address, fakeNetNumber, false /* multicastLoop */); tc.routeNeeded {
				// Route table is empty but we need a route, this should cause an error.
				if err != tcpip.ErrNoRoute {
					t.Fatalf("got FindRoute(1, %v, %v, %v) = %v, want = %v", anyAddr, tc.address, fakeNetNumber, err, tcpip.ErrNoRoute)
				}
			} else {
				if err != nil {
					t.Fatalf("FindRoute(1, %v, %v, %v) failed: %v", anyAddr, tc.address, fakeNetNumber, err)
				}
				if r.LocalAddress != anyAddr {
					t.Errorf("Bad local address: got %v, want = %v", r.LocalAddress, anyAddr)
				}
				if r.RemoteAddress != tc.address {
					t.Errorf("Bad remote address: got %v, want = %v", r.RemoteAddress, tc.address)
				}
			}
			// If the NIC doesn't exist, it won't work.
			if _, err := s.FindRoute(2, anyAddr, tc.address, fakeNetNumber, false /* multicastLoop */); err != want {
				t.Fatalf("got FindRoute(2, %v, %v, %v) = %v want = %v", anyAddr, tc.address, fakeNetNumber, err, want)
			}
		})
	}
}

// Set the subnet, then check that packet is delivered.
func TestSubnetAcceptsMatchingPacket(t *testing.T) {
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})

	id, linkEP := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	buf := buffer.NewView(30)

	buf[0] = 1
	fakeNet.packetCount[1] = 0
	subnet, err := tcpip.NewSubnet(tcpip.Address("\x00"), tcpip.AddressMask("\xF0"))
	if err != nil {
		t.Fatal("NewSubnet failed:", err)
	}
	if err := s.AddSubnet(1, fakeNetNumber, subnet); err != nil {
		t.Fatal("AddSubnet failed:", err)
	}

	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
}

// Set the subnet, then check that CheckLocalAddress returns the correct NIC.
func TestCheckLocalAddressForSubnet(t *testing.T) {
	const nicID tcpip.NICID = 1
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})

	id, _ := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(nicID, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: nicID}})
	}

	subnet, err := tcpip.NewSubnet(tcpip.Address("\xa0"), tcpip.AddressMask("\xf0"))

	if err != nil {
		t.Fatal("NewSubnet failed:", err)
	}
	if err := s.AddSubnet(nicID, fakeNetNumber, subnet); err != nil {
		t.Fatal("AddSubnet failed:", err)
	}

	// Loop over all subnet addresses and check them.
	numOfAddresses := 1 << uint(8-subnet.Prefix())
	if numOfAddresses < 1 || numOfAddresses > 255 {
		t.Fatalf("got numOfAddresses = %d, want = [1 .. 255] (subnet=%s)", numOfAddresses, subnet)
	}
	addr := []byte(subnet.ID())
	for i := 0; i < numOfAddresses; i++ {
		if gotNicID := s.CheckLocalAddress(0, fakeNetNumber, tcpip.Address(addr)); gotNicID != nicID {
			t.Errorf("got CheckLocalAddress(0, %d, %s) = %d, want = %d", fakeNetNumber, tcpip.Address(addr), gotNicID, nicID)
		}
		addr[0]++
	}

	// Trying the next address should fail since it is outside the subnet range.
	if gotNicID := s.CheckLocalAddress(0, fakeNetNumber, tcpip.Address(addr)); gotNicID != 0 {
		t.Errorf("got CheckLocalAddress(0, %d, %s) = %d, want = %d", fakeNetNumber, tcpip.Address(addr), gotNicID, 0)
	}
}

// Set destination outside the subnet, then check it doesn't get delivered.
func TestSubnetRejectsNonmatchingPacket(t *testing.T) {
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})

	id, linkEP := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	buf := buffer.NewView(30)

	buf[0] = 1
	fakeNet.packetCount[1] = 0
	subnet, err := tcpip.NewSubnet(tcpip.Address("\x10"), tcpip.AddressMask("\xF0"))
	if err != nil {
		t.Fatal("NewSubnet failed:", err)
	}
	if err := s.AddSubnet(1, fakeNetNumber, subnet); err != nil {
		t.Fatal("AddSubnet failed:", err)
	}
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 0 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 0)
	}
}

func TestNetworkOptions(t *testing.T) {
	s := stack.New([]string{"fakeNet"}, []string{}, stack.Options{})

	// Try an unsupported network protocol.
	if err := s.SetNetworkProtocolOption(tcpip.NetworkProtocolNumber(99999), fakeNetGoodOption(false)); err != tcpip.ErrUnknownProtocol {
		t.Fatalf("SetNetworkProtocolOption(fakeNet2, blah, false) = %v, want = tcpip.ErrUnknownProtocol", err)
	}

	testCases := []struct {
		option   interface{}
		wantErr  *tcpip.Error
		verifier func(t *testing.T, p stack.NetworkProtocol)
	}{
		{fakeNetGoodOption(true), nil, func(t *testing.T, p stack.NetworkProtocol) {
			t.Helper()
			fakeNet := p.(*fakeNetworkProtocol)
			if fakeNet.opts.good != true {
				t.Fatalf("fakeNet.opts.good = false, want = true")
			}
			var v fakeNetGoodOption
			if err := s.NetworkProtocolOption(fakeNetNumber, &v); err != nil {
				t.Fatalf("s.NetworkProtocolOption(fakeNetNumber, &v) = %v, want = nil, where v is option %T", v, err)
			}
			if v != true {
				t.Fatalf("s.NetworkProtocolOption(fakeNetNumber, &v) returned v = %v, want = true", v)
			}
		}},
		{fakeNetBadOption(true), tcpip.ErrUnknownProtocolOption, nil},
		{fakeNetInvalidValueOption(1), tcpip.ErrInvalidOptionValue, nil},
	}
	for _, tc := range testCases {
		if got := s.SetNetworkProtocolOption(fakeNetNumber, tc.option); got != tc.wantErr {
			t.Errorf("s.SetNetworkProtocolOption(fakeNet, %v) = %v, want = %v", tc.option, got, tc.wantErr)
		}
		if tc.verifier != nil {
			tc.verifier(t, s.NetworkProtocolInstance(fakeNetNumber))
		}
	}
}

func TestSubnetAddRemove(t *testing.T) {
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})
	id, _ := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	addr := tcpip.Address("\x01\x01\x01\x01")
	mask := tcpip.AddressMask(strings.Repeat("\xff", len(addr)))
	subnet, err := tcpip.NewSubnet(addr, mask)
	if err != nil {
		t.Fatal("NewSubnet failed:", err)
	}

	if contained, err := s.ContainsSubnet(1, subnet); err != nil {
		t.Fatal("ContainsSubnet failed:", err)
	} else if contained {
		t.Fatal("got s.ContainsSubnet(...) = true, want = false")
	}

	if err := s.AddSubnet(1, fakeNetNumber, subnet); err != nil {
		t.Fatal("AddSubnet failed:", err)
	}

	if contained, err := s.ContainsSubnet(1, subnet); err != nil {
		t.Fatal("ContainsSubnet failed:", err)
	} else if !contained {
		t.Fatal("got s.ContainsSubnet(...) = false, want = true")
	}

	if err := s.RemoveSubnet(1, subnet); err != nil {
		t.Fatal("RemoveSubnet failed:", err)
	}

	if contained, err := s.ContainsSubnet(1, subnet); err != nil {
		t.Fatal("ContainsSubnet failed:", err)
	} else if contained {
		t.Fatal("got s.ContainsSubnet(...) = true, want = false")
	}
}

func TestGetMainNICAddressAddPrimaryNonPrimary(t *testing.T) {
	for _, addrLen := range []int{4, 16} {
		t.Run(fmt.Sprintf("addrLen=%d", addrLen), func(t *testing.T) {
			for canBe := 0; canBe < 3; canBe++ {
				t.Run(fmt.Sprintf("canBe=%d", canBe), func(t *testing.T) {
					for never := 0; never < 3; never++ {
						t.Run(fmt.Sprintf("never=%d", never), func(t *testing.T) {
							s := stack.New([]string{"fakeNet"}, nil, stack.Options{})
							id, _ := channel.New(10, defaultMTU, "")
							if err := s.CreateNIC(1, id); err != nil {
								t.Fatal("CreateNIC failed:", err)
							}
							// Insert <canBe> primary and <never> never-primary addresses.
							// Each one will add a network endpoint to the NIC.
							primaryAddrAdded := make(map[tcpip.AddressWithPrefix]struct{})
							for i := 0; i < canBe+never; i++ {
								var behavior stack.PrimaryEndpointBehavior
								if i < canBe {
									behavior = stack.CanBePrimaryEndpoint
								} else {
									behavior = stack.NeverPrimaryEndpoint
								}
								// Add an address and in case of a primary one include a
								// prefixLen.
								address := tcpip.Address(bytes.Repeat([]byte{byte(i)}, addrLen))
								if behavior == stack.CanBePrimaryEndpoint {
									protocolAddress := tcpip.ProtocolAddress{
										Protocol: fakeNetNumber,
										AddressWithPrefix: tcpip.AddressWithPrefix{
											Address:   address,
											PrefixLen: addrLen * 8,
										},
									}
									if err := s.AddProtocolAddressWithOptions(1, protocolAddress, behavior); err != nil {
										t.Fatal("AddProtocolAddressWithOptions failed:", err)
									}
									// Remember the address/prefix.
									primaryAddrAdded[protocolAddress.AddressWithPrefix] = struct{}{}
								} else {
									if err := s.AddAddressWithOptions(1, fakeNetNumber, address, behavior); err != nil {
										t.Fatal("AddAddressWithOptions failed:", err)
									}
								}
							}
							// Check that GetMainNICAddress returns an address if at least
							// one primary address was added. In that case make sure the
							// address/prefixLen matches what we added.
							if len(primaryAddrAdded) == 0 {
								// No primary addresses present, expect an error.
								if _, err := s.GetMainNICAddress(1, fakeNetNumber); err != tcpip.ErrNoLinkAddress {
									t.Fatalf("got s.GetMainNICAddress(...) = %v, wanted = %s", err, tcpip.ErrNoLinkAddress)
								}
							} else {
								// At least one primary address was added, expect a valid
								// address and prefixLen.
								gotAddressWithPefix, err := s.GetMainNICAddress(1, fakeNetNumber)
								if err != nil {
									t.Fatal("GetMainNICAddress failed:", err)
								}
								if _, ok := primaryAddrAdded[gotAddressWithPefix]; !ok {
									t.Fatalf("GetMainNICAddress: got addressWithPrefix = %v, wanted any in {%v}", gotAddressWithPefix, primaryAddrAdded)
								}
							}
						})
					}
				})
			}
		})
	}
}

func TestGetMainNICAddressAddRemove(t *testing.T) {
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})
	id, _ := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	for _, tc := range []struct {
		name      string
		address   tcpip.Address
		prefixLen int
	}{
		{"IPv4", "\x01\x01\x01\x01", 24},
		{"IPv6", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 116},
	} {
		t.Run(tc.name, func(t *testing.T) {
			protocolAddress := tcpip.ProtocolAddress{
				Protocol: fakeNetNumber,
				AddressWithPrefix: tcpip.AddressWithPrefix{
					Address:   tc.address,
					PrefixLen: tc.prefixLen,
				},
			}
			if err := s.AddProtocolAddress(1, protocolAddress); err != nil {
				t.Fatal("AddProtocolAddress failed:", err)
			}

			// Check that we get the right initial address and prefix length.
			if gotAddressWithPrefix, err := s.GetMainNICAddress(1, fakeNetNumber); err != nil {
				t.Fatal("GetMainNICAddress failed:", err)
			} else if gotAddressWithPrefix != protocolAddress.AddressWithPrefix {
				t.Fatalf("got GetMainNICAddress = %+v, want = %+v", gotAddressWithPrefix, protocolAddress.AddressWithPrefix)
			}

			if err := s.RemoveAddress(1, protocolAddress.AddressWithPrefix.Address); err != nil {
				t.Fatal("RemoveAddress failed:", err)
			}

			// Check that we get an error after removal.
			if _, err := s.GetMainNICAddress(1, fakeNetNumber); err != tcpip.ErrNoLinkAddress {
				t.Fatalf("got s.GetMainNICAddress(...) = %v, want = %s", err, tcpip.ErrNoLinkAddress)
			}
		})
	}
}

// Simple network address generator. Good for 255 addresses.
type addressGenerator struct{ cnt byte }

func (g *addressGenerator) next(addrLen int) tcpip.Address {
	g.cnt++
	return tcpip.Address(bytes.Repeat([]byte{g.cnt}, addrLen))
}

func verifyAddresses(t *testing.T, expectedAddresses, gotAddresses []tcpip.ProtocolAddress) {
	if len(gotAddresses) != len(expectedAddresses) {
		t.Fatalf("got len(addresses) = %d, wanted = %d", len(gotAddresses), len(expectedAddresses))
	}

	sort.Slice(gotAddresses, func(i, j int) bool {
		return gotAddresses[i].AddressWithPrefix.Address < gotAddresses[j].AddressWithPrefix.Address
	})
	sort.Slice(expectedAddresses, func(i, j int) bool {
		return expectedAddresses[i].AddressWithPrefix.Address < expectedAddresses[j].AddressWithPrefix.Address
	})

	for i, gotAddr := range gotAddresses {
		expectedAddr := expectedAddresses[i]
		if gotAddr != expectedAddr {
			t.Errorf("got address = %+v, wanted = %+v", gotAddr, expectedAddr)
		}
	}
}

func TestAddAddress(t *testing.T) {
	const nicid = 1
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})
	id, _ := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(nicid, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	var addrGen addressGenerator
	expectedAddresses := make([]tcpip.ProtocolAddress, 0, 2)
	for _, addrLen := range []int{4, 16} {
		address := addrGen.next(addrLen)
		if err := s.AddAddress(nicid, fakeNetNumber, address); err != nil {
			t.Fatalf("AddAddress(address=%s) failed: %s", address, err)
		}
		expectedAddresses = append(expectedAddresses, tcpip.ProtocolAddress{
			Protocol:          fakeNetNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{address, fakeDefaultPrefixLen},
		})
	}

	gotAddresses := s.NICInfo()[nicid].ProtocolAddresses
	verifyAddresses(t, expectedAddresses, gotAddresses)
}

func TestAddProtocolAddress(t *testing.T) {
	const nicid = 1
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})
	id, _ := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(nicid, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	var addrGen addressGenerator
	addrLenRange := []int{4, 16}
	prefixLenRange := []int{8, 13, 20, 32}
	expectedAddresses := make([]tcpip.ProtocolAddress, 0, len(addrLenRange)*len(prefixLenRange))
	for _, addrLen := range addrLenRange {
		for _, prefixLen := range prefixLenRange {
			protocolAddress := tcpip.ProtocolAddress{
				Protocol: fakeNetNumber,
				AddressWithPrefix: tcpip.AddressWithPrefix{
					Address:   addrGen.next(addrLen),
					PrefixLen: prefixLen,
				},
			}
			if err := s.AddProtocolAddress(nicid, protocolAddress); err != nil {
				t.Errorf("AddProtocolAddress(%+v) failed: %s", protocolAddress, err)
			}
			expectedAddresses = append(expectedAddresses, protocolAddress)
		}
	}

	gotAddresses := s.NICInfo()[nicid].ProtocolAddresses
	verifyAddresses(t, expectedAddresses, gotAddresses)
}

func TestAddAddressWithOptions(t *testing.T) {
	const nicid = 1
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})
	id, _ := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(nicid, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	addrLenRange := []int{4, 16}
	behaviorRange := []stack.PrimaryEndpointBehavior{stack.CanBePrimaryEndpoint, stack.FirstPrimaryEndpoint, stack.NeverPrimaryEndpoint}
	expectedAddresses := make([]tcpip.ProtocolAddress, 0, len(addrLenRange)*len(behaviorRange))
	var addrGen addressGenerator
	for _, addrLen := range addrLenRange {
		for _, behavior := range behaviorRange {
			address := addrGen.next(addrLen)
			if err := s.AddAddressWithOptions(nicid, fakeNetNumber, address, behavior); err != nil {
				t.Fatalf("AddAddressWithOptions(address=%s, behavior=%d) failed: %s", address, behavior, err)
			}
			expectedAddresses = append(expectedAddresses, tcpip.ProtocolAddress{
				Protocol:          fakeNetNumber,
				AddressWithPrefix: tcpip.AddressWithPrefix{address, fakeDefaultPrefixLen},
			})
		}
	}

	gotAddresses := s.NICInfo()[nicid].ProtocolAddresses
	verifyAddresses(t, expectedAddresses, gotAddresses)
}

func TestAddProtocolAddressWithOptions(t *testing.T) {
	const nicid = 1
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})
	id, _ := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(nicid, id); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	addrLenRange := []int{4, 16}
	prefixLenRange := []int{8, 13, 20, 32}
	behaviorRange := []stack.PrimaryEndpointBehavior{stack.CanBePrimaryEndpoint, stack.FirstPrimaryEndpoint, stack.NeverPrimaryEndpoint}
	expectedAddresses := make([]tcpip.ProtocolAddress, 0, len(addrLenRange)*len(prefixLenRange)*len(behaviorRange))
	var addrGen addressGenerator
	for _, addrLen := range addrLenRange {
		for _, prefixLen := range prefixLenRange {
			for _, behavior := range behaviorRange {
				protocolAddress := tcpip.ProtocolAddress{
					Protocol: fakeNetNumber,
					AddressWithPrefix: tcpip.AddressWithPrefix{
						Address:   addrGen.next(addrLen),
						PrefixLen: prefixLen,
					},
				}
				if err := s.AddProtocolAddressWithOptions(nicid, protocolAddress, behavior); err != nil {
					t.Fatalf("AddProtocolAddressWithOptions(%+v, %d) failed: %s", protocolAddress, behavior, err)
				}
				expectedAddresses = append(expectedAddresses, protocolAddress)
			}
		}
	}

	gotAddresses := s.NICInfo()[nicid].ProtocolAddresses
	verifyAddresses(t, expectedAddresses, gotAddresses)
}

func TestNICStats(t *testing.T) {
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})
	id1, linkEP1 := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id1); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}
	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}
	// Route all packets for address \x01 to NIC 1.
	{
		subnet, err := tcpip.NewSubnet("\x01", "\xff")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	// Send a packet to address 1.
	buf := buffer.NewView(30)
	linkEP1.Inject(fakeNetNumber, buf.ToVectorisedView())
	if got, want := s.NICInfo()[1].Stats.Rx.Packets.Value(), uint64(1); got != want {
		t.Errorf("got Rx.Packets.Value() = %d, want = %d", got, want)
	}

	if got, want := s.NICInfo()[1].Stats.Rx.Bytes.Value(), uint64(len(buf)); got != want {
		t.Errorf("got Rx.Bytes.Value() = %d, want = %d", got, want)
	}

	payload := buffer.NewView(10)
	// Write a packet out via the address for NIC 1
	sendTo(t, s, "\x01", payload)
	want := uint64(linkEP1.Drain())
	if got := s.NICInfo()[1].Stats.Tx.Packets.Value(); got != want {
		t.Errorf("got Tx.Packets.Value() = %d, linkEP1.Drain() = %d", got, want)
	}

	if got, want := s.NICInfo()[1].Stats.Tx.Bytes.Value(), uint64(len(payload)); got != want {
		t.Errorf("got Tx.Bytes.Value() = %d, want = %d", got, want)
	}
}

func TestNICForwarding(t *testing.T) {
	// Create a stack with the fake network protocol, two NICs, each with
	// an address.
	s := stack.New([]string{"fakeNet"}, nil, stack.Options{})
	s.SetForwarding(true)

	id1, linkEP1 := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id1); err != nil {
		t.Fatal("CreateNIC #1 failed:", err)
	}
	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress #1 failed:", err)
	}

	id2, linkEP2 := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(2, id2); err != nil {
		t.Fatal("CreateNIC #2 failed:", err)
	}
	if err := s.AddAddress(2, fakeNetNumber, "\x02"); err != nil {
		t.Fatal("AddAddress #2 failed:", err)
	}

	// Route all packets to address 3 to NIC 2.
	{
		subnet, err := tcpip.NewSubnet("\x03", "\xff")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 2}})
	}

	// Send a packet to address 3.
	buf := buffer.NewView(30)
	buf[0] = 3
	linkEP1.Inject(fakeNetNumber, buf.ToVectorisedView())

	select {
	case <-linkEP2.C:
	default:
		t.Fatal("Packet not forwarded")
	}

	// Test that forwarding increments Tx stats correctly.
	if got, want := s.NICInfo()[2].Stats.Tx.Packets.Value(), uint64(1); got != want {
		t.Errorf("got Tx.Packets.Value() = %d, want = %d", got, want)
	}

	if got, want := s.NICInfo()[2].Stats.Tx.Bytes.Value(), uint64(len(buf)); got != want {
		t.Errorf("got Tx.Bytes.Value() = %d, want = %d", got, want)
	}
}

func init() {
	stack.RegisterNetworkProtocolFactory("fakeNet", func() stack.NetworkProtocol {
		return &fakeNetworkProtocol{}
	})
}
