package dhcplib

import (
	"log"
	"math/rand"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Client struct {
	HW         net.HardwareAddr
	PeerHw     net.HardwareAddr
	IP         net.IP
	IFName     string
	ethLayer   *layers.Ethernet
	ipLayer    *layers.IPv4
	udpLayer   *layers.UDP
	dhcpLayer  *layers.DHCPv4
	opts       gopacket.SerializeOptions
	pcapHandle *pcap.Handle
	lease      uint32
	t1         uint32
	t2         uint32
}

func NewClient(smac, peermac, ifname, hostname string) (*Client, error) {
	hw, err := net.ParseMAC(smac)
	if err != nil {
		return nil, err
	}
	peerhw, err := net.ParseMAC(peermac)
	if err != nil {
		return nil, err
	}
	srcIP := net.ParseIP("0.0.0.0")

	//eth layer
	eth := &layers.Ethernet{}
	eth.SrcMAC = hw
	eth.DstMAC, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	eth.EthernetType = layers.EthernetTypeIPv4

	//ip layer
	ip := &layers.IPv4{}
	ip.Version = 4
	ip.Protocol = layers.IPProtocolUDP
	ip.TTL = 64
	ip.SrcIP = srcIP
	ip.DstIP = net.ParseIP("255.255.255.255")

	//udp layer
	udp := &layers.UDP{
		SrcPort:  68,
		DstPort:  67,
		Length:   0,
		Checksum: 0,
	}

	//dhcpv4 layer and options
	dhcp4 := &layers.DHCPv4{}
	dhcp4.Flags = 0x0000
	dhcp4.Operation = layers.DHCPOpRequest
	dhcp4.HardwareType = layers.LinkTypeEthernet
	dhcp4.Xid = uint32(rand.Int31())
	dhcp4.ClientIP = net.ParseIP("0.0.0.0")
	dhcp4.ClientHWAddr = hw
	hn := []byte(hostname)

	//dhcpv4 options
	dhcp4Opts := []layers.DHCPOption{
		{
			Type:   layers.DHCPOptMessageType,
			Length: 1,
			Data:   []byte{byte(layers.DHCPMsgTypeDiscover)},
		},
		{
			Type:   layers.DHCPOptRequestIP,
			Length: 4,
			Data:   srcIP.To4(),
		},
		{
			Type:   layers.DHCPOptClientID,
			Length: uint8(len(hw)) + 1,
			Data:   append([]byte{0x01}, []byte(hw)...),
		},
		{
			Type:   layers.DHCPOptHostname,
			Length: uint8(len(hostname)),
			Data:   hn,
		},

		{
			Type: layers.DHCPOptEnd,
		},
	}
	dhcp4.Options = dhcp4Opts

	//create read packet handle
	writeHandle, err := pcap.OpenLive(ifname, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Println("pcap open read handle error: ", err.Error())
		return nil, err
	}

	c := &Client{
		HW:        hw,
		PeerHw:    peerhw,
		IP:        srcIP,
		IFName:    ifname,
		ethLayer:  eth,
		ipLayer:   ip,
		udpLayer:  udp,
		dhcpLayer: dhcp4,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		pcapHandle: writeHandle,
	}

	return c, nil
}

func (c Client) Lease() uint32 {
	return c.lease
}

func (c Client) T1() uint32 {
	return c.t1
}

func (c Client) T2() uint32 {
	return c.t2
}
