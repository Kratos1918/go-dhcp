package dhcplib

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

func (c *Client) Start() error {
	readHandle, err := pcap.OpenLive(c.IFName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Println(c.HW.String(), "pcap open write handle error: ", err.Error())
		return err
	}
	defer readHandle.Close()
	err = readHandle.SetBPFFilter(fmt.Sprintf("ether dst %s", c.HW.String()))
	if err != nil {
		log.Println("pcap set bpf filter error: ", err.Error())
		return err
	}

	readChan := make(chan layers.DHCPMsgType, 1)
	packConn := make(chan *layers.DHCPv4)
	go readPacket(readHandle, readChan, packConn)

	err = c.sendDiscover()
	if err != nil {
		log.Println(c.HW, err)
		return err
	}
	readChan <- layers.DHCPMsgTypeOffer
	offer := <-packConn
	if offer == nil {
		log.Println(c.HW.String(), " offer is nil")
		return errors.New("no offer packet received")
	}

	err = c.sendRequest(offer.YourClientIP)
	if err != nil {
		log.Println(c.HW, err)
		return err
	}
	readChan <- layers.DHCPMsgTypeAck
	ack := <-packConn
	if ack == nil {
		log.Println(c.HW.String(), " ack is nil")
		return errors.New("no ack packet received")
	}

	c.IP = ack.YourClientIP

	for _, o := range ack.Options {
		if o.Type == layers.DHCPOptT1 {
			c.t1 = binary.BigEndian.Uint32(o.Data)
		}
		if o.Type == layers.DHCPOptT2 {
			c.t2 = binary.BigEndian.Uint32(o.Data)
		}
		if o.Type == layers.DHCPOptLeaseTime {
			c.lease = binary.BigEndian.Uint32(o.Data)
		}
	}

	close(readChan)
	close(packConn)

	return nil
}

func (c *Client) HandleARPRequest() {
	readHandle, err := pcap.OpenLive(c.IFName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Println(c.HW.String(), "pcap open write handle error: ", err.Error())
		return
	}
	defer readHandle.Close()

	closeChan := make(chan int, 1)

	ipStrHex := hex.EncodeToString(c.IP.To4())
	filter := fmt.Sprintf("(arp) and (ether[38:4]=0x%s) and (not ether src %s)", ipStrHex, c.HW.String())
	log.Println("BPFFilter is: ", filter)
	err = readHandle.SetBPFFilter(filter)
	if err != nil {
		log.Println(c.HW, err)
		return
	}
	src := gopacket.NewPacketSource(readHandle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case packet = <-in:
			{
				if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
					arp := arpLayer.(*layers.ARP)
					if arp.Operation == 1 {
						data := packet.Data()
						copy(data[0:], data[6:12])
						copy(data[6:], c.HW)
						copy(data[32:], c.HW)
						data[21] = layers.ARPReply
						//fmt.Println(hex.Dump(data))
						err := writePacket(c.pcapHandle, data)
						if err != nil {
							log.Println(c.HW, err)
							return
						}
						log.Printf("%s sent arp replay to %s", c.HW, hex.EncodeToString(data[0:6]))
					}
				}
				continue
			}
		case <-closeChan:
			{
				return
			}
		}
	}
}

func (c *Client) HandleICMPEchoRequest() {
	readHandle, err := pcap.OpenLive(c.IFName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Println(c.HW.String(), "pcap open write handle error: ", err.Error())
		return
	}
	defer readHandle.Close()

	closeChan := make(chan int, 1)

	ipStrHex := hex.EncodeToString(c.IP.To4())
	filter := fmt.Sprintf("(icmp) and (ether[30:4]=0x%s) and (not ether src %s)", ipStrHex, c.HW.String())
	log.Println("BPFFilter is: ", filter)
	err = readHandle.SetBPFFilter(filter)
	if err != nil {
		log.Println(c.HW, err)
		return
	}
	src := gopacket.NewPacketSource(readHandle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case packet = <-in:
			{
				if icmpv4Layer := packet.Layer(layers.LayerTypeICMPv4); icmpv4Layer != nil {
					icmpv4 := icmpv4Layer.(*layers.ICMPv4)
					if icmpv4.TypeCode.Type() == 8 {
						data := packet.Data()
						// swap src mac and dst mac
						dmac := make([]byte, 6)
						copy(dmac, data[0:6])
						copy(data[0:], data[6:12])
						copy(data[6:12], dmac)

						// swap src ip and dst mac
						dip := make([]byte, 4)
						copy(dip, data[26:30])
						copy(data[26:30], data[30:34])
						copy(data[30:34], dip)

						// set checksum 0x0000
						copy(data[36:38], []byte{0, 0})

						// change icmp type to replay
						data[34] = layers.ICMPv4TypeEchoReply
						//fmt.Println(hex.Dump(data))

						// calculate the new checksum
						binary.BigEndian.PutUint16(data[36:38], ^checkSum(data[34:]))

						err := writePacket(c.pcapHandle, data)
						if err != nil {
							log.Println(c.HW, err)
							return
						}
						log.Printf("%s sent icmp replay to %s", c.HW, hex.EncodeToString(dip))
					}
				}
				continue
			}
		case <-closeChan:
			{
				return
			}
		}
	}
}

func (c *Client) sendDiscover() error {
	buff := gopacket.NewSerializeBuffer()
	dhcp4Opts := c.dhcpLayer.Options
	dhcp4Opts[0].Data = []byte{byte(layers.DHCPMsgTypeDiscover)}

	err := c.udpLayer.SetNetworkLayerForChecksum(c.ipLayer)
	if err != nil {
		log.Println(c.HW, err)
		return err
	}

	/*
	   	err = c.dhcpLayer.SerializeTo(buff, c.opts)
	   	if err != nil {
	   		log.Println(c.HW, "sendDiscover Serialize UDP error: ", err)
	   		return err
	   	}

	       err = c.udpLayer.SerializeTo(buff, c.opts)
	   	if err != nil {
	   		log.Println(c.HW, err)
	   		return err
	   	}
	   	err = c.ipLayer.SerializeTo(buff, c.opts)
	   	if err != nil {
	   		log.Println(c.HW, err)
	   		return err
	   	}
	   	err = c.ethLayer.SerializeTo(buff, c.opts)
	   	if err != nil {
	   		log.Println(c.HW, err)
	   		return err
	   	}*/

	err = gopacket.SerializeLayers(buff, c.opts,
		c.ethLayer,
		c.ipLayer,
		c.udpLayer,
		c.dhcpLayer)

	if err != nil {
		log.Println(c.HW, err)
		return err
	}

	//fmt.Println(hex.Dump(buff.Bytes()))

	return writePacket(c.pcapHandle, buff.Bytes())
}

func (c *Client) sendRequest(requestIP net.IP) error {
	buff := gopacket.NewSerializeBuffer()

	dhcp4Opts := c.dhcpLayer.Options
	dhcp4Opts[1].Data = requestIP.To4()
	dhcp4Opts[0].Data = []byte{byte(layers.DHCPMsgTypeRequest)}

	err := c.udpLayer.SetNetworkLayerForChecksum(c.ipLayer)
	if err != nil {
		log.Println(c.HW, err)
		return err
	}

	/*	err = c.dhcpLayer.SerializeTo(buff, c.opts)
		if err != nil {
			log.Println(c.HW, err)
			return err
		}
		err = c.udpLayer.SerializeTo(buff, c.opts)
		if err != nil {
			log.Println(c.HW, "sendRequest Serialize UDP error: ", err)
			return err
		}
		err = c.ipLayer.SerializeTo(buff, c.opts)
		if err != nil {
			log.Println(c.HW, err)
			return err
		}
		err = c.ethLayer.SerializeTo(buff, c.opts)
		if err != nil {
			log.Println(c.HW, err)
			return err
		}*/

	err = gopacket.SerializeLayers(buff, c.opts,
		c.ethLayer,
		c.ipLayer,
		c.udpLayer,
		c.dhcpLayer)

	if err != nil {
		log.Println(c.HW, err)
		return err
	}

	//fmt.Println(hex.Dump(buff.Bytes()))

	return writePacket(c.pcapHandle, buff.Bytes())
}

func (c *Client) DNSQuerySend(dst string) error {
	dstUDPAddr := net.UDPAddr{
		IP:   net.ParseIP(dst),
		Port: 53,
	}
	buff := gopacket.NewSerializeBuffer()
	//eth layer
	eth := &layers.Ethernet{}
	eth.SrcMAC = c.HW
	eth.DstMAC = c.PeerHw
	eth.EthernetType = layers.EthernetTypeIPv4

	//ip layer
	ip := &layers.IPv4{}
	ip.Version = 4
	ip.Protocol = layers.IPProtocolUDP
	ip.TTL = 64
	ip.SrcIP = c.IP
	ip.DstIP = dstUDPAddr.IP

	//udp layer
	udp := &layers.UDP{
		SrcPort:  12345,
		DstPort:  layers.UDPPort(dstUDPAddr.Port),
		Length:   0,
		Checksum: 0,
	}

	//dns layer
	dns := &layers.DNS{
		ID: 1,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("mi.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
			{
				Name:  make([]byte, 1400),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}

	err := udp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		log.Println(c.HW, err)
		return err
	}

	/*	err = dns.SerializeTo(buff, c.opts)
		if err != nil {
			log.Println(c.HW, "DNSQuerySend Serialize DNS error: ", err)
			return err
		}

		err = udp.SerializeTo(buff, c.opts)
		if err != nil {
			log.Println(c.HW, "DNSQuerySend Serialize UDP error: ", err)
			return err
		}
		err = ip.SerializeTo(buff, c.opts)
		if err != nil {
			log.Println(c.HW, "DNSQuerySend Serialize IP error: ", err)
			return err
		}
		err = eth.SerializeTo(buff, c.opts)
		if err != nil {
			log.Println(c.HW, "DNSQuerySend Serialize Eth error: ", err)
			return err
		}*/

	err = gopacket.SerializeLayers(buff, c.opts,
		eth,
		ip,
		udp,
		dns)

	if err != nil {
		log.Println(c.HW, err)
		return err
	}

	return writePacket(c.pcapHandle, buff.Bytes())

}

func (c *Client) GraARPSend() error {
	buff := gopacket.NewSerializeBuffer()
	//eth layer
	eth := &layers.Ethernet{}
	eth.SrcMAC = c.HW
	eth.DstMAC, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	eth.EthernetType = layers.EthernetTypeARP

	//arp layer
	dsthwaddr, _ := net.ParseMAC("00:00:00:00:00:00")
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1,
		SourceHwAddress:   c.HW,
		SourceProtAddress: c.IP.To4(),
		DstHwAddress:      dsthwaddr,
		DstProtAddress:    c.IP.To4(),
	}

	/*err := arp.SerializeTo(buff, c.opts)
	if err != nil {
		log.Println(c.HW, "GraARPSend Serialize ARP error: ", err)
		return err
	}
	err = eth.SerializeTo(buff, c.opts)
	if err != nil {
		log.Println(c.HW, "GraARPSend Serialize Eth error: ", err)
		return err
	}*/

	err := gopacket.SerializeLayers(buff, c.opts,
		eth,
		arp)

	if err != nil {
		log.Println(c.HW, err)
		return err
	}

	return writePacket(c.pcapHandle, buff.Bytes())
}

func writePacket(handle *pcap.Handle, buf []byte) error {
	if err := handle.WritePacketData(buf); err != nil {
		log.Printf("Failed to send packet: %s\n", err)
		return err
	}
	return nil
}

func readPacket(handle *pcap.Handle, tch <-chan layers.DHCPMsgType, packConn chan<- *layers.DHCPv4) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for t := range tch {
		var packet gopacket.Packet
		select {
		case packet = <-in:
			{
				if dhcp4layer := packet.Layer(layers.LayerTypeDHCPv4); dhcp4layer != nil {
					dhcp4 := dhcp4layer.(*layers.DHCPv4)
					if msgType := dhcp4.Options[0]; msgType.Type == layers.DHCPOptMessageType {
						if msgType.Data[0] == byte(t) {
							packConn <- dhcp4
						}
					}
				}
				continue
			}
		case <-time.After(time.Second * 10):
			packConn <- nil
		}
	}
}

func checkSum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(uint16(data[i])<<8 | uint16(data[i+1]))
	}

	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	//sum = sum + (sum >> 16)
	return uint16(sum)
}
