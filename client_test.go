package dhcplib_test

import (
	"github.com/goofool/dhcplib"
	"log"
)

func ExampleNewClient() {
	// dhcp client mac
	srcmac := "12:34:56:78:9a:ab"
	// dhcp server  mac
	peermac := "50:64:2B:B5:81:32"
	hostname := "IPhoneX-AA"
	// the interface name
	ifname := "\\Device\\NPF_{4392CADC-8E95-4D1E-B782-440E3434A5FF}"
	client, err := dhcplib.NewClient(srcmac, peermac, ifname, hostname)
	if err != nil {
		log.Println(srcmac, err)
		return
	}
	err = client.Start()
	if err != nil {
		log.Println(srcmac, err)
		return
	}

	log.Println(client.IP)
}
