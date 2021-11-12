# Quick start

```golang
package main

import (
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/goofool/go-dhcp"
)

var wg sync.WaitGroup

var ifName = flag.String("f", "\\Device\\NPF_{4392CADC-8E95-4D1E-B782-440E3434A5FF}", "ifname")
var num = flag.Int("n", 1, "dhcp client nubmer")
var peermac = flag.String("m", "50:64:2B:E6:23:F8", "peer mac")

func main() {

	flag.Parse()
	if *peermac == "" {
		log.Fatal("useage: dhcplib -m 6A:20:5E:12:49:9C -n 100")
	}

	for i := 0; i < *num; i++ {
		wg.Add(1)
		mac := fmt.Sprintf("12:34:56:78:9a:%02x", i)

		go func(s string) {
			defer wg.Done()
			hostname := fmt.Sprintf("IPhoneX-AA%d", i)
			client, err := dhcplib.NewClient(s, *peermac, *ifName, hostname)
			if err != nil {
				log.Println(s, err)
				return
			}
			err = client.Start()
			if err != nil {
				log.Println(s, err)
				return
			}
			log.Println(s, client.IP.String(), client.Lease(), client.T1(), client.T2())
			go client.HandleARPRequest()
			go client.HandleICMPEchoRequest()

			log.Println(s, client.GraARPSend())
			log.Println(s, "sent gratuitous arp")
			for {

				log.Println(s, client.DNSQuerySend("114.114.114.114"))
				log.Println(s, "sent dns query")
				time.Sleep(time.Second * 10)
			}
		}(mac)

		time.Sleep(time.Millisecond * 100)
	}

	wg.Wait()
}

```

