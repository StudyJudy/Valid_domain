/**
 * @Project :   Kaweh
 * @File    :   xdns.go
 * @Contact :
 * @License :   (C)Copyright 2025
 *
 * @Modify Time        @Author     @Version    @Description
 * ----------------    --------    --------    -----------
 * 2025/6/17 23:49     idealeer    0.0         None
 */
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	iface, srcIP, srcMAC, gtwMAC, domainListFile, dnsFile, dnsList, outputFile string
	rate, waitingTime                                                           uint
	totalCount, sentCount, foundCount                                           uint64
	dnsServers                                                                  []string
	showVersion, dryRun                                                         bool
	packetChan                                                                  = make(
		chan []byte, 10000,
	)
	storeChan = make(
		chan string, 10000,
	)
	srcMACB, gtwMACB net.HardwareAddr
	srcIPB           net.IP
	logLevel         uint
	startTime        time.Time
)

const version = "XDNS v1.0"

func printBanner() {
	cyan := "\033[36m"
	reset := "\033[0m"

	fmt.Println(
		cyan +
			` 
#   __   _______  _   _  _____ 
#   \ \ / /  __ \| \ | |/ ____|
#    \ V /| |  | |  \| | (___  
#     > < | |  | | . ' |\___ \
#    / . \| |__| | |\  |____) |
#   /_/ \_\_____/|_| \_|_____/
` + reset,
	)
	fmt.Println("🔍 XDNS - Fast DNS Domain Checker Using Multiple Resolvers")
	fmt.Println("📦 Version:", version)
	fmt.Println("✨ Supports: high-speed DNS validation with rotating resolvers\n")
}

func initParams() {
	flag.UintVar(&logLevel, "v", 2, "Log verbosity level (0=silent, 1=only result, 2=progress, 3=all)")
	flag.BoolVar(&showVersion, "V", false, "Show version and exit")
	flag.StringVar(&iface, "iface", "ens160", "Network interface")
	flag.StringVar(&srcIP, "srcip", "", "Source IP")
	flag.StringVar(&srcMAC, "srcmac", "", "Source MAC")
	flag.StringVar(&gtwMAC, "gtwmac", "", "Gateway MAC")
	flag.UintVar(&rate, "rate", 1000, "Query rate (qps)")
	flag.StringVar(&domainListFile, "domainlist", "", "Path to domain list file (one domain per line)")
	flag.StringVar(&dnsFile, "dnsfile", "", "Path to DNS server IP list (default 8.8.8.8)")
	flag.StringVar(&dnsList, "dnsList", "", "DNS server IP list with comma separated (default 8.8.8.8)")
	flag.StringVar(&outputFile, "out", "result-<date>.txt", "Output file")
	flag.BoolVar(&dryRun, "dry", false, "Dry run mode (only print domain, dns ip)")
	flag.UintVar(&waitingTime, "wtgtime", 5, "Waiting time (s) until exit")

	flag.Parse()

	if showVersion {
		fmt.Println("XDNS - Multi-resolver DNS checker")
		fmt.Println("Version:", version)
		os.Exit(0)
	}

	if logLevel != 1 {
		printBanner()
		log.Println("Initializing parameters...")
	}

	if !dryRun && (iface == "" || srcIP == "" || srcMAC == "" || gtwMAC == "") {
		log.Fatal("Error: Please specify -iface, -srcip, -srcmac, and -gtwmac")
	}

	if rate == 0 {
		log.Fatal("Error: rate must be > 0")
	}

	if domainListFile == "" {
		log.Fatal("Error: Please specify -domainlist with path to domain list file")
	}

	if dnsFile != "" {
		if logLevel != 1 {
			log.Println("Reading DNS server list...")
		}

		f, err := os.Open(dnsFile)
		if err != nil {
			log.Fatalf("Failed to open DNS file: %v", err)
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" {
				dnsServers = append(dnsServers, ip)
			}
		}

		f.Close()
	}

	if dnsList != "" {
		dnsLists := strings.Split(dnsList, ",")
		for _, ip := range dnsLists {
			dnsServers = append(dnsServers, ip)
		}
	}

	if len(dnsServers) == 0 {
		dnsServers = []string{"8.8.8.8"}
		if logLevel != 1 {
			log.Println("No DNS file specified, using default DNS server: 8.8.8.8")
		}
	}

	if outputFile == "result-<date>.txt" {
		outputFile = fmt.Sprintf("result-%s.txt", time.Now().Format(time.ANSIC))
	}

	// Count domains in the domain list file
	if logLevel != 1 {
		log.Println("Counting domains...")
	}

	f, err := os.Open(domainListFile)
	if err != nil {
		log.Fatalf("Failed to open domain list file: %v", err)
	}

	s := bufio.NewScanner(f)
	for s.Scan() {
		domain := strings.TrimSpace(s.Text())
		if domain != "" {
			totalCount++
		}
	}
	f.Close()

	if totalCount == 0 {
		log.Fatal("Domain list file is empty")
	}

	if logLevel != 1 {
		log.Printf("Total domains to check: %s\n", humanize.Comma(int64(totalCount)))
	}

	if dryRun {
		log.Printf("Dryrun mode, no actual sending...\n")
	} else {
		// Init net
		srcMAC_, _ := hex.DecodeString(strings.ReplaceAll(srcMAC, ":", ""))
		gtwMAC_, _ := hex.DecodeString(strings.ReplaceAll(gtwMAC, ":", ""))
		srcMACB = net.HardwareAddr(srcMAC_)
		gtwMACB = net.HardwareAddr(gtwMAC_)
		srcIPB = net.ParseIP(srcIP)
	}
}

func buildDNSQuery(qname, dnsServer string) []byte {
	ethernetLayer := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMACB,
		DstMAC:       gtwMACB,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}

	ipv4Layer := &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         0,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      srcIPB,
		DstIP:      net.ParseIP(dnsServer),
		Options:    nil,
		Padding:    nil,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(54321),
		DstPort:   layers.UDPPort(53),
		Length:    0,
		Checksum:  0,
	}

	err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	dnsLayer := &layers.DNS{
		BaseLayer:    layers.BaseLayer{},
		ID:           uint16(0),
		QR:           false,
		OpCode:       0,
		AA:           true,
		TC:           false,
		RD:           true,
		RA:           false,
		Z:            0,
		ResponseCode: 0,
		QDCount:      1,
		ANCount:      0,
		NSCount:      0,
		ARCount:      0,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(qname),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err = gopacket.SerializeLayers(
		buffer, options,
		ethernetLayer,
		ipv4Layer,
		udpLayer,
		dnsLayer,
	)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	outgoingPacket := buffer.Bytes()

	return outgoingPacket
}

func generatePackets() {
	if logLevel != 1 {
		log.Println("Starting query generating...")
	}

	f, err := os.Open(domainListFile)
	if err != nil {
		log.Fatalf("Failed to open domain list file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	idx := 0

	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}

		// Convert domain to lowercase and ensure it doesn't end with a dot
		domain = strings.TrimRight(strings.ToLower(domain), ".")
		
		// Select DNS server using round-robin
		dnsServer := dnsServers[idx%len(dnsServers)]

		if dryRun {
			fmt.Printf("%s,%s\n", domain, dnsServer)
		} else {
			pkt := buildDNSQuery(domain, dnsServer)
			if pkt != nil {
				packetChan <- pkt
			}
		}

		idx++
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading domain list file: %v", err)
	}

	if !dryRun {
		packetChan <- nil
	}
}

func sendPackets(done context.CancelFunc) {
	if dryRun {
		return
	}

	if logLevel != 1 {
		log.Println("Starting query sending...")
	}

	// 打开pcap handle
	handle, err := pcap.OpenLive(iface, 65536, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open pcap: %v", err)
	}
	defer handle.Close()

	err = handle.SetDirection(pcap.DirectionOut)
	if err != nil {
		log.Fatalf("Failed to SetDirection: %v", err)
	}

	// 批量发送参数 - 根据DNS解析器数量和速率动态调整
	var batchSize int
	dnsServerCount := len(dnsServers)

	if dnsServerCount >= int(rate) {
		// DNS解析器数量充足，每批发送rate个包
		batchSize = int(rate)
	} else {
		// DNS解析器数量不足，每批发送解析器数量个包，多批满足速率
		batchSize = dnsServerCount
	}

	// 计算批次间隔（毫秒）
	batchInterval := time.Duration(float64(batchSize)/float64(rate)*1000) * time.Millisecond

	var batch [][]byte
	lastBatchTime := time.Now()

	// 从channel读取并批量发送包
	for {
		select {
		case pkt := <-packetChan:
			if pkt == nil {
				// 发送剩余的包
				if len(batch) > 0 {
					for _, p := range batch {
						handle.WritePacketData(p)
						atomic.AddUint64(&sentCount, 1)
					}
				}

				// 所有包发送完毕
				if logLevel != 1 {
					log.Println("All queries sent. Waiting before signaling receive thread...")
				}
				time.Sleep(time.Duration(waitingTime) * time.Second)
				done()
				return
			}

			// 添加到批次
			batch = append(batch, pkt)

			// 当批次满了或者时间到了，发送批次
			if len(batch) >= batchSize {
				// 速率控制
				elapsed := time.Since(lastBatchTime)
				if elapsed < batchInterval {
					time.Sleep(batchInterval - elapsed)
				}

				// 批量发送
				for _, p := range batch {
					handle.WritePacketData(p)
					atomic.AddUint64(&sentCount, 1)

					// 每发送rate个包显示一次进度
					if logLevel != 0 && logLevel != 1 {
						if sentCount%uint64(rate) == 0 {
							dur := time.Since(startTime).Seconds()
							left := float64(totalCount-sentCount) / float64(rate)

							log.Printf(
								"Probed %s/%s (%.1f%%, %spps), %s elapsed, est %s left.\n",
								humanize.Comma(int64(sentCount)),
								humanize.Comma(int64(totalCount)),
								float64(sentCount)/float64(totalCount)*100,
								humanize.Comma(int64(rate)),
								formatDuration(dur),
								formatDuration(left),
							)
						}
					}
				}

				// 重置批次
				batch = batch[:0]
				lastBatchTime = time.Now()
			}
		}
	}
}

func recvPackets(ctx context.Context) {
	if dryRun {
		return
	}

	if logLevel != 1 {
		log.Println("Starting response receiving...")
	}

	handle, err := pcap.OpenLive(iface, 65536, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open interface: %v", err)
	}
	defer handle.Close()

	var filter = "udp src port 53 and udp dst port 54321"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Failed to SetBPFFilter: %v", err)
	}
	err = handle.SetDirection(pcap.DirectionIn)
	if err != nil {
		log.Fatalf("Failed to SetDirection: %v", err)
	}

	var eth layers.Ethernet
	var ipv4 layers.IPv4
	var udp layers.UDP
	var dns_ layers.DNS
	var decoded []gopacket.LayerType
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &udp, &dns_)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetRecvChan := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			if logLevel != 1 {
				log.Println("All responses analyzed.")
			}

			handle.Close() // Must first be called

			storeChan <- ""

			return

		case packet := <-packetRecvChan:
			if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
				continue
			}

			if len(dns_.Questions) <= 0 {
				continue
			}

			// Only filter out NXDOMAIN responses, no need to check domain suffix
			if !dns_.QR || dns_.ResponseCode == layers.DNSResponseCodeNXDomain {
				continue
			}

			var ips []string
			for _, rr := range dns_.Answers {
				if rr.IP != nil {
					ips = append(ips, rr.IP.String())
				}
			}

			res := fmt.Sprintf("%s,%s", strings.ToLower(string(dns_.Questions[0].Name)), strings.Join(ips, ","))
			res = strings.TrimRight(res, ",")

			storeChan <- res
		}
	}
}

func storeResults() {
	if dryRun {
		return
	}

	if logLevel != 1 {
		log.Println("Starting result storing...")
	}

	f, _ := os.Create(outputFile)
	defer f.Close()
	w := bufio.NewWriter(f)

	for {
		res := <-storeChan
		if res == "" {
			if logLevel != 1 {
				log.Println("All results stored.")
			}

			break
		}

		w.WriteString(res + "\n")
		w.Flush()

		if logLevel == 1 || logLevel == 3 {
			fmt.Println(res)
		}

		atomic.AddUint64(&foundCount, 1)

		if logLevel != 0 && logLevel != 1 {
			if foundCount%uint64(rate) == 0 {
				log.Printf(
					"Found %s valid domain(s) (%.1f%%).\n", humanize.Comma(int64(foundCount)),
					float64(foundCount)/float64(sentCount)*100,
				)
			}
		}
	}
}

func showState() {
	dur := time.Since(startTime).Seconds()
	left := float64(totalCount-sentCount) / float64(rate)

	log.Printf("Current state:------------------------------\n")
	log.Printf(
		"Probed %s/%s (%.1f%%, %spps), %s elapsed, est %s left.\n", humanize.Comma(int64(sentCount)),
		humanize.Comma(int64(totalCount)), float64(sentCount)/float64(totalCount)*100, humanize.Comma(int64(rate)),
		formatDuration(dur), formatDuration(left),
	)
	log.Printf(
		"Found %s valid domain(s) (%.1f%%).\n", humanize.Comma(int64(foundCount)),
		float64(foundCount)/float64(sentCount)*100,
	)
}

func interactiveStatusReporter() {
	//if logLevel != 0 && logLevel != 1 {
	//	return
	//}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	inputChan := make(chan struct{})

	go func() {
		for {
			_, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
			if err == nil {
				inputChan <- struct{}{}
			}
		}
	}()

	for {
		select {
		case <-sigChan:
			fmt.Println("")
			showState()
			log.Println("Received interrupt signal (Ctrl+C). Exited.")

			os.Exit(0)
		case <-inputChan:
			showState()
		}
	}
}

func formatDuration(s float64) string {
	seconds := int(s)
	days := seconds / 86400
	seconds %= 86400
	hours := seconds / 3600
	seconds %= 3600
	minutes := seconds / 60
	seconds %= 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 || days > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 || hours > 0 || days > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	parts = append(parts, fmt.Sprintf("%ds", seconds))

	return strings.Join(parts, "")
}

func main() {
	initParams()

	startTime = time.Now()

	ctx, done := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(4)

	go func() { defer wg.Done(); recvPackets(ctx) }()
	go func() { defer wg.Done(); storeResults() }()
	go func() { defer wg.Done(); generatePackets() }()
	go func() { defer wg.Done(); sendPackets(done) }()

	go interactiveStatusReporter()

	wg.Wait()

	duration := time.Since(startTime).Seconds()
	if logLevel != 1 {
		log.Printf(
			"Done. Cost time: %s. Found %s valid domain(s).\n", formatDuration(duration),
			humanize.Comma(int64(foundCount)),
		)
	}
}
