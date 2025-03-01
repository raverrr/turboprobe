package main

import (
    "bufio"
    "context"
    "flag"
    "fmt"
    "log"
    "net"
    "os"
    "sync"
    "syscall"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

var (
    concurrency   = flag.Int("c", 100, "concurrency level")
    timeout       = flag.Int("t", 300, "timeout in milliseconds")
    interfaceName = flag.String("i", "eth0", "network interface")
)

func main() {
    flag.Parse()

    iface, err := net.InterfaceByName(*interfaceName)
    if err != nil {
        log.Fatalf("Failed to get interface %s: %v", *interfaceName, err)
    }

    addrs, err := iface.Addrs()
    if err != nil {
        log.Fatalf("Failed to get addresses for interface %s: %v", *interfaceName, err)
    }

    var srcIPv4, srcIPv6 net.IP
    for _, addr := range addrs {
        ipNet, ok := addr.(*net.IPNet)
        if !ok {
            continue
        }
        ip := ipNet.IP
        if ip.To4() != nil && srcIPv4 == nil {
            srcIPv4 = ip.To4()
        } else if ip.To4() == nil && srcIPv6 == nil {
            srcIPv6 = ip.To16()
        }
    }
    if srcIPv4 == nil {
        log.Fatalf("Interface %s has no IPv4 address", *interfaceName)
    }
    if srcIPv6 == nil {
        log.Fatalf("Interface %s has no IPv6 address", *interfaceName)
    }

    subdomains := make(chan string, *concurrency)
    results := make(chan string, *concurrency)

    var wg sync.WaitGroup
    for i := 0; i < *concurrency; i++ {
        wg.Add(1)
        go worker(&wg, *interfaceName, srcIPv4, srcIPv6, subdomains, results)
    }

    go func() {
        scanner := bufio.NewScanner(os.Stdin)
        for scanner.Scan() {
            subdomains <- scanner.Text()
        }
        if err := scanner.Err(); err != nil {
            log.Printf("Error reading stdin: %v", err)
        }
        close(subdomains)
    }()

    go func() {
        for result := range results {
            fmt.Println(result)
        }
    }()

    wg.Wait()
    close(results)
}

func worker(wg *sync.WaitGroup, iface string, srcIPv4, srcIPv6 net.IP, subdomains <-chan string, results chan<- string) {
    defer wg.Done()

    handle, err := pcap.OpenLive(iface, 64, true, 100*time.Millisecond)
    if err != nil {
        log.Printf("Worker failed to open pcap handle: %v", err)
        return
    }
    defer handle.Close()

    if err := handle.SetDirection(pcap.DirectionIn); err != nil {
        log.Printf("Worker failed to set pcap direction: %v", err)
        return
    }

    fd4, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
    if err != nil {
        log.Printf("Worker failed to create IPv4 raw socket: %v", err)
        return
    }
    defer syscall.Close(fd4)

    fd6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
    if err != nil {
        log.Printf("Worker failed to create IPv6 raw socket: %v", err)
        return
    }
    defer syscall.Close(fd6)

    for subdomain := range subdomains {
        probe(handle, fd4, fd6, srcIPv4, srcIPv6, subdomain, results)
    }
}

func probe(handle *pcap.Handle, fd4, fd6 int, srcIPv4, srcIPv6 net.IP, subdomain string, results chan<- string) {
    ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Millisecond)
    defer cancel()
    ips, err := net.DefaultResolver.LookupIPAddr(ctx, subdomain)
    if err != nil || len(ips) == 0 {
        return // Skip silently on DNS failure
    }
    ipAddr := ips[0].IP

    isIPv4 := ipAddr.To4() != nil

    var srcIP net.IP
    if isIPv4 {
        srcIP = srcIPv4
    } else {
        srcIP = srcIPv6
    }
    if srcIP == nil {
        return // Skip if no matching source IP
    }

    srcPort := layers.TCPPort(time.Now().UnixNano()%10000 + 50000)

    var ipLayer gopacket.SerializableLayer
    if isIPv4 {
        ipLayer = &layers.IPv4{
            SrcIP:    srcIP,
            DstIP:    ipAddr,
            Protocol: layers.IPProtocolTCP,
            Version:  4,
            TTL:      64,
        }
    } else {
        ipLayer = &layers.IPv6{
            SrcIP:      srcIP,
            DstIP:      ipAddr,
            NextHeader: layers.IPProtocolTCP,
            Version:    6,
            HopLimit:   64,
        }
    }

    tcpLayer := &layers.TCP{
        SrcPort: srcPort,
        DstPort: 443,
        SYN:     true,
        Seq:     uint32(time.Now().UnixNano()),
        Window:  64240,
    }
    if netLayer, ok := ipLayer.(gopacket.NetworkLayer); ok {
        if err := tcpLayer.SetNetworkLayerForChecksum(netLayer); err != nil {
            return
        }
    } else {
        log.Printf("ipLayer does not implement gopacket.NetworkLayer")
        return
    }

    buffer := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{
        ComputeChecksums: true,
        FixLengths:       true,
    }
    if err := gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer); err != nil {
        return
    }
    packetData := buffer.Bytes()

    if isIPv4 {
        var dst syscall.SockaddrInet4
        copy(dst.Addr[:], ipAddr.To4())
        if err := syscall.Sendto(fd4, packetData, 0, &dst); err != nil {
            return
        }
    } else {
        var dst syscall.SockaddrInet6
        copy(dst.Addr[:], ipAddr.To16())
        if err := syscall.Sendto(fd6, packetData, 0, &dst); err != nil {
            return
        }
    }

    filter := ""
    if isIPv4 {
        filter = fmt.Sprintf("tcp and src host %s and dst host %s and src port 443 and dst port %d", ipAddr.String(), srcIP.String(), srcPort)
    } else {
        filter = fmt.Sprintf("ip6 and tcp and src host %s and dst host %s and src port 443 and dst port %d", ipAddr.String(), srcIP.String(), srcPort)
    }
    if err := handle.SetBPFFilter(filter); err != nil {
        return
    }

    if listenForSYNACK(handle, subdomain) {
        results <- "https://" + subdomain
    }
}

func listenForSYNACK(handle *pcap.Handle, subdomain string) bool {
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    start := time.Now()
    for {
        if time.Since(start) > time.Duration(*timeout)*time.Millisecond {
            //log.Printf("Timeout reached for %s", subdomain)
            return false
        }
        packet, err := packetSource.NextPacket()
        if err == pcap.NextErrorTimeoutExpired {
            continue
        }
        if err != nil {
            log.Printf("Error reading packet for %s: %v", subdomain, err)
            return false
        }
        if packet != nil {
            if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
                tcp, _ := tcpLayer.(*layers.TCP)
                if tcp.SYN && tcp.ACK {
                    //log.Printf("SYN-ACK received for %s", subdomain)
                    return true
                }
            }
        }
    }
}
