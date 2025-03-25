package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ExporterAddress       string   `yaml:"exporterAddress"`
	ExporterPort          int      `yaml:"exporterPort"`
	IgnoreInternalTraffic bool     `yaml:"ignoreInternalTraffic"`
	CidrInternalList      []string `yaml:"cidrInternalList"`
	BpfFilter             string   `yaml:"bpfFilter"`
	EnableBytesPerFlow    bool     `yaml:"enableBytesPerFlow"`
	InterfaceName         string   `yaml:"interfaceName"`
	CidrIgnorelist        []string `yaml:"cidrIgnorelist"`
}

// Global variables loaded from config
var config Config

// Convert CIDRs into parsed `net.IPNet` lists
var parsedCIDRIgnoreList []*net.IPNet
var parsedCIDRInternalList []*net.IPNet

// Parse CIDR lists
func initCIDRs() {
	for _, cidr := range config.CidrIgnorelist {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("Invalid ignorelist CIDR: %s", cidr)
		}
		parsedCIDRIgnoreList = append(parsedCIDRIgnoreList, ipNet)
	}

	for _, cidr := range config.CidrInternalList {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("Invalid internal CIDR: %s", cidr)
		}
		parsedCIDRInternalList = append(parsedCIDRInternalList, ipNet)
	}
}

func loadConfig(filename string) {
	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	// Parse YAML
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Error parsing YAML: %v", err)
	}
}

// Check if an IP is in a given CIDR list
func isInCIDRList(ip string, cidrList []*net.IPNet) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false // Invalid IP
	}
	for _, ipNet := range cidrList {
		if ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// Prometheus metrics
var (
	bytesPerFlow = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bytes_per_flow",
			Help: "Total bytes transferred per peer-to-peer connection",
		},
		[]string{"peerA", "peerB"},
	)
)

var (
	packetsPerFlow = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "packets_per_flow",
			Help: "Total packets transferred per peer-to-peer connection",
		},
		[]string{"peerA", "peerB"},
	)
)

func main() {
	// Parse command-line arguments
	configFile := flag.String("c", "config.yaml", "Path to the config file (default: config.yaml)")
	flag.Parse()

	// Load configuration
	loadConfig(*configFile)
	initCIDRs()

	var snaplen int32 = 64
	// Register Prometheus metrics
	if config.EnableBytesPerFlow {
		snaplen = 65535
		prometheus.MustRegister(bytesPerFlow)
	}
	prometheus.MustRegister(packetsPerFlow)

	// Start Prometheus HTTP server
	go func() {
		listenAddr := fmt.Sprintf("%s:%d", config.ExporterAddress, config.ExporterPort)
		http.Handle("/metrics", promhttp.Handler())
		log.Printf("Prometheus metrics available at http://%s/metrics", listenAddr)
		log.Fatal(http.ListenAndServe(listenAddr, nil))
	}()

	// Open the network interface for packet capture
	handle, err := pcap.OpenLive(config.InterfaceName, snaplen, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", config.InterfaceName, err)
	}
	defer handle.Close()

	// Apply BPF filter
	if err := handle.SetBPFFilter(config.BpfFilter); err != nil {
		log.Fatalf("Error applying BPF filter: %v", err)
	}

	log.Printf("Capturing packets from %s", config.BpfFilter)

	// Open a log file for writing
	logFile, err := os.OpenFile("packets.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Error opening log file: %v", err)
	}
	defer logFile.Close()

	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}
	srcIP, dstIP := networkLayer.NetworkFlow().Endpoints()
	// Check if destination IP is in the CIDR whitelist (ignore if true)
	if isInCIDRList(dstIP.String(), parsedCIDRIgnoreList) {
		return
	}

	srcIsHome := isInCIDRList(srcIP.String(), parsedCIDRInternalList)
	dstIsHome := isInCIDRList(dstIP.String(), parsedCIDRInternalList)

	// Normalize the flow order
	var peerA, peerB string
	if srcIsHome && !dstIsHome {
		// Source is home, destination is external
		peerA, peerB = srcIP.String(), dstIP.String()
	} else if !srcIsHome && dstIsHome {
		// Destination is home, source is external
		peerA, peerB = dstIP.String(), srcIP.String()
	} else if srcIsHome && dstIsHome && config.IgnoreInternalTraffic {
		// Destination is home, source is home and ignoreHome is true
		return
	} else {
		// Neither or both are home
		peerA, peerB = srcIP.String(), dstIP.String()
		if peerA > peerB {
			peerA, peerB = peerB, peerA
		}
	}
	// Update Prometheus metrics
	if config.EnableBytesPerFlow {
		packetLength := len(packet.Data())
		bytesPerFlow.WithLabelValues(peerA, peerB).Add(float64(packetLength))
	}
	packetsPerFlow.WithLabelValues(peerA, peerB).Add(float64(1))
}
