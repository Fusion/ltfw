package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/cakturk/go-netstat/netstat"
	"github.com/docopt/docopt-go"
	"github.com/fusion/ltfw/pkg/config"
	"github.com/fusion/ltfw/pkg/iptables"
	"github.com/hydronica/toml"
	"github.com/kardianos/service"
)

type Transport int
type L3 int

const (
	TCP Transport = iota
	UDP           = iota
)

const (
	v4 L3 = iota
	v6    = iota
)

var cmdline struct {
	Run     bool   `docopt:"run"`
	Config  string `docopt:"-c,--config"`
	Quiet   bool   `docopt:"-q,--quiet"`
	Verbose bool   `docopt:"-v,--verbose"`
}

var usage = `ltfw - Light Touch Firewall.

Usage:
  ltfw [--quiet|--verbose] [--config=<path>] run
  ltfw -h --help
  ltfw --version

Options:
  -h, --help                Show this screen.
  -v, --version             Show version.
  -c, --config=<file>       Config file.
  -q, --quiet               Suppress output.
  --verbose                 Comprehensive output.
`

type addrData struct {
	transport Transport
	l3        L3
	tab       netstat.SockTabEntry
}

type program struct {
	cfg *config.Config
}

func main() {
	if parseMyArgs() != nil {
		fmt.Println("Unable to parse command-line arguments")
		os.Exit(1)
	}

	cfg := readConfig()
	if cfg == nil {
		fmt.Println("Could not find config file.")
		os.Exit(1)
	}
	if cfg.DropOrReject != "drop" && cfg.DropOrReject != "reject" {
		fmt.Println("Configuration/DropOrReject: should be one of 'drop' or 'reject'")
		os.Exit(1)
	}

	serviceConfig := &service.Config{
		Name:        "LT",
		DisplayName: "Light Touch Firewall",
		Description: "Not even a real firewall",
	}
	prg := &program{
		cfg: cfg,
	}
	if !prg.checkIPTablesReady() {
		fmt.Println("IPTables not ready, exiting")
		return
	}
	s, err := service.New(prg, serviceConfig)
	if err != nil {
		fmt.Println("Cannot create the service: " + err.Error())
		return
	}
	err = s.Run()
	if err != nil {
		fmt.Println("Cannot start the service: " + err.Error())
		return
	}
}

func parseMyArgs() error {
	opts, err := docopt.ParseArgs(usage, os.Args[1:], "0.1.0")
	if err != nil {
		return err
	}
	opts.Bind(&cmdline)
	if cmdline.Config == "" {
		cmdline.Config = "config.toml"
	}

	return nil
}

func readConfig() *config.Config {
	cfg := config.Config{}
	if _, err := toml.DecodeFile(cmdline.Config, &cfg); err != nil {
		return nil
	}
	return &cfg
}

func (p program) Start(s service.Service) error {
	if !cmdline.Quiet {
		fmt.Println(s.String() + " started, checking every " + strconv.Itoa(int(p.cfg.Every)) + " seconds...")
	}
	go p.run()
	return nil
}

func (p program) Stop(s service.Service) error {
	if !cmdline.Quiet {
		fmt.Println(s.String() + " stopped")
	}
	return nil
}

func (p program) run() {
	for {
		if !cmdline.Quiet {
			fmt.Println("checking")
		}

		portsInfo := p.getPortList()
		p.updateRules(portsInfo)

		time.Sleep(p.cfg.Every * time.Second)
	}
}

func (p program) getPortList() []addrData {
	tabs, err := netstat.TCPSocks(p.tcpListenerFilter)
	if err != nil {
		fmt.Println("Unable to retrieve TCP4 listeners", err)
	}
	wtabs := WrapTabEntry(tabs, func(s netstat.SockTabEntry) addrData {
		return addrData{
			transport: TCP,
			l3:        v4,
			tab:       s,
		}
	})
	udptabs, err := netstat.UDPSocks(p.udpListenerFilter)
	if err != nil {
		fmt.Println("Unable to retrieve UDP4 listeners", err)
	}
	wtabs = append(wtabs, WrapTabEntry(udptabs, func(s netstat.SockTabEntry) addrData {
		return addrData{
			transport: UDP,
			l3:        v4,
			tab:       s,
		}
	})...)
	tcp6tabs, err := netstat.TCP6Socks(p.tcpListenerFilter)
	if err != nil {
		fmt.Println("Unable to retrieve TCP6 listeners", err)
	}
	wtabs = append(wtabs, WrapTabEntry(tcp6tabs, func(s netstat.SockTabEntry) addrData {
		return addrData{
			transport: TCP,
			l3:        v6,
			tab:       s,
		}
	})...)
	udp6tabs, err := netstat.UDP6Socks(p.udpListenerFilter)
	if err != nil {
		fmt.Println("Unable to retrieve UDP6 listeners", err)
	}
	wtabs = append(wtabs, WrapTabEntry(udp6tabs, func(s netstat.SockTabEntry) addrData {
		return addrData{
			transport: UDP,
			l3:        v6,
			tab:       s,
		}
	})...)
	return wtabs
}

// Filter IP addresses that we should close
func (p program) tcpListenerFilter(s *netstat.SockTabEntry) bool {
	if p.isIPSafe(s) {
		return false
	}
	return s.State == netstat.Listen
}

// Filter IP addresses that we should close
func (p program) udpListenerFilter(s *netstat.SockTabEntry) bool {
	if p.isIPSafe(s) {
		return false
	}
	return true
}

// If this IP address is in the list of ips we should close, it is not safe
func (p program) isIPSafe(s *netstat.SockTabEntry) bool {
	ip := s.LocalAddr.IP.String()
	for _, cip := range p.cfg.Closeips {
		if cip == ip {
			return false
		}
	}
	return true
}

func (p program) checkIPTablesReady() bool {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return false
	}
	listChain, err := ipt.ListChains("filter")
	if err != nil {
		return false
	}
	for _, c := range listChain {
		if c == "INPUT" {
			return true
		}
	}
	return false
}

func (p program) updateRules(wtabs []addrData) {
	ipt4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return
	}
	p.updateRulesForProto(ipt4, FilterWrappedTabEntry(wtabs, func(s addrData) bool {
		return s.l3 == v4
	}))

	ipt6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return
	}
	p.updateRulesForProto(ipt6, FilterWrappedTabEntry(wtabs, func(s addrData) bool {
		return s.l3 == v6
	}))
}

func (p program) updateRulesForProto(ipt *iptables.IPTables, wtabs []addrData) {
	for _, e := range wtabs {
		if p.isPortProtected(&e.tab) {
			continue
		}
		if cmdline.Verbose {
			fmt.Println("- blocking:", e.transport, e.tab.LocalAddr.IP.String(), e.tab.LocalAddr.Port)
		}
		ipt.AppendUnique(
			"filter", "INPUT",
			"-p", getProtoStr()[e.transport],
			"--destination-port", strconv.Itoa(int(e.tab.LocalAddr.Port)),
			"-j", dropOrRejectStr()[p.cfg.DropOrReject])
	}
}

func (p program) isPortProtected(s *netstat.SockTabEntry) bool {
	port := strconv.Itoa(int(s.LocalAddr.Port))
	for _, cport := range p.cfg.Protectedports {
		if cport == port {
			return true
		}
	}
	return false
}

func WrapTabEntry(vs []netstat.SockTabEntry, f func(netstat.SockTabEntry) addrData) []addrData {
	vsm := make([]addrData, len(vs))
	for i, v := range vs {
		vsm[i] = f(v)
	}
	return vsm
}

func FilterWrappedTabEntry(vs []addrData, f func(addrData) bool) []addrData {
	var vsf []addrData
	for _, v := range vs {
		if f(v) {
			vsf = append(vsf, v)
		}
	}
	return vsf
}

func getProtoStr() map[Transport]string {
	return map[Transport]string{TCP: "tcp", UDP: "udp"}
}

func dropOrRejectStr() map[string]string {
	return map[string]string{"drop": "DROP", "reject": "REJECT"}
}
