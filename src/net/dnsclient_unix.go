// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux netbsd openbsd solaris

// DNS client: see RFC 1035.
// Has to be linked into package net for Dial.

// TODO(rsc):
//	Could potentially handle many outstanding lookups faster.
//	Could have a small cache.
//	Random UDP source port (net.Dial should do that for us).
//	Random request IDs.

package net

import (
	"errors"
	"io"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"time"
	"fmt"
)

// A dnsConn represents a DNS transport endpoint.
type dnsConn interface {
	Conn

	// readDNSResponse reads a DNS response message from the DNS
	// transport endpoint and returns the received DNS response
	// message.
	readDNSResponse() (*dnsMsg, error)

	// writeDNSQuery writes a DNS query message to the DNS
	// connection endpoint.
	writeDNSQuery(*dnsMsg) error
}

func (c *UDPConn) readDNSResponse() (*dnsMsg, error) {
	b := make([]byte, 512) // see RFC 1035
	n, err := c.Read(b)
	if err != nil {
		return nil, err
	}
	msg := &dnsMsg{}
	if !msg.Unpack(b[:n]) {
		return nil, errors.New("cannot unmarshal DNS message")
	}
	return msg, nil
}

func (c *UDPConn) writeDNSQuery(msg *dnsMsg) error {
	b, ok := msg.Pack()
	if !ok {
		return errors.New("cannot marshal DNS message")
	}
	if _, err := c.Write(b); err != nil {
		return err
	}
	return nil
}

func (c *TCPConn) readDNSResponse() (*dnsMsg, error) {
	PrintWithTime("readDNSResponse()")
	defer PrintWithTime("readDNSResponse() exit")
	b := make([]byte, 1280) // 1280 is a reasonable initial size for IP over Ethernet, see RFC 4035
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return nil, err
	}
	l := int(b[0])<<8 | int(b[1])
	if l > len(b) {
		b = make([]byte, l)
	}
	n, err := io.ReadFull(c, b[:l])
	if err != nil {
		return nil, err
	}
	msg := &dnsMsg{}
	if !msg.Unpack(b[:n]) {
		return nil, errors.New("cannot unmarshal DNS message")
	}
	return msg, nil
}

func (c *TCPConn) writeDNSQuery(msg *dnsMsg) error {
	PrintWithTime(fmt.Sprintf("writeDNSQuery(%v)", msg))
	defer PrintWithTime(fmt.Sprintf("writeDNSQuery(%v) exit", msg))
	b, ok := msg.Pack()
	if !ok {
		return errors.New("cannot marshal DNS message")
	}
	l := uint16(len(b))
	b = append([]byte{byte(l >> 8), byte(l)}, b...)
	if _, err := c.Write(b); err != nil {
		return err
	}
	return nil
}

func (d *Dialer) dialDNS(network, server string) (dnsConn, error) {
	PrintWithTime(fmt.Sprintf("dialDNS(%s, %s)", network, server))
	defer PrintWithTime(fmt.Sprintf("dialDNS(%s, %s) exit ", network, server))
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
	default:
		return nil, UnknownNetworkError(network)
	}
	// Calling Dial here is scary -- we have to be sure not to
	// dial a name that will require a DNS lookup, or Dial will
	// call back here to translate it. The DNS config parser has
	// already checked that all the cfg.servers[i] are IP
	// addresses, which Dial will use without a DNS lookup.
	c, err := d.Dial(network, server)
	if err != nil {
		PrintWithTime(fmt.Sprintf("error d.Dail(%s, %s): %s", network, server, err))
		return nil, err
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		return c.(*TCPConn), nil
	case "udp", "udp4", "udp6":
		return c.(*UDPConn), nil
	}
	panic("unreachable")
}

// exchange sends a query on the connection and hopes for a response.
func exchange(server, name string, qtype uint16, timeout time.Duration) (*dnsMsg, error) {
	PrintWithTime(fmt.Sprintf("exchange(%s, %s, %d, %s)", server, name, qtype, timeout))
	defer PrintWithTime(fmt.Sprintf("exchange(%s, %s, %d, %s) exit", server, name, qtype, timeout))
	d := Dialer{Timeout: timeout}
	out := dnsMsg{
		dnsMsgHdr: dnsMsgHdr{
			recursion_desired: true,
		},
		question: []dnsQuestion{
			{name, qtype, dnsClassINET},
		},
	}
	for _, network := range []string{"udp", "tcp"} {
		c, err := d.dialDNS(network, server)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		if timeout > 0 {
			c.SetDeadline(time.Now().Add(timeout))
		}
		out.id = uint16(rand.Int()) ^ uint16(time.Now().UnixNano())
		if err := c.writeDNSQuery(&out); err != nil {
			PrintWithTime(fmt.Sprintf("writeDNSQuery(%s) error: %s", &out, err))
			return nil, err
		}
		in, err := c.readDNSResponse()
		if err != nil {
			PrintWithTime(fmt.Sprintf("readDNSResponse() error: %s", err))
			return nil, err
		}
		if in.id != out.id {
			PrintWithTime(fmt.Sprintf("dns message ID mismatch %s %s", in.id, out.id))
			return nil, errors.New("DNS message ID mismatch")
		}
		if in.truncated { // see RFC 5966
			continue
		}
		PrintWithTime(fmt.Sprintf("exchange(%s, %s, %d, %s) returning: dns message %v", server, name, qtype, timeout, in))
		return in, nil
	}

	PrintWithTime(fmt.Sprintf("exchange(%s, %s, %d, %s) returning: no answer from DNS server", server, name, qtype, timeout))
	return nil, errors.New("no answer from DNS server")
}

// Do a lookup for a single name, which must be rooted
// (otherwise answer will not find the answers).
func tryOneName(cfg *dnsConfig, name string, qtype uint16) (string, []dnsRR, error) {
	PrintWithTime(fmt.Sprintf("tryOneName(%s, %d)", name, qtype))
	if len(cfg.servers) == 0 {
		PrintWithTime(fmt.Sprintf("tryOneName(%s, %d) exit: %s", name, qtype, "no DNS servers"))
		return "", nil, &DNSError{Err: "no DNS servers", Name: name}
	}
	if len(name) >= 256 {
		PrintWithTime(fmt.Sprintf("tryOneName(%s, %d) exit: %s", name, qtype, "DNS name too long"))
		return "", nil, &DNSError{Err: "DNS name too long", Name: name}
	}
	timeout := time.Duration(cfg.timeout) * time.Second
	var lastErr error
	for i := 0; i < cfg.attempts; i++ {
		PrintWithTime(fmt.Sprintf("tryOneName attempt: %d", i))
		for _, server := range cfg.servers {
			server = JoinHostPort(server, "53")
			msg, err := exchange(server, name, qtype, timeout)
			if err != nil {
				PrintWithTime(fmt.Sprintf("error from exchange: %s", err))
				lastErr = &DNSError{
					Err:    err.Error(),
					Name:   name,
					Server: server,
				}
				if nerr, ok := err.(Error); ok && nerr.Timeout() {
					lastErr.(*DNSError).IsTimeout = true
				}
				continue
			}
			cname, rrs, err := answer(name, server, msg, qtype)
			if err == nil || msg.rcode == dnsRcodeSuccess || msg.rcode == dnsRcodeNameError && msg.recursion_available {
				PrintWithTime(fmt.Sprintf("tryOneName(%s, %d) finished", name, qtype))
				return cname, rrs, err
			}
			lastErr = err
		}
	}

	PrintWithTime(fmt.Sprintf("tryOneName(%s, %d) finished all attempts to resolve: lastErr: %s", name, qtype, lastErr))
	return "", nil, lastErr
}

// addrRecordList converts and returns a list of IP addresses from DNS
// address records (both A and AAAA). Other record types are ignored.
func addrRecordList(rrs []dnsRR) []IPAddr {
	PrintWithTime("addrRecordList()")
	defer PrintWithTime("addrRecordList() exit")
	addrs := make([]IPAddr, 0, 4)
	for _, rr := range rrs {
		switch rr := rr.(type) {
		case *dnsRR_A:
			addrs = append(addrs, IPAddr{IP: IPv4(byte(rr.A>>24), byte(rr.A>>16), byte(rr.A>>8), byte(rr.A))})
		case *dnsRR_AAAA:
			ip := make(IP, IPv6len)
			copy(ip, rr.AAAA[:])
			addrs = append(addrs, IPAddr{IP: ip})
		}
	}
	return addrs
}

// A resolverConfig represents a DNS stub resolver configuration.
type resolverConfig struct {
	initOnce sync.Once // guards init of resolverConfig

	// ch is used as a semaphore that only allows one lookup at a
	// time to recheck resolv.conf.
	ch          chan struct{} // guards lastChecked and modTime
	lastChecked time.Time     // last time resolv.conf was checked
	modTime     time.Time     // time of resolv.conf modification

	mu        sync.RWMutex // protects dnsConfig
	dnsConfig *dnsConfig   // parsed resolv.conf structure used in lookups
}

var resolvConf resolverConfig

// init initializes conf and is only called via conf.initOnce.
func (conf *resolverConfig) init() {
	// Set dnsConfig, modTime, and lastChecked so we don't parse
	// resolv.conf twice the first time.
	conf.dnsConfig = systemConf().resolv
	if conf.dnsConfig == nil {
		conf.dnsConfig = dnsReadConfig("/etc/resolv.conf")
	}

	if fi, err := os.Stat("/etc/resolv.conf"); err == nil {
		conf.modTime = fi.ModTime()
	}
	conf.lastChecked = time.Now()

	// Prepare ch so that only one update of resolverConfig may
	// run at once.
	conf.ch = make(chan struct{}, 1)
}

// tryUpdate tries to update conf with the named resolv.conf file.
// The name variable only exists for testing. It is otherwise always
// "/etc/resolv.conf".
func (conf *resolverConfig) tryUpdate(name string) {
	PrintWithTime(fmt.Sprintf("resolverConfig tryUpdate(%s)", name))
	defer PrintWithTime(fmt.Sprintf("resolverConfig tryUpdate(%s) exit", name))
	conf.initOnce.Do(conf.init)

	// Ensure only one update at a time checks resolv.conf.
	if !conf.tryAcquireSema() {
		PrintWithTime(fmt.Sprintf("resolverConfig tryUpdate could not acquire semaphore (%s)", name))
		return
	}
	defer conf.releaseSema()

	now := time.Now()
	if conf.lastChecked.After(now.Add(-5 * time.Second)) {
		PrintWithTime(fmt.Sprintf("resolverConfig tryUpdate last checked was very recent (%s)", conf.lastChecked.String()))
		return
	}
	conf.lastChecked = now

	if fi, err := os.Stat(name); err == nil {
		if fi.ModTime().Equal(conf.modTime) {
			PrintWithTime(fmt.Sprintf("resolverConfig tryUpdate modified time is same. (%s) = (%s)", fi.ModTime().String(), conf.modTime.String()))
			return
		}
		conf.modTime = fi.ModTime()
	} else {
		// If modTime wasn't set prior, assume nothing has changed.
		if conf.modTime.IsZero() {
			PrintWithTime(fmt.Sprintf("resolverConfig tryUpdate conf.ModTime was not set. (%s)", conf.modTime.String()))
			return
		}
		conf.modTime = time.Time{}
	}

	dnsConf := dnsReadConfig(name)
	conf.mu.Lock()
	conf.dnsConfig = dnsConf
	conf.mu.Unlock()
}

func (conf *resolverConfig) tryAcquireSema() bool {
	select {
	case conf.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (conf *resolverConfig) releaseSema() {
	<-conf.ch
}

func lookup(name string, qtype uint16) (cname string, rrs []dnsRR, err error) {
	if !isDomainName(name) {
		return "", nil, &DNSError{Err: "invalid domain name", Name: name}
	}
	resolvConf.tryUpdate("/etc/resolv.conf")
	resolvConf.mu.RLock()
	conf := resolvConf.dnsConfig
	resolvConf.mu.RUnlock()
	for _, fqdn := range conf.nameList(name) {
		cname, rrs, err = tryOneName(conf, fqdn, qtype)
		if err == nil {
			break
		}
	}
	if err, ok := err.(*DNSError); ok {
		// Show original name passed to lookup, not suffixed one.
		// In general we might have tried many suffixes; showing
		// just one is misleading. See also golang.org/issue/6324.
		err.Name = name
	}
	return
}

// nameList returns a list of names for sequential DNS queries.
func (conf *dnsConfig) nameList(name string) []string {
	PrintWithTime(fmt.Sprintf("nameList %s", name))
	defer PrintWithTime(fmt.Sprintf("nameList exit %s", name))
	// If name is rooted (trailing dot), try only that name.
	rooted := len(name) > 0 && name[len(name)-1] == '.'
	if rooted {
		return []string{name}
	}
	// Build list of search choices.
	names := make([]string, 0, 1+len(conf.search))
	// If name has enough dots, try unsuffixed first.
	if count(name, '.') >= conf.ndots {
		names = append(names, name+".")
	}
	// Try suffixes.
	for _, suffix := range conf.search {
		suffixed := name + "." + suffix
		if suffixed[len(suffixed)-1] != '.' {
			suffixed += "."
		}
		names = append(names, suffixed)
	}
	// Try unsuffixed, if not tried first above.
	if count(name, '.') < conf.ndots {
		names = append(names, name+".")
	}
	return names
}

// hostLookupOrder specifies the order of LookupHost lookup strategies.
// It is basically a simplified representation of nsswitch.conf.
// "files" means /etc/hosts.
type hostLookupOrder int

const (
	// hostLookupCgo means defer to cgo.
	hostLookupCgo      hostLookupOrder = iota
	hostLookupFilesDNS                 // files first
	hostLookupDNSFiles                 // dns first
	hostLookupFiles                    // only files
	hostLookupDNS                      // only DNS
)

var lookupOrderName = map[hostLookupOrder]string{
	hostLookupCgo:      "cgo",
	hostLookupFilesDNS: "files,dns",
	hostLookupDNSFiles: "dns,files",
	hostLookupFiles:    "files",
	hostLookupDNS:      "dns",
}

func (o hostLookupOrder) String() string {
	if s, ok := lookupOrderName[o]; ok {
		return s
	}
	return "hostLookupOrder=" + strconv.Itoa(int(o)) + "??"
}

// goLookupHost is the native Go implementation of LookupHost.
// Used only if cgoLookupHost refuses to handle the request
// (that is, only if cgoLookupHost is the stub in cgo_stub.go).
// Normally we let cgo use the C library resolver instead of
// depending on our lookup code, so that Go and C get the same
// answers.
func goLookupHost(name string) (addrs []string, err error) {
	return goLookupHostOrder(name, hostLookupFilesDNS)
}

func goLookupHostOrder(name string, order hostLookupOrder) (addrs []string, err error) {
	PrintWithTime(fmt.Sprintf("goLookupHostOrder(%s, %s)", name, order))
	defer PrintWithTime(fmt.Sprintf("goLookupHostOrder(%s, %s) exit: %v, %s", name, order, addrs, err))
	if order == hostLookupFilesDNS || order == hostLookupFiles {
		// Use entries from /etc/hosts if they match.
		addrs = lookupStaticHost(name)
		if len(addrs) > 0 || order == hostLookupFiles {
			return
		}
	}
	ips, err := goLookupIPOrder(name, order)
	if err != nil {
		return
	}
	addrs = make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
	}
	return
}

// lookup entries from /etc/hosts
func goLookupIPFiles(name string) (addrs []IPAddr) {
	PrintWithTime(fmt.Sprintf("goLookupIPFiles(%s)", name))
	defer PrintWithTime(fmt.Sprintf("goLookupIPFiles(%s) exit: %s", name, addrs))
	for _, haddr := range lookupStaticHost(name) {
		haddr, zone := splitHostZone(haddr)
		if ip := ParseIP(haddr); ip != nil {
			addr := IPAddr{IP: ip, Zone: zone}
			addrs = append(addrs, addr)
		}
	}

	sortByRFC6724(addrs)
	return
}

// goLookupIP is the native Go implementation of LookupIP.
// The libc versions are in cgo_*.go.
func goLookupIP(name string) (addrs []IPAddr, err error) {
	return goLookupIPOrder(name, hostLookupFilesDNS)
}

func goLookupIPOrder(name string, order hostLookupOrder) (addrs []IPAddr, err error) {
	PrintWithTime(fmt.Sprintf("goLookupIPOrder(%s): %s", name, order))
	defer PrintWithTime(fmt.Sprintf("goLookupIPOrder(%s) exit: %v, %s", name, addrs, err))
	if order == hostLookupFilesDNS || order == hostLookupFiles {
		addrs = goLookupIPFiles(name)
		if len(addrs) > 0 || order == hostLookupFiles {
			return addrs, nil
		}
	}
	if !isDomainName(name) {
		PrintWithTime(fmt.Sprintf("goLookupIPOrder(%s) returning: invalid domain name", name))
		return nil, &DNSError{Err: "invalid domain name", Name: name}
	}
	resolvConf.tryUpdate("/etc/resolv.conf")
	resolvConf.mu.RLock()
	conf := resolvConf.dnsConfig
	resolvConf.mu.RUnlock()
	type racer struct {
		rrs []dnsRR
		error
	}
	lane := make(chan racer, 1)
	qtypes := [...]uint16{dnsTypeA, dnsTypeAAAA}
	var lastErr error
	for _, fqdn := range conf.nameList(name) {
		for _, qtype := range qtypes {
			go func(qtype uint16) {
				_, rrs, err := tryOneName(conf, fqdn, qtype)
				lane <- racer{rrs, err}
			}(qtype)
		}
		for range qtypes {
			PrintWithTime(fmt.Sprintf("goLookupIPOrder(%s): Waiting for tryOneName to return", name))
			racer := <-lane
			if racer.error != nil {
				PrintWithTime(fmt.Sprintf("goLookupIPOrder(%s): Error from tryOneName: %s", name, racer.error))
				lastErr = racer.error
				continue
			}

			PrintWithTime(fmt.Sprintf("goLookupIPOrder(%s): success from tryOneName: %v", name, racer.rrs))
			addrs = append(addrs, addrRecordList(racer.rrs)...)
		}
		if len(addrs) > 0 {
			break
		}
	}
	if lastErr, ok := lastErr.(*DNSError); ok {
		// Show original name passed to lookup, not suffixed one.
		// In general we might have tried many suffixes; showing
		// just one is misleading. See also golang.org/issue/6324.
		lastErr.Name = name
	}
	sortByRFC6724(addrs)
	if len(addrs) == 0 {
		PrintWithTime(fmt.Sprintf("goLookupIPOrder(%s): len(addrs) is 0", name))
		if lastErr != nil {
			PrintWithTime(fmt.Sprintf("goLookupIPOrder(%s): returning lastErr: %s", name, lastErr))
			return nil, lastErr
		}
		if order == hostLookupDNSFiles {
			PrintWithTime(fmt.Sprintf("goLookupIPOrder(%s): order == hostLookupDNSFiles", name))
			addrs = goLookupIPFiles(name)
		}
	}
	return addrs, nil
}

// goLookupCNAME is the native Go implementation of LookupCNAME.
// Used only if cgoLookupCNAME refuses to handle the request
// (that is, only if cgoLookupCNAME is the stub in cgo_stub.go).
// Normally we let cgo use the C library resolver instead of
// depending on our lookup code, so that Go and C get the same
// answers.
func goLookupCNAME(name string) (cname string, err error) {
	_, rrs, err := lookup(name, dnsTypeCNAME)
	if err != nil {
		return
	}
	cname = rrs[0].(*dnsRR_CNAME).Cname
	return
}

// goLookupPTR is the native Go implementation of LookupAddr.
// Used only if cgoLookupPTR refuses to handle the request (that is,
// only if cgoLookupPTR is the stub in cgo_stub.go).
// Normally we let cgo use the C library resolver instead of depending
// on our lookup code, so that Go and C get the same answers.
func goLookupPTR(addr string) ([]string, error) {
	names := lookupStaticAddr(addr)
	if len(names) > 0 {
		return names, nil
	}
	arpa, err := reverseaddr(addr)
	if err != nil {
		return nil, err
	}
	_, rrs, err := lookup(arpa, dnsTypePTR)
	if err != nil {
		return nil, err
	}
	ptrs := make([]string, len(rrs))
	for i, rr := range rrs {
		ptrs[i] = rr.(*dnsRR_PTR).Ptr
	}
	return ptrs, nil
}
