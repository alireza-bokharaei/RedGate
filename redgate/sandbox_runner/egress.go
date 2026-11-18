package main

import (
	"fmt"
	"net"
	"strings"
)

// MetadataCIDRs lists cloud instance metadata ranges that are unconditionally
// blocked from sandbox egress regardless of engagement configuration.
var metadataCIDRs = []string{
	"169.254.169.254/32",
	"169.254.170.2/32",
	"100.100.100.200/32",
	"fd00:ec2::254/128",
}

// EgressPolicy holds validated destination IPs/CIDRs permitted for a single job.
type EgressPolicy struct {
	AllowedIPs   []string `json:"allowed_ips"`
	AllowedCIDRs []string `json:"allowed_cidrs"`
	Mode         string   `json:"mode"`
}

// BuildEgressPolicy validates all candidate IP/CIDR destinations, strips any
// cloud metadata endpoints, and produces a normalized egress policy.
func BuildEgressPolicy(candidates []string, enforceIptables bool) (*EgressPolicy, error) {
	blocked := make([]*net.IPNet, 0, len(metadataCIDRs))
	for _, raw := range metadataCIDRs {
		_, cidr, err := net.ParseCIDR(raw)
		if err == nil {
			blocked = append(blocked, cidr)
		}
	}

	// Rendering rules is not enforcement. Never claim an installed firewall or
	// silently satisfy a caller who explicitly requires in-process enforcement.
	if enforceIptables {
		return nil, fmt.Errorf("in-process iptables enforcement is unsupported; configure an external default-deny firewall (no rules were installed)")
	}
	policy := &EgressPolicy{
		AllowedIPs:   []string{},
		AllowedCIDRs: []string{},
		Mode:         "policy_validated_only",
	}

	seen := make(map[string]struct{})
	for _, raw := range candidates {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if _, dup := seen[entry]; dup {
			continue
		}
		seen[entry] = struct{}{}

		if strings.Contains(entry, "/") {
			ip, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid egress CIDR %q: %w", entry, err)
			}
			for _, b := range blocked {
				if b.Contains(ip) || ipNet.Contains(b.IP) {
					return nil, fmt.Errorf("egress CIDR %q overlaps blocked metadata range %s", entry, b.String())
				}
			}
			policy.AllowedCIDRs = append(policy.AllowedCIDRs, ipNet.String())
			continue
		}

		ip := net.ParseIP(entry)
		if ip == nil {
			// Domain names must be resolved & pinned by the Gateway before sandbox run.
			continue
		}
		for _, b := range blocked {
			if b.Contains(ip) {
				return nil, fmt.Errorf("egress IP %q falls in blocked cloud metadata range %s", entry, b.String())
			}
		}
		policy.AllowedIPs = append(policy.AllowedIPs, ip.String())
	}

	return policy, nil
}

// RenderIptablesRules produces deterministic, default-deny OUTPUT rules for an
// ephemeral Linux network namespace dedicated to one sandbox execution.
func (p *EgressPolicy) RenderIptablesRules() []string {
	rules := []string{
		"iptables -P OUTPUT DROP",
		"iptables -F OUTPUT",
		"iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
	}
	// Block metadata ranges explicitly at top of chain.
	for _, m := range metadataCIDRs {
		if !strings.Contains(m, ":") {
			rules = append(rules, fmt.Sprintf("iptables -A OUTPUT -d %s -j REJECT", m))
		}
	}
	for _, ip := range p.AllowedIPs {
		if net.ParseIP(ip).To4() != nil {
			rules = append(rules, fmt.Sprintf("iptables -A OUTPUT -d %s/32 -j ACCEPT", ip))
		}
	}
	for _, cidr := range p.AllowedCIDRs {
		if !strings.Contains(cidr, ":") {
			rules = append(rules, fmt.Sprintf("iptables -A OUTPUT -d %s -j ACCEPT", cidr))
		}
	}
	rules = append(rules, "iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited")
	return rules
}
