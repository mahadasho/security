# Linux Security Lab – Network Service Audit
# 1. Summary
I audited the listening network sockets of an Ubuntu 24.04 instance running on WSL2. Every TCP and UDP listener is bound to a loopback address (127.0.0.0/8, ::1) or to 10.255.255.254/32, which is assigned to the lo interface. Nothing listens on eth0 (172.29.170.201) or on a wildcard address (0.0.0.0, ::), so from the inside view no service is reachable from other hosts. The attack surface of this instance is low.

Two items are not fully explained yet: the process behind 10.255.255.254:53 and UDP 323 is not visible even with sudo, and systemd-resolved logs repeated clock changes. Both are listed as follow-up checks in section 7.

# 2. Objective
Analyze network interfaces, identify open ports, and attribute each listening socket to a process. Then assess whether any listener could be a security risk.

# 3. Environment
Item	Value
Date of audit	2026-10-30
Operating system	Ubuntu 24.04 LTS
Kernel	6.6.87.2-microsoft-standard-WSL2
Platform	Windows Subsystem for Linux (WSL2) on Windows 11
Tools	ip, ss, systemctl, journalctl
Hostname, username and MAC address are redacted in the outputs below.

# 4. Methodology
Command	Purpose
uname -r	Kernel version
ip addr	Interfaces and IP addresses
ss -tuln	Listening TCP and UDP sockets
sudo ss -tulnp	Processes that own the sockets
systemctl status systemd-resolved	State of the DNS resolver service and its recent log lines
# 5. Findings
5.1 Interfaces and addresses
Interface	Address	Note
lo	127.0.0.1/8, ::1/128	Standard loopback
lo	10.255.255.254/32	Secondary address on the loopback interface, not on eth0
eth0	172.29.170.201/20	Virtual NIC of the WSL2 VM, no listening sockets bound to it
text
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 ...
    inet 127.0.0.1/8 scope host lo
    inet 10.255.255.254/32 brd 10.255.255.254 scope global lo
    inet6 ::1/128 scope host
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
    inet 172.29.170.201/20 brd 172.29.175.255 scope global eth0
5.2 Listening sockets
text
Netid  State   Local Address:Port     Process
udp    UNCONN  127.0.0.54:53          users:(("systemd-resolve",pid=167,fd=16))
udp    UNCONN  127.0.0.53%lo:53       users:(("systemd-resolve",pid=167,fd=14))
udp    UNCONN  10.255.255.254:53
udp    UNCONN  127.0.0.1:323
udp    UNCONN  [::1]:323
tcp    LISTEN  127.0.0.53%lo:53       users:(("systemd-resolve",pid=167,fd=15))
tcp    LISTEN  10.255.255.254:53
tcp    LISTEN  127.0.0.54:53          users:(("systemd-resolve",pid=167,fd=17))
UNCONN is the normal state of an unconnected UDP socket. It is the UDP equivalent of a listener, not an error.

Socket	Process	Assessment
127.0.0.53:53 (TCP/UDP)	systemd-resolved, PID 167	Expected: local stub resolver, loopback only
127.0.0.54:53 (TCP/UDP)	systemd-resolved, PID 167	Second loopback listener of the same service
10.255.255.254:53 (TCP/UDP)	not visible, even with sudo	Unconfirmed. The address is the nameserver WSL provides in /etc/resolv.conf on recent Windows 11 builds (WSL issue 11698), so this is most likely WSL's built-in DNS proxy. To be verified.
127.0.0.1:323 and [::1]:323 (UDP)	not visible, even with sudo	Unconfirmed. The pattern (UDP 323, localhost and ::1 only) matches the default command port of chronyd (chronyc manual), but chrony is not the default time service on Ubuntu 24.04. To be verified.
5.3 Observation: repeated clock changes
The systemd-resolved journal shows a cache flush roughly every 35 to 50 seconds:

text
Oct 30 12:29:10 <host> systemd-resolved[167]: Clock change detected. Flush...
Oct 30 12:29:44 <host> systemd-resolved[167]: Clock change detected. Flush...
Oct 30 12:30:19 <host> systemd-resolved[167]: Clock change detected. Flush...
Ten such entries appeared between 12:29 and 12:34. systemd-resolved flushes its DNS cache whenever it detects that the system clock changed. On WSL2 the guest clock is separate from the Windows clock, and the Windows time sync and a guest NTP daemon can both adjust it (Deephaven: WSL2 clock drift). This is probably harmless here, but it matters for security work: log correlation in a SIEM needs reliable timestamps.

# External Connectivity Test

A TCP connectivity test was performed from Windows PowerShell against the Ubuntu WSL2 IP address `172.29.170.201`.

**Command:**
`Test-NetConnection -ComputerName 172.29.170.201 -Port 53`

**Results:**
- ICMP ping: Successful
- TCP connection to port 53: Failed

The Ubuntu environment was reachable via ICMP, but TCP port 53 did not accept a connection from Windows.

Earlier local socket analysis showed that the DNS service was listening on loopback addresses rather than the WSL2 network interface.

This result is consistent with a service that is locally available but not reachable through the tested network address.

**Security conclusion:** No TCP accessibility to port 53 was demonstrated from the Windows host. This does not prove that all other ports are closed or that the entire environment is secure.

# 6. Security Assessment
All listeners are bound to loopback addresses. A service bound to 127.0.0.1 accepts connections only from the same host, while one bound to 0.0.0.0 would accept them on every interface, including eth0. No wildcard binds exist, so the exposure to the network is low.

Item	Risk	Reason	Recommendation
127.0.0.53/54:53	Low	Loopback only, expected resolver	None
10.255.255.254:53	Low	Bound to a loopback address, owner not yet confirmed	Confirm via /etc/resolv.conf, do not disable (DNS would break)
UDP 323 on localhost	Low	Loopback only, owner not yet confirmed	Identify the process. If it is chronyd and remote monitoring is not needed, cmdport 0 in its config closes the listener (Docker forum)
Clock changes	Informational	Cache flushes, unreliable timestamps	Check the time sync configuration
Limits of this audit: it is a snapshot from 2026-10-30 and covers only the inside view of the WSL2 VM. It does not assess the Windows host, the Windows firewall, or the network.

# 7. Follow-up checks (replace with results before publishing)
Check	Command	What the result tells me
DNS proxy	cat /etc/resolv.conf	nameserver 10.255.255.254 confirms the WSL DNS proxy
UDP 323 owner	systemctl status chrony, ps aux | grep -i chrony, sudo lsof -iUDP:323	Names the process, or shows that no userland process owns it
Time sync	timedatectl and journalctl -u systemd-timesyncd --since today	Shows which service sets the clock
Outside view	nmap -sT -sU -p 53,323 172.29.170.201 from the Windows host	Confirms that nothing answers on eth0

##  Additional Security Checks

### DNS Configuration

The DNS configuration was inspected using `cat /etc/resolv.conf`.

The configuration was automatically generated by WSL2 and referenced the DNS resolver `10.255.255.254`.

### Time Synchronization

The following commands were executed:

- `systemctl status chrony`
- `ps aux | grep -i chrony`
- `sudo lsof -nP -iUDP:323`
- `timedatectl`

No running Chrony process was identified. However, the operating system reported that its system clock was synchronized and an NTP service was active.

The process responsible for UDP port 323 could not be confirmed.

### Windows-to-WSL2 Connectivity Tests

TCP connectivity tests were performed from Windows PowerShell against the Ubuntu WSL2 IP address `172.29.170.201`.

| Port | Service | TCP Connection |
|---|---|---|
| 22 | SSH | Failed |
| 53 | DNS | Failed |
| 80 | HTTP | Failed |
| 443 | HTTPS | Failed |
| 323 | Chrony-related port | Failed |

ICMP ping to the WSL2 IP address was successful.

The results show that the WSL2 environment was reachable via ICMP, but none of the tested TCP ports accepted a connection from Windows.

## 8. Final Conclusion

This lab demonstrated how to investigate Linux network interfaces, listening sockets, system services, DNS configuration, and network reachability.

The local DNS service `systemd-resolved` was identified and confirmed as active.

The Windows connectivity tests demonstrated the difference between services listening locally and services reachable through a network interface.

No unexpected listening TCP service was identified during the investigation.

However, the assessment was limited to selected ports and the Ubuntu WSL2 environment. It does not represent a complete vulnerability assessment.

### Skills Practiced

- Linux command-line administration
- Network interface analysis
- TCP/UDP socket enumeration
- Process and service investigation
- DNS configuration analysis
- System time verification
- Windows PowerShell connectivity testing
- Technical security documentation

9. References
chronyc manual page
Docker forum: chronyd listening on udp/323
microsoft/WSL issue 11698
Deephaven: WSL2 clock drift

