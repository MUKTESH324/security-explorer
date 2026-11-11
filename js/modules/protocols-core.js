/* Domain: Internet Protocols, core networking */

SE.register({
  id: 'ethernet', domain: 'protocols', kind: 'protocol', level: 'Beginner', severity: 'Layer 2',
  name: 'Ethernet & Switching', full: 'How frames find the right port on a LAN',
  tags: ['ethernet', 'switch', 'mac address', 'frame', 'layer 2', 'cam table'],
  summary: 'Inside a local network, devices talk in Ethernet frames addressed by MAC address. A switch learns which MAC lives on which port and forwards each frame only where it needs to go, flooding only when it doesn\'t know yet.',
  facts: [['Standard', 'IEEE 802.3'], ['OSI layer', 'Layer 2 (Data link)'], ['Address', '48-bit MAC (aa:bb:cc:dd:ee:ff)'], ['Max payload', '1500 bytes (MTU)'], ['Switch memory', 'MAC / CAM table'], ['Broadcast', 'ff:ff:ff:ff:ff:ff']],
  defenses: [
    'Port security: limit how many MAC addresses a port may learn',
    'Use VLANs to split guests, IoT and staff into separate broadcast domains',
    'Enable 802.1X so only authenticated devices get network access',
    'Turn on DHCP snooping and Dynamic ARP Inspection on access switches',
  ],
  nodes: [
    { id: 'a', type: 'client', label: 'Laptop A', sub: 'aa:aa:aa:00:00:0a', x: 140, y: 120 },
    { id: 'b', type: 'workstation', label: 'Desktop B', sub: 'bb:bb:bb:00:00:0b', x: 140, y: 380 },
    { id: 'sw', type: 'switch', label: 'Switch', sub: '24 ports', x: 450, y: 245 },
    { id: 'c', type: 'server', label: 'Printer C', sub: 'cc:cc:cc:00:00:0c', x: 770, y: 120 },
    { id: 'gw', type: 'router', label: 'Router', sub: 'cc:00:00:00:00:01', x: 770, y: 380 },
  ],
  steps: [
    {
      title: 'Empty table', sub: 'The switch knows nothing yet',
      text: 'Laptop A sends a frame to Printer C. The switch records that A\'s MAC address is on port 1, but it has never seen C, so it floods the frame out of every other port.',
      fields: [['Learned', 'aa:aa:…:0a → port 1'], ['Destination', 'unknown → flood']],
      packets: [
        ['a', 'sw', 'Ethernet', 'src aa:…:0a → dst cc:…:0c (print job)', 1514, 'req'],
        ['sw', 'b', 'Ethernet', 'Flooded copy (B ignores it, not its MAC)', 1514, 'ctl'],
        ['sw', 'c', 'Ethernet', 'Flooded copy (C accepts it)', 1514, 'req'],
        ['sw', 'gw', 'Ethernet', 'Flooded copy (router ignores it)', 1514, 'ctl'],
      ],
    },
    {
      title: 'Learning from replies', sub: 'Now both ends are known',
      text: 'When Printer C replies, the switch learns C is on port 7. From now on, frames between A and C go only to the right port.',
      fields: [['Learned', 'cc:cc:…:0c → port 7'], ['Table entries', '2']],
      packets: [
        ['c', 'sw', 'Ethernet', 'src cc:…:0c → dst aa:…:0a (ack)', 64, 'res'],
        ['sw', 'a', 'Ethernet', 'Forwarded to port 1 only', 64, 'res'],
      ],
    },
    {
      title: 'Direct forwarding', sub: 'No more flooding',
      text: 'The next frames are switched straight to their port. This is why a switch is faster and more private than an old hub, which copied everything to everyone.',
      fields: [['A → C', 'port 1 → port 7 only'], ['Others see it?', 'No']],
      packets: [
        ['a', 'sw', 'Ethernet', 'src aa:…:0a → dst cc:…:0c', 1514, 'req'],
        ['sw', 'c', 'Ethernet', 'Forwarded to port 7 only', 1514, 'req'],
      ],
    },
    {
      title: 'Broadcasts', sub: 'Messages for everyone',
      text: 'Some frames are meant for every device, like an ARP request or DHCP discover. They go to the broadcast address and the switch delivers them to all ports in the same VLAN.',
      fields: [['Destination', 'ff:ff:ff:ff:ff:ff'], ['Scope', 'One VLAN (broadcast domain)']],
      defend: 'Everything on the same VLAN can see broadcasts and attempt layer-2 attacks. Segment untrusted devices into their own VLAN.',
      packets: [
        ['b', 'sw', 'ARP', 'Who has 192.168.1.1? (broadcast)', 42, 'ctl'],
        ['sw', 'a', 'Ethernet', 'Broadcast copy', 42, 'ctl'],
        ['sw', 'c', 'Ethernet', 'Broadcast copy', 42, 'ctl'],
        ['sw', 'gw', 'Ethernet', 'Broadcast copy', 42, 'ctl'],
        ['gw', 'b', 'ARP', '192.168.1.1 is at cc:00:00:00:00:01', 42, 'res'],
      ],
    },
  ],
});

SE.register({
  id: 'dhcp', domain: 'protocols', kind: 'protocol', level: 'Beginner', severity: 'Protocol',
  name: 'DHCP', full: 'Dynamic Host Configuration Protocol',
  tags: ['dhcp', 'dora', 'ip address', 'lease', 'bootp'],
  summary: 'When a device joins a network it has no IP address. DHCP hands it one, along with the router, DNS servers and lease time, in a four-message exchange known as DORA: Discover, Offer, Request, Acknowledge.',
  facts: [['Defined in', 'RFC 2131'], ['Transport', 'UDP 67 (server), 68 (client)'], ['Exchange', 'Discover · Offer · Request · Ack'], ['Gives out', 'IP, mask, gateway, DNS, lease'], ['Typical lease', '24 hours'], ['IPv6 equivalent', 'SLAAC / DHCPv6']],
  defenses: [
    'Enable DHCP snooping so only trusted switch ports may answer as a DHCP server',
    'Watch for rogue DHCP servers; a fake one can redirect all traffic',
    'Rate-limit DHCP requests to stop pool exhaustion',
    'Reserve addresses for servers and network gear',
  ],
  nodes: [
    { id: 'c', type: 'client', label: 'New Laptop', sub: 'no IP yet', x: 140, y: 245 },
    { id: 'sw', type: 'switch', label: 'Switch', sub: 'broadcast domain', x: 450, y: 245 },
    { id: 'srv', type: 'router', label: 'DHCP Server', sub: '192.168.1.1', x: 760, y: 245 },
  ],
  steps: [
    {
      title: 'Discover', sub: 'Anyone out there?',
      text: 'The laptop has no address, so it sends from `0.0.0.0` to the broadcast address `255.255.255.255`, asking any DHCP server for an address.',
      fields: [['Source', '0.0.0.0:68'], ['Destination', '255.255.255.255:67']],
      packets: [
        ['c', 'sw', 'DHCP', 'DHCPDISCOVER (broadcast, xid 0x3903f326)', 342, 'ctl'],
        ['sw', 'srv', 'DHCP', 'DHCPDISCOVER (broadcast copy)', 342, 'ctl'],
      ],
    },
    {
      title: 'Offer', sub: 'Here is an address you can have',
      text: 'The server picks a free address from its pool and offers it, along with the network settings.',
      fields: [['Offered IP', '192.168.1.42'], ['Gateway / DNS', '192.168.1.1 / 192.168.1.1']],
      packets: [
        ['srv', 'c', 'DHCP', 'DHCPOFFER 192.168.1.42, lease 86400 s', 342, 'res',
          `DHCP Offer
  Your IP:      192.168.1.42
  Subnet mask:  255.255.255.0
  Router:       192.168.1.1
  DNS servers:  192.168.1.1
  Lease time:   86400 s (24 h)
  Server ID:    192.168.1.1`],
      ],
    },
    {
      title: 'Request', sub: 'I\'ll take it',
      text: 'The laptop broadcasts a request for that exact address. Broadcasting lets any other servers that made offers know they weren\'t chosen.',
      fields: [['Requested IP', '192.168.1.42'], ['Server ID', '192.168.1.1']],
      packets: [
        ['c', 'sw', 'DHCP', 'DHCPREQUEST 192.168.1.42 (broadcast)', 342, 'ctl'],
        ['sw', 'srv', 'DHCP', 'DHCPREQUEST (broadcast copy)', 342, 'ctl'],
      ],
    },
    {
      title: 'Acknowledge', sub: 'Lease confirmed',
      text: 'The server confirms. The laptop configures the address and can now reach the internet. Halfway through the lease it quietly renews it directly with the server.',
      fields: [['Bound', '192.168.1.42/24'], ['Renew at', '50% of lease (T1)']],
      defend: 'Any device on the LAN can pretend to be a DHCP server and hand out its own address as the gateway. DHCP snooping on the switch blocks that.',
      packets: [
        ['srv', 'c', 'DHCP', 'DHCPACK 192.168.1.42, lease 86400 s', 342, 'res'],
        ['c', 'c', 'Local', 'Interface configured: 192.168.1.42/24 via 192.168.1.1', 0, 'def'],
      ],
    },
  ],
});

SE.register({
  id: 'ip-routing', domain: 'protocols', kind: 'protocol', level: 'Beginner', severity: 'Layer 3',
  name: 'IP Routing & Traceroute', full: 'How packets hop across networks',
  tags: ['ip', 'routing', 'ttl', 'traceroute', 'hops', 'layer 3'],
  summary: 'IP gets a packet from one network to another, hop by hop. Each router looks at the destination address, forwards it one step closer, and lowers the TTL by one. Traceroute uses that TTL to reveal every hop on the path.',
  facts: [['Defined in', 'RFC 791 (IPv4)'], ['OSI layer', 'Layer 3 (Network)'], ['Header field', 'TTL (hop limit)'], ['On TTL = 0', 'ICMP Time Exceeded'], ['Tool', 'traceroute / tracert'], ['Addressing', 'IPv4 32-bit, IPv6 128-bit']],
  defenses: [
    'Filter spoofed source addresses at your network edge (BCP 38)',
    'Rate-limit ICMP rather than blocking it completely',
    'Don\'t leak internal hostnames in reverse DNS on routers',
    'Segment internal networks with routed boundaries and ACLs',
  ],
  nodes: [
    { id: 'pc', type: 'client', label: 'Your PC', sub: '192.168.1.42', x: 110, y: 245 },
    { id: 'r1', type: 'router', label: 'Home Router', sub: '192.168.1.1', x: 290, y: 245 },
    { id: 'r2', type: 'router', label: 'ISP Router', sub: '100.64.0.1', x: 470, y: 245 },
    { id: 'r3', type: 'router', label: 'Transit Router', sub: '203.0.113.9', x: 650, y: 245 },
    { id: 'srv', type: 'server', label: 'Web Server', sub: '198.51.100.10', x: 810, y: 245 },
  ],
  steps: [
    {
      title: 'Hop 1', sub: 'TTL = 1',
      text: 'Traceroute sends a probe with TTL 1. The home router decrements it to 0, drops the packet, and sends back an ICMP "Time Exceeded". Now we know hop 1.',
      fields: [['TTL sent', '1'], ['Revealed', '192.168.1.1 (1.2 ms)']],
      packets: [
        ['pc', 'r1', 'UDP', 'Probe → 198.51.100.10:33434, TTL=1', 60, 'req'],
        ['r1', 'pc', 'ICMP', 'Time-to-live exceeded (from 192.168.1.1)', 88, 'res'],
      ],
    },
    {
      title: 'Hop 2', sub: 'TTL = 2',
      text: 'The next probe has TTL 2. The home router forwards it (TTL becomes 1), and the ISP router drops it and reports back.',
      fields: [['TTL sent', '2'], ['Revealed', '100.64.0.1 (9.8 ms)']],
      packets: [
        ['pc', 'r1', 'UDP', 'Probe, TTL=2', 60, 'req'],
        ['r1', 'r2', 'UDP', 'Forwarded, TTL=1', 60, 'req'],
        ['r2', 'pc', 'ICMP', 'Time-to-live exceeded (from 100.64.0.1)', 88, 'res'],
      ],
    },
    {
      title: 'Hop 3', sub: 'TTL = 3',
      text: 'One more hop out. The transit router, owned by a backbone provider, answers this time.',
      fields: [['TTL sent', '3'], ['Revealed', '203.0.113.9 (18.4 ms)']],
      packets: [
        ['pc', 'r1', 'UDP', 'Probe, TTL=3', 60, 'req'],
        ['r1', 'r2', 'UDP', 'Forwarded, TTL=2', 60, 'req'],
        ['r2', 'r3', 'UDP', 'Forwarded, TTL=1', 60, 'req'],
        ['r3', 'pc', 'ICMP', 'Time-to-live exceeded (from 203.0.113.9)', 88, 'res'],
      ],
    },
    {
      title: 'Destination reached', sub: 'Port unreachable means "arrived"',
      text: 'With TTL 4 the probe reaches the server. Nothing listens on that high UDP port, so the server replies "Port Unreachable", which tells traceroute it has arrived.',
      fields: [['Hops', '4'], ['Total latency', '21.7 ms']],
      defend: 'Traceroute output maps an organisation\'s network edge. Many networks rate-limit or hide internal hops for that reason.',
      packets: [
        ['pc', 'r1', 'UDP', 'Probe, TTL=4', 60, 'req'],
        ['r1', 'r2', 'UDP', 'Forwarded, TTL=3', 60, 'req'],
        ['r2', 'r3', 'UDP', 'Forwarded, TTL=2', 60, 'req'],
        ['r3', 'srv', 'UDP', 'Forwarded, TTL=1', 60, 'req'],
        ['srv', 'pc', 'ICMP', 'Destination unreachable (port unreachable)', 88, 'res'],
      ],
    },
  ],
});

SE.register({
  id: 'icmp', domain: 'protocols', kind: 'protocol', level: 'Beginner', severity: 'Protocol',
  name: 'ICMP & Ping', full: 'Internet Control Message Protocol',
  tags: ['icmp', 'ping', 'echo', 'unreachable', 'pmtud', 'mtu'],
  summary: 'ICMP is how the network reports problems and answers simple checks. Ping uses it to test reachability, routers use it to say a destination is unreachable, and it quietly helps find the largest packet size a path can carry.',
  facts: [['Defined in', 'RFC 792'], ['Carried in', 'IP (protocol 1)'], ['Ping', 'Type 8 request / Type 0 reply'], ['Unreachable', 'Type 3'], ['Time exceeded', 'Type 11'], ['IPv6 version', 'ICMPv6 (essential)']],
  defenses: [
    'Rate-limit ICMP instead of blocking it; blocking breaks Path MTU Discovery',
    'Allow "fragmentation needed" (type 3 code 4) through firewalls',
    'Watch for ICMP tunnels: large or regular echo payloads can hide data',
    'Never block ICMPv6 wholesale; IPv6 depends on it',
  ],
  nodes: [
    { id: 'pc', type: 'client', label: 'Your PC', sub: '192.168.1.42', x: 140, y: 245 },
    { id: 'rt', type: 'router', label: 'Router', sub: 'MTU 1400 link', x: 450, y: 245 },
    { id: 'srv', type: 'server', label: 'Server', sub: '198.51.100.10', x: 760, y: 245 },
  ],
  steps: [
    {
      title: 'Ping', sub: 'Are you there?',
      text: 'Ping sends an Echo Request with an ID and sequence number. The server copies the payload into an Echo Reply. The round-trip time shows latency.',
      fields: [['Request', 'Type 8, id 0x1a2b, seq 1'], ['Round trip', '14.2 ms']],
      packets: [
        ['pc', 'rt', 'ICMP', 'Echo (ping) request id=0x1a2b seq=1', 98, 'req'],
        ['rt', 'srv', 'ICMP', 'Echo request (forwarded)', 98, 'req'],
        ['srv', 'rt', 'ICMP', 'Echo (ping) reply id=0x1a2b seq=1', 98, 'res'],
        ['rt', 'pc', 'ICMP', 'Echo reply (forwarded)', 98, 'res'],
      ],
    },
    {
      title: 'Destination unreachable', sub: 'The network explains failures',
      text: 'If the router has no route to a destination, it doesn\'t just drop the packet silently. It sends back "Destination Unreachable", so your app fails fast instead of waiting.',
      fields: [['Type / code', '3 / 1 (host unreachable)'], ['Effect', 'Fast, clear error']],
      packets: [
        ['pc', 'rt', 'TCP', '→ 10.99.0.5:443 [SYN]', 66, 'req'],
        ['rt', 'pc', 'ICMP', 'Destination unreachable (host unreachable)', 94, 'res'],
      ],
    },
    {
      title: 'Path MTU discovery', sub: 'Finding the biggest safe packet',
      text: 'A large packet with "don\'t fragment" set hits a link that only carries 1400 bytes. The router replies "Fragmentation needed, MTU 1400", and the sender shrinks its packets.',
      fields: [['Sent', '1500 bytes, DF set'], ['Reply', 'Type 3 code 4, next-hop MTU 1400']],
      defend: 'Firewalls that block all ICMP break this, causing connections that hang on large transfers. Allow this message type.',
      packets: [
        ['pc', 'rt', 'TCP', 'Data segment 1500 bytes [DF]', 1500, 'req'],
        ['rt', 'pc', 'ICMP', 'Fragmentation needed, next-hop MTU 1400', 70, 'ctl'],
        ['pc', 'rt', 'TCP', 'Resent as 1400-byte segments', 1400, 'req'],
        ['rt', 'srv', 'TCP', 'Forwarded', 1400, 'req'],
      ],
    },
  ],
});

SE.register({
  id: 'tcp', domain: 'protocols', kind: 'protocol', level: 'Beginner', severity: 'Layer 4',
  name: 'TCP', full: 'Transmission Control Protocol',
  tags: ['tcp', 'handshake', 'syn', 'ack', 'retransmission', 'fin', 'layer 4'],
  summary: 'TCP turns an unreliable network into a reliable, ordered stream of bytes. It opens a connection with a three-way handshake, numbers every byte, resends anything that gets lost, and closes cleanly.',
  facts: [['Defined in', 'RFC 9293'], ['OSI layer', 'Layer 4 (Transport)'], ['Setup', 'SYN · SYN-ACK · ACK'], ['Reliability', 'Sequence numbers + ACKs'], ['Teardown', 'FIN / ACK each way'], ['Used by', 'HTTP/1.1, HTTP/2, SSH, SMTP, TLS']],
  defenses: [
    'Enable SYN cookies against SYN floods',
    'Close unused ports; every listening port is attack surface',
    'Use TLS on top. TCP itself has no encryption or authentication',
    'Keep timeouts sensible to avoid exhausting connection slots',
  ],
  nodes: [
    { id: 'c', type: 'client', label: 'Client', sub: '192.168.1.42:52344', x: 140, y: 245 },
    { id: 's', type: 'server', label: 'Server', sub: '198.51.100.10:443', x: 760, y: 245 },
  ],
  steps: [
    {
      title: 'Three-way handshake', sub: 'Agreeing to talk',
      text: 'The client sends SYN with a random starting sequence number. The server answers SYN-ACK with its own, and the client confirms with ACK. Both sides now know where the other\'s byte count starts.',
      fields: [['Client ISN', '1209384710'], ['Server ISN', '3920100388']],
      packets: [
        ['c', 's', 'TCP', '52344 → 443 [SYN] Seq=0 Win=65535 MSS=1460', 66, 'ctl'],
        ['s', 'c', 'TCP', '443 → 52344 [SYN, ACK] Seq=0 Ack=1 MSS=1460', 66, 'ctl'],
        ['c', 's', 'TCP', '52344 → 443 [ACK] Seq=1 Ack=1', 54, 'ctl'],
      ],
    },
    {
      title: 'Sending data', sub: 'Every byte is counted',
      text: 'Data flows in segments. Each ACK says "I\'ve received everything up to byte N". The window size tells the sender how much it may have in flight at once.',
      fields: [['Sent', '517 bytes'], ['ACK', 'Ack=518 (next byte expected)']],
      packets: [
        ['c', 's', 'TCP', '[PSH, ACK] Seq=1 Len=517', 571, 'req'],
        ['s', 'c', 'TCP', '[ACK] Ack=518', 54, 'ctl'],
        ['s', 'c', 'TCP', '[PSH, ACK] Seq=1 Len=1460', 1514, 'res'],
        ['s', 'c', 'TCP', '[PSH, ACK] Seq=1461 Len=1460', 1514, 'res'],
        ['c', 's', 'TCP', '[ACK] Ack=2921', 54, 'ctl'],
      ],
    },
    {
      title: 'Loss and retransmission', sub: 'Reliability in action',
      text: 'One segment is lost on the way. The client keeps acknowledging the last byte it has in order. After three duplicate ACKs, the server resends the missing segment (fast retransmit).',
      fields: [['Lost', 'Seq=2921'], ['Signal', '3 duplicate ACKs']],
      packets: [
        ['s', 'c', 'TCP', '[PSH, ACK] Seq=4381 Len=1460 (Seq=2921 was lost)', 1514, 'res'],
        ['c', 's', 'TCP', '[ACK] Ack=2921 (dup ACK ×3)', 162, 'ctl'],
        ['s', 'c', 'TCP', '[PSH, ACK] Seq=2921 Len=1460 (retransmission)', 1514, 'res'],
        ['c', 's', 'TCP', '[ACK] Ack=5841', 54, 'ctl'],
      ],
    },
    {
      title: 'Closing', sub: 'FIN from both sides',
      text: 'Each side closes its own direction with FIN and gets an ACK. The side that closed first waits a short time (TIME_WAIT) in case any stray packets are still in flight.',
      fields: [['Sequence', 'FIN → ACK, FIN → ACK'], ['Final state', 'TIME_WAIT then CLOSED']],
      defend: 'TCP sequence numbers are random so attackers can\'t easily inject data or reset connections they can\'t see.',
      packets: [
        ['c', 's', 'TCP', '[FIN, ACK] Seq=518', 54, 'ctl'],
        ['s', 'c', 'TCP', '[ACK] Ack=519', 54, 'ctl'],
        ['s', 'c', 'TCP', '[FIN, ACK] Seq=5841', 54, 'ctl'],
        ['c', 's', 'TCP', '[ACK] Ack=5842', 54, 'ctl'],
      ],
    },
  ],
});

SE.register({
  id: 'udp', domain: 'protocols', kind: 'protocol', level: 'Beginner', severity: 'Layer 4',
  name: 'UDP', full: 'User Datagram Protocol',
  tags: ['udp', 'datagram', 'voip', 'gaming', 'amplification', 'layer 4'],
  summary: 'UDP is the fast, simple alternative to TCP: no handshake, no retransmission, no ordering. Each datagram travels on its own. That suits real-time traffic like voice and games, and protocols like DNS that build their own retries.',
  facts: [['Defined in', 'RFC 768'], ['Header size', '8 bytes'], ['Handshake', 'None'], ['Reliability', 'None (app decides)'], ['Used by', 'DNS, QUIC, VoIP, games, NTP'], ['Risk', 'Easy to spoof source']],
  defenses: [
    'Validate who you\'re talking to at the application layer; UDP source addresses are easy to fake',
    'Don\'t expose UDP services that send big replies to small requests (amplification)',
    'Rate-limit per source',
    'Prefer protocols with built-in authentication (DTLS, QUIC)',
  ],
  nodes: [
    { id: 'c', type: 'phone', label: 'Game Client', sub: '192.168.1.42:50000', x: 140, y: 245 },
    { id: 's', type: 'server', label: 'Game Server', sub: '198.51.100.20:27015', x: 760, y: 245 },
  ],
  steps: [
    {
      title: 'Just send', sub: 'No handshake',
      text: 'The client sends its first datagram immediately. There is no connection setup, so the first message arrives one full round trip sooner than with TCP.',
      fields: [['Setup cost', '0 round trips'], ['Header', 'src port, dst port, length, checksum']],
      packets: [
        ['c', 's', 'UDP', '50000 → 27015 Len=48 (join game)', 90, 'req'],
        ['s', 'c', 'UDP', '27015 → 50000 Len=320 (world state)', 362, 'res'],
      ],
    },
    {
      title: 'Steady stream', sub: 'Many small updates',
      text: 'Position updates flow many times a second in both directions. Each one is independent.',
      fields: [['Rate', '60 updates / s'], ['Size', '~60 bytes each']],
      packets: [
        ['c', 's', 'UDP', 'Player input tick 1041', 102, 'req'],
        ['s', 'c', 'UDP', 'World state tick 1041', 362, 'res'],
        ['c', 's', 'UDP', 'Player input tick 1042', 102, 'req'],
        ['s', 'c', 'UDP', 'World state tick 1042', 362, 'res'],
      ],
    },
    {
      title: 'Loss is fine', sub: 'Old data is useless anyway',
      text: 'A datagram is lost. Nobody resends it, because by the time it arrived a newer update would already have replaced it. For real-time apps, that\'s a feature.',
      fields: [['Lost', 'tick 1043'], ['Recovery', 'Next update replaces it']],
      defend: 'Because there is no handshake, a UDP source address can be forged. Attackers abuse open UDP services to reflect large replies at victims.',
      packets: [
        ['s', 'c', 'UDP', 'World state tick 1043 (lost, never resent)', 362, 'res'],
        ['s', 'c', 'UDP', 'World state tick 1044', 362, 'res'],
      ],
    },
  ],
});

SE.register({
  id: 'dns', domain: 'protocols', kind: 'protocol', level: 'Beginner', severity: 'Protocol',
  name: 'DNS', full: 'Domain Name System',
  tags: ['dns', 'resolver', 'root', 'tld', 'authoritative', 'recursion', 'cache', 'doh'],
  summary: 'DNS turns names like `securityexplorer.org` into IP addresses. Your resolver walks the hierarchy from the root servers, to the `.org` servers, to the domain\'s own name servers, then caches the answer so the next lookup is instant.',
  facts: [['Defined in', 'RFC 1034, RFC 1035'], ['Transport', 'UDP/TCP 53'], ['Encrypted', 'DoH (443), DoT (853)'], ['Hierarchy', 'Root → TLD → Authoritative'], ['Caching', 'TTL per record'], ['Record types', 'A, AAAA, CNAME, MX, TXT, NS']],
  defenses: [
    'Validate DNSSEC on resolvers; sign your own zones',
    'Use encrypted DNS (DoH/DoT) to a trusted resolver',
    'Lock your domain at the registrar and enable 2FA there',
    'Remove dangling CNAMEs that point at deleted cloud resources',
    'Monitor DNS logs: tunnels and malware show up as odd queries',
  ],
  nodes: [
    { id: 'pc', type: 'client', label: 'Your PC', sub: 'stub resolver', x: 110, y: 245 },
    { id: 'res', type: 'dns', label: 'Resolver', sub: '1.1.1.1', x: 380, y: 245 },
    { id: 'root', type: 'dns', label: 'Root Server', sub: 'a.root-servers.net', x: 720, y: 90 },
    { id: 'tld', type: 'dns', label: '.org Server', sub: 'TLD name server', x: 800, y: 245 },
    { id: 'auth', type: 'dns', label: 'Authoritative', sub: 'ns1.example-dns.net', x: 720, y: 400 },
  ],
  steps: [
    {
      title: 'Ask the resolver', sub: 'One question from your PC',
      text: 'Your PC asks its configured resolver a single question: "What is the A record for www.example.org?" The resolver does the rest of the work.',
      fields: [['Query', 'www.example.org A'], ['Recursion desired', 'Yes']],
      packets: [
        ['pc', 'res', 'DNS', 'Standard query 0x4f1a A www.example.org', 74, 'req'],
      ],
    },
    {
      title: 'Root referral', sub: '"Ask the .org servers"',
      text: 'The resolver starts at a root server. The root doesn\'t know the answer, but it knows who runs `.org` and returns a referral.',
      fields: [['Asked', 'Root server'], ['Answer', 'Referral to .org name servers']],
      packets: [
        ['res', 'root', 'DNS', 'Query A www.example.org', 74, 'req'],
        ['root', 'res', 'DNS', 'Referral: org. NS a0.org.afilias-nst.info …', 820, 'res'],
      ],
    },
    {
      title: 'TLD referral', sub: '"Ask example.org\'s name servers"',
      text: 'The `.org` server knows which name servers are authoritative for `example.org` and refers the resolver there.',
      fields: [['Asked', '.org TLD server'], ['Answer', 'Referral to ns1.example-dns.net']],
      packets: [
        ['res', 'tld', 'DNS', 'Query A www.example.org', 74, 'req'],
        ['tld', 'res', 'DNS', 'Referral: example.org. NS ns1.example-dns.net', 260, 'res'],
      ],
    },
    {
      title: 'Authoritative answer', sub: 'The real record',
      text: 'The domain\'s own name server has the record and answers with the IP address and a TTL that says how long it may be cached.',
      fields: [['Answer', 'A 198.51.100.10'], ['TTL', '3600 s']],
      packets: [
        ['res', 'auth', 'DNS', 'Query A www.example.org', 74, 'req'],
        ['auth', 'res', 'DNS', 'Response A 198.51.100.10 TTL 3600 (authoritative)', 90, 'res'],
      ],
    },
    {
      title: 'Answer and cache', sub: 'Fast the second time',
      text: 'The resolver returns the address to your PC and keeps it in its cache. Anyone asking in the next hour gets the answer instantly, without touching the root, TLD or authoritative servers.',
      fields: [['Cached for', '3600 s'], ['Next lookup', '~1 ms from cache']],
      defend: 'Plain DNS is unencrypted and unauthenticated. DNSSEC proves answers are genuine; DoH/DoT hides your queries from the local network.',
      packets: [
        ['res', 'pc', 'DNS', 'Standard query response 0x4f1a A 198.51.100.10', 90, 'res'],
        ['pc', 'res', 'DNS', 'Standard query A www.example.org (later)', 74, 'req'],
        ['res', 'pc', 'DNS', 'Response A 198.51.100.10 (from cache)', 90, 'res'],
      ],
    },
  ],
});

SE.register({
  id: 'http', domain: 'protocols', kind: 'protocol', level: 'Beginner', severity: 'Protocol',
  name: 'HTTP', full: 'Hypertext Transfer Protocol',
  tags: ['http', 'web', 'request', 'response', 'headers', 'status code', 'cookies', 'cache'],
  summary: 'HTTP is the language of the web. A client sends a request (a method, a path and headers) and the server returns a response with a status code, headers and usually a body. Everything else on the web is built on this simple exchange.',
  facts: [['Defined in', 'RFC 9110, RFC 9112'], ['Port', '80 (HTTPS: 443)'], ['Methods', 'GET, POST, PUT, DELETE, PATCH'], ['Status classes', '2xx ok · 3xx redirect · 4xx client · 5xx server'], ['State', 'Stateless (cookies add sessions)'], ['Versions', 'HTTP/1.1, HTTP/2, HTTP/3']],
  defenses: [
    'Serve everything over HTTPS and send HSTS',
    'Set security headers: Content-Security-Policy, X-Content-Type-Options, Referrer-Policy',
    'Mark cookies Secure, HttpOnly and SameSite',
    'Never put secrets or tokens in URLs; they end up in logs and history',
  ],
  nodes: [
    { id: 'br', type: 'browser', label: 'Browser', sub: '192.168.1.42', x: 140, y: 245 },
    { id: 'dns', type: 'dns', label: 'DNS Resolver', sub: '1.1.1.1', x: 450, y: 90 },
    { id: 'srv', type: 'server', label: 'Web Server', sub: 'www.example.org', x: 760, y: 245 },
  ],
  steps: [
    {
      title: 'Find the server', sub: 'Name to address',
      text: 'You type `http://www.example.org`. The browser first looks up the IP address with DNS, then opens a TCP connection to port 80.',
      fields: [['URL', 'http://www.example.org/'], ['Resolved', '198.51.100.10']],
      packets: [
        ['br', 'dns', 'DNS', 'Query A www.example.org', 74, 'req'],
        ['dns', 'br', 'DNS', 'Response A 198.51.100.10', 90, 'res'],
        ['br', 'srv', 'TCP', '52344 → 80 [SYN] / [SYN, ACK] / [ACK]', 186, 'ctl'],
      ],
    },
    {
      title: 'The request', sub: 'Method, path, headers',
      text: 'The browser sends a plain-text request: the method `GET`, the path, and headers describing what it accepts.',
      fields: [['Method', 'GET'], ['Path', '/']],
      packets: [
        ['br', 'srv', 'HTTP', 'GET / HTTP/1.1', 412, 'req',
          `GET / HTTP/1.1
Host: www.example.org
User-Agent: Mozilla/5.0 (Macintosh)
Accept: text/html,application/xhtml+xml
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, br
Connection: keep-alive`],
      ],
    },
    {
      title: 'The response', sub: 'Status, headers, body',
      text: 'The server answers `200 OK` with headers (content type, caching rules, cookies) and the HTML body. The browser then requests the CSS, scripts and images the page refers to, reusing the same connection.',
      fields: [['Status', '200 OK'], ['Body', 'text/html, 12.4 KB (gzip)']],
      packets: [
        ['srv', 'br', 'HTTP', 'HTTP/1.1 200 OK (text/html)', 12800, 'res',
          `HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Encoding: gzip
Cache-Control: max-age=300
ETag: "5f2a-19c"
Set-Cookie: session=7f3a…; Secure; HttpOnly; SameSite=Lax

<!doctype html><html>…</html>`],
        ['br', 'srv', 'HTTP', 'GET /style.css', 380, 'req'],
        ['srv', 'br', 'HTTP', 'HTTP/1.1 200 OK (text/css)', 4100, 'res'],
      ],
    },
    {
      title: 'Caching', sub: 'Not modified',
      text: 'On the next visit the browser asks "has this changed since version 5f2a?" using `If-None-Match`. The server replies `304 Not Modified` with no body, saving bandwidth.',
      fields: [['Request header', 'If-None-Match: "5f2a-19c"'], ['Response', '304, no body']],
      defend: 'Plain HTTP is readable and editable by anyone on the path. Real sites redirect to HTTPS and send HSTS so browsers never use plain HTTP again.',
      packets: [
        ['br', 'srv', 'HTTP', 'GET / (If-None-Match: "5f2a-19c")', 430, 'req'],
        ['srv', 'br', 'HTTP', 'HTTP/1.1 304 Not Modified', 180, 'res'],
      ],
    },
  ],
});
