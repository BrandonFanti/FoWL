# Fog of War Listener - FoWL 
### A network traffic inspection and injection tool.

> The "fog of war" is the uncertainty in situational awareness experienced by participants in military operations. The term seeks to capture the uncertainty regarding one's own capability, adversary capability, and adversary intent during an engagement, operation, or campaign.


To work against the Red Team's reconnaissance efforts, this tool (inefficiently and fallibly) attempts to listen and respond to various fuzzing, scan, and exploitation attempts.

Highlights:

- Blue Team endeavors:
    - configurable to kin of a very-confusing firewall, or "hollow" honeypot (falsify banners and/or limited services - purely blue team)
- Purple Team:
    - devious redirection to actual honeypots, or 
    - outright redirection of exploit attempts/methods 
        - I call this red-team-by-proxy --
            - redirect your own ports to your targets - make the "enemy" work for you
            - detect and steal their (basic) shells
- Red Team:
    - MITM/Service/Route Poisoning (expanded in TODO)

### HELP
```
usage: FOWL [-h] [--setup-firewall] [-i] [-d] [-l ADDRESS] [-p PORTS]

Fog Of War Listener - FOWL - a network traffic inspection and injection tool.

options:
  -h, --help            show this help message and exit
  --setup-firewall      Setup firewall (iptables) rules to DROP traffic, and allow us to respond over the raw sockets
                        WARNING: This WILL WIPE existing rules, and is not persistent (in itself) 
  -i, --inject          Use root privileges (raw socket(s)) to inject response traffic
  -d, --debugging       Maximize log verbosity
  -l ADDRESS, --bind-address ADDRESS
                        Which source addresses to listen/inject/respond from/on
  -p PORTS, --listen-ports PORTS
                        Which destination ports to listen/inject/respond from

    ~ A tool created by Brandon Fanti ~

Thanks for checking out my project.
```


### Working:
  - Stateless emulation of basic HTTP/1.1 server

### TODO:

- Applicable to *
    - Streamline service emulation implementations
        - capture PCAPs/Pickles
        - auto analysis ~~~ magics ~~~
        - detect/emulate server responses?
    - Implement stateful monitoring of connections (TCP - SEQ/ACK tracking, DNS request/response pairs, etc)
    - root-less packet capture (Blue Team knocker daemon could use regular sockets, and if wireshark group is configured - Red Team gets Recon)
- Blue Team:
    - knocker daemon 
    - specific service emulation toggles (... after writing them.... after writing "Applicable to (*)" - streamline service...)
    - with prereqs 1&2 - complex challenge->response knocker daemon
        - IE: 
            - Find the ports running 'running' HTTP, SSH, DNS servers
                - send post request with *this*
                - send a SYN packet to the port running SSH - _do not respond_ to subsequent packets
                - DNS request for *this* domain
            - *Click* - port x unlocks to the true service y for host _you_
- Purple Team:
    - honeypot submodules/install/setup?
    - Detect basic successful exploits (Port redirection/timing)
        - Detect/prevent meterpreter/nc callbacks?
            - This may be ambitious - would require egghunt on potentially time sensitive data
                - is there a way to "hold" a stateful connection for analysis with heartbeats?
                - prone to middleman DOS, IE: Send massive payloads that trigger the egghunts to max out firewall resources
- Red Team:
    - Recon:
        - Node detection/mapping
        - Hardware (OUI) and OS (other passive traffic - bonjour, NBNS, SSDP, MDNS etc)
    - MITM implementations (IPv4/6)
    - Poisoning
        - MDNS/NBNS/DNS 
        - Route poisoning (Ether/ICMP)
        - MAC flood
        - BEEF hook injection for insecure requests
    - TLS Downgrade attempts? (may not be relevant with TLS1.3 protections by the time it's implemeneted)
    - Shell theft - extend function of purple team exploit success detection







