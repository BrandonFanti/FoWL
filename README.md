<p align="center">
<img src=src/visualization/assets/fowl.png alt="fowl.png" width="30%" margin=auto>
</p>

# Fog Of War Listener - FOWL 
## --- a network traffic inspection and injection tool.

> The "fog of war" is the uncertainty in situational awareness experienced by participants in military operations. 

> The term seeks to capture the uncertainty regarding one's own capability, adversary capability, and adversary intent during an engagement, operation, or campaign. 

> "The quieter you become, the more you are able to hear"


## UI Sample:
<img src=src/visualization/assets/sample.png alt="sample.png">

<details>
<summary> 
*Note - concerning shrug.jpg 
</summary>
It appears for 2 reasons:

 1. Your sensor has not collected any data relevant to the visualizer-segment.
 2. In IP->IP graphs:
    - if you don't have the network configured for the interface used in collection, or 
    - ran a PCAP through `FOWL.py` with `-f $file`/`--pcap $file`
</details>

### Quick HELP
```
usage: FOWL [-h] [--setup-firewall] [--no-timeout] [-f FILE] [--pcap-filter PCAP_FILTER] [-i] [-v]
            [--crash-on-handler-exception] [--suppress-handler-unhandled] [-l ADDRESS] [-p PORTS]

Fog Of War Listener - FOWL - a network traffic inspection and injection tool.

options:
  -h, --help            show this help message and exit
  --setup-firewall      Setup firewall rules to DROP traffic, and allow us to respond over the raw sockets
                                            WARNING: This WILL WIPE existing rules, and is not persistent (in itself) 
  --no-timeout          Disables the default capture window of 5 minutes
  -f FILE, --pcap FILE  Analyze a pcap file
  --pcap-filter PCAP_FILTER
                        Apply a custom pcap-filter to constrain traffic FoWL receives - for more info, run `man pcap-filter`
  -i, --inject          Use root privileges (raw socket(s)) to inject response traffic
  -v, --debugging       Maximize log verbosity
  --crash-on-handler-exception
                        useful for debugging custom handler exceptions raised by an engine
  --suppress-handler-unhandled
                        useful for debugging custom handler exceptions raised by an engine
  -l ADDRESS, --bind-address ADDRESS
                        Which source addresses to listen/inject/respond from/on
  -p PORTS, --listen-ports PORTS
                        Which destination ports to listen/inject/respond from

    ~ A tool created by Brandon Fanti ~

Thanks for checking out my project.
```

<details>
<summary> 

# Q & A 

</summary>

> # You: **What** is this?

In a few words: A firewall with somewhat limited but informative dissection capabilities, and more limited (atm) traffic injection capability.

It's also decent as a framework for packet dissection (if you know scapy <3), has segregated logging, *very basic* network modeling, and "indirect" passive host fingerprinting.


> # Ok... and **Why** is this?

I just like doing things like this. ¯\\\_(ツ)_/¯

`I am a hacker, enter my world...`

`Yes, I am a criminal.  My crime is that of curiosity.  My crime is
that of judging people by what they say and think, not what they look like.` -

> `My crime is that of outsmarting you, something that you will never forgive me for.`

--- The Mentor

### Wait- Wait- OK- 
### specifically this,

No such tool existed that combines the functionality of a [port knocking](https://en.wikipedia.org/wiki/Port_knocking), 
[fail2ban](https://en.wikipedia.org/wiki/Fail2ban), and... well I can't find anything technical/"official" to describe it, but its something between "phishing and fuzzing" of hacker tools/kits/scanners/**botnets**, and "a honeypot"(if I ever see my original dream to fruition, honeypot would be an inclusive term.)

Fairly early on, I decided a merge of those 3 things was "a solid thing to make", and provides a more foundational function than my "lame port scan responder" (The OG name.)

I deeply expand on "the why", and this vision at the very bottom of the readme - forewarning: its a lot. 

> # and I use it how? 

That depends...

<img src=src/visualization/assets/who_ru.jpg alt="who_ru.jpg">

Are you...
### Blue team - a firewall
  A basic sample is provided, `FOWLWALL.JSON`, that demonstrates the main 3 functions (bannable conditions, knock->unlock conditions, respond conditions AND actions, and BONUS: a simple notification service)

  More info on the rules of this file/the-tokenizer as they are written.

or, are you...
### Red team - a passive recon tool
  Running a captured `pcap` through `FoWL.py` analysis tools and viewing them in the visualizer is one approach to get a "big picture" of the network, and fairly easily discern what devices are in-view.

Really, all teams should have awareness of all tools - to prepare for the opposition - "Know your enemy."

</details>

<details>
<summary> 

# PRERELEASE TODO:
</summary>

 - Clean up the built-in `scapy_handler`s
   - Parallels: 
     - Add an engine method of adding/removing handlers with "some given scapy conditions to be satisfied" (or a default/fallback with no conditions being supplied)
     - Add calls of aforementioned callback to FoWLWall-tokenizer rules+their action handlers
 - Finish stateful connection tracking
 - Knocker daemon
 - Fail2Ban-esque
 - "Mirror mode" - described in purp team highlights
 - Add a license
</details>

<!-- # Highlights:

- Blue Team endeavors:
    - configurable to kin of a very-confusing firewall, or "hollow" honeypot (falsify banners and/or limited services - purely blue team)
      - Fun fact: This idea was actually my motiviation for the project - a Mirai botnet derivative kept throwing random router exploits at my servers
- Purple Team:
    - devious redirection to actual honeypots, or 
    - outright redirection of exploit attempts 
        - I'm calling this red-team-by-proxy --
            - redirect your own ports to your "targets" (perhaps... the origin?) - make the "enemy" work for you, or against themselves
              - A play on the classic: "You can't hack me, here's my IP: 127.0.0.1"
            - detect and steal their (basic) shells
- Red Team:
    - MITM/Service/Route Poisoning (expanded in TODO) -->

<details>
<summary> 

# Working:
</summary>

- Stateless emulation of basic HTTP/1.1 server
- Offline reanalysis of PCAPs
- Packet capture/analysis pipelines
- visualizer
  - MAC->MAC graph
    - MAC broadcasts are not considered in this graph
  - IP->IP graph
    - Using the information configured for the host network interface, subdivide traffic into LAN segments
      - I hope to change/add subdivisions per detected network ranges
        - E.G. DHCP Response contains this, as do broadcasts
- logging 
  - I personally prefer more to less (details), I will likely reduce the log verbosity, to at least reduce ->$file operations.
  - I also prefer file based division, but don't like the inconvenience of splicing a timeline/trace, so there is a "merged output streams" to "log/latest.log"

</details>

<details>
<summary> 

# Big TODO:
</summary>

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
    - Recon:
        - Hardware (OUI) and OS (other passive traffic - bonjour, NBNS, SSDP, MDNS etc)
    - honeypot submodules/install/setup?
    - Detect basic successful exploits (Port redirection/timing)
        - Detect/prevent meterpreter/nc callbacks?
            - This may be ambitious - would require egghunt on potentially time sensitive data
                - is there a way to "hold" a stateful connection for analysis with heartbeats?
                - prone to middleman DOS, IE: Send massive payloads that trigger the egghunts to max out firewall resources
- Red Team:
    - MITM implementations (IPv4/6)
    - Poisoning
        - MDNS/NBNS/DNS 
        - Route poisoning (Ether/ICMP)
        - MAC flood
        - BEEF hook injection for insecure requests
    - TLS Downgrade attempts? (may not be relevant with TLS1.3 protections by the time it's implemeneted)
    - Shell theft - extend function of purple team exploit success detection
</details>

# Honerable mentions:
- People: My Friends, Family, and everyone in between, for taking __and__ faking interest, and letting me work peacefully.
  - ZK
  - NC
  - MB
  - SL (both of you)
  - TF
  - (If any of you want your full-name/an-alias here, say the word)
- Projects:
  - [Kismet Wireless](https://www.kismetwireless.net/) ([repo-"mirror"](https://github.com/kismetwireless/kismet/))
    - Kismet is *fantastic*, for passive detection of wireless devices - hands down, no contest, it is "the tool": but my biggest complaints(that don't apply to this one)
      - pertaining to plugins:
        - Lack of modularity/"complex"-requirements/compilation
        - Arbitrarily requires C++ whilst boasting the [Capture-Framework is pure-c](https://www.kismetwireless.net/docs/dev/capframework/#pure-c)
      - Lacking *accessible* MITM/Injection support, while requiring (or strongly pushing for, I have not tried W/O) access levels for it.
        - I did try a plugin for this (...once... I think...WellICan'tFindItNow!), and it simply did not work.
    - Having said that, they have me beat in: 
      - Speed: Their compiled code is *surely* faster (I'd love to benchmark)
        - Rewriting this codebase in a compiled language is a longterm dream
      - Protocol support: They're "streets ahead", or maybe I'm "streets behind"
      - Direct hardware support: "ditto protocol support"
      - User Interface 
        - Mine is an absolute joke by comparison... I asked myself two questions:
          - "What looks good and does well with decently sized datasets?"
          - What do I __*not have any experience*__ with?
            - The answer: Dash, but you probably wouldn't know it from the UI or "ahem" the way I bullied modern browser functions for it to work...
        - Their's is killer, and easily extensible (once you have a plugin...)
  - [PfSense](https://github.com/pfsense/pfsense) ([repo](https://github.com/pfsense/pfsense))
    - PfSense is an open-source project, mainly designed for their hardware, a product of NetGate. It's hard to *succintly* describe it... router/firewall/switch - given the right hardware, its all in one and more.
      - Its probably best to check out their [docs](https://docs.netgate.com/pfsense/en/latest/preface/index.html).

<details>
<summary> 

# More on why: recap of my journal 

</summary>


So, some of the code making up this project was written April 18th, 2024. I was deep-diving into scapy layers, for no other reason than network protocols have always been 'my thing', and scapy is a great framework which I was not very familiar with. 

`I am a hacker, enter my world...`

A few weeks later, (est. 8PM, April 26th, 2024):

I exposed a few ports to my PC, ones commonly used for web development, e.g. 8883, 8080, etc, to the internet. The simple/boring traffic of network broadcasts, casual browsing, etc, I was just hoping for someone/thing new/interesting to pop up while I messed around with various layers/socket types etc.

> Going on a deep

<details>
    <summary> tangent. </summary>

So it/they did. (est 10PM, same day)

A mirai variant was knocking, and (presumably for speed/mass-effectiveness) it didn't bother waiting for either notification of the port being blocked (`tcp->th_flags & TH_SYN`), or server acknowledgement (`tcp->th_flags & TH_RST`) - it just pushed the exploit request right in after that SYN... Had it waited, it would have received neither anyway - a `DROP` rule was in place.


I dug deeply into that router exploit attempt - identifying it as [CVE-2023-1389](https://nvd.nist.gov/vuln/detail/CVE-2023-1389), quickly discovered, and downloaded what turned out to be the initial bash script (first noted publically 2 weeks prior) to detect the architecture, and grab the architecture appropriate [stage 2 dropper](https://www.virustotal.com/gui/file/74c1e2cc3733bc1b5927f3b5497daab5a52fc4af3ca59b008a55dcf4ca520544/detection) 

I do not seem to have the raw binaries any more (I hold hope of finding them), but I did still have the sha256 hashes for them. 

If you have these, hand'em over! My archives are incomplete!
Those 4 architecture's are yet-to-be-uploaded to VirusTotal as well.

(No uploads prior to me for these hashes - so I presume no one dug this far.)
<details>
    <summary> Hashes </summary>

stage 1 - loader

    a050602514fed406372d2a22ca15f07fcade5451cfcb87c1177623b9617df07a  mirai-dropper-host-103.163.214./shk
stage 2 (not uploaded: mips, mpsl, ppc, sh4)

    f8e8bb834d8af28cf7da8792c1613b0d09b62ee97308c98741c4b342036f9976  mirai-dropper-host-103.163.214./arc
    1b74b0ba5bf75fff38f46125a57eafb210f65d687da19b010dd7c3c332ece906  mirai-dropper-host-103.163.214./arm
    804567fd527dd1cbb8868fa0d6696546f87848fd16344d606482f85ef53ed8df  mirai-dropper-host-103.163.214./arm5
    46d265fdf131c59d03a695132589e1c34a99fbafc2b5403910c975b4be6e3a7a  mirai-dropper-host-103.163.214./mips
    0dd2b4446b32981fc10e51ba59de28ae1c3c88628cd3bb83b401c402afb33d05  mirai-dropper-host-103.163.214./mpsl
    999314a0ab3c17d6b818f04aa5fac291e8d41489e9fa11d259dee5490bbf6ce7  mirai-dropper-host-103.163.214./ppc
    e1deb88da3dc9bd903dbf2e77dcb7f867fb816c03379024013cc0ca5f1a7ba9c  mirai-dropper-host-103.163.214./sh4
    74c1e2cc3733bc1b5927f3b5497daab5a52fc4af3ca59b008a55dcf4ca520544  mirai-dropper-host-103.163.214./x86
    44734078fe15b68e680b31852fccd127515a99e5019ada15c54d448605dab787  mirai-dropper-host-103.163.214./arm6
    44734078fe15b68e680b31852fccd127515a99e5019ada15c54d448605dab787  mirai-dropper-host-103.163.214./arm7
</details>


I lack details in my notes beyond this, but seem have been confident from what I had unpacked/reversed that I found the C2, and a front-end/admin-portal public: 45.128_232.208:33335 (no longer operating.)

At that point, it was April 27th, 4AM rolled around, and my fun was over with, but I did not forget this excercise as a month passed me by.

My take away thoughts:

- "If I were running these botnets, I would not be so 'inellegant' as to spam the whole internet with my lame publicly identified CVEs - at least scan first"

![FreakingIdiots!](src/visualization/assets/NapoleonDyna.jpg)
- "Wait, so what if I did scan first? Who's to say that *what I see*, **is** what it appears, even if every probe/response and byte is lining up 1:1 (as far as **my checks would go**) with what the vulnerable device would display?"
  - *Queue first bullet* of "Working" header, with that PoC written:
  - *various sub-thoughts dumped into the TODO section*
</details>

> TLDR: Mirai botnet hit a port with a weird/relatively new exploit, I fixated on it for a night, though the night turned into one of binary dissection, I returned to scapy, with a simple goal: I'm going to make a little responder app to emulate various services.

Had it stayed so simple, my summer would have been much more lively, as my friends would attest.

</description>

### End Game
A hard question for my breed- we see a gap in tooling, we fill it, some times (most times in my case) with paper clips, tape, and glue, among existing tooling.

Once that's together though, it becomes "how can I make this less-shitty, and/or more-novel?" which I had endless answers to. 

This time though, I found a simple concrete: 
- Fail2Ban + knocker + configuration parser
  - These 3 are simple enough, and provide real value-add over the former 2 as individual tools.

Though, I would love for it to be a 1-stop-shop for any team (Red, Blue, the general network operator, etc), the **Big TODO:** has simply gotten too big, and getting to this point has taken long enough(collectively a few hundred hours) that I don't see that happening (this year.)



 FoWL © 2024 by Brandon Fanti is licensed under CC BY-NC-SA 4.0 




