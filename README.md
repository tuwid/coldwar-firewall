# ColdWar Project

The project is aimed at setting up a proactive defense from single to large infrastructures.
ColdWar use pcap libraries to get any type of low level connections so fragmentation wont work (sorry bad guys)

If you want to see whats going on in your network this project is a must, expecially for larger infrastructures
as you can set up multiple nodes and get real-time information and/or block the attackers on the other nodes

You can set the program either in MONITOR mode where it will just act as a honeypot 
OR

your can set it in PROACTIVE mode that will also block future connections from any malicious host that might attempt
to gather info / exploit / infect your server. 

It has syslog support, alerting support (it will send email alerts if configured )

The list of libraries used:
	"Net::Pcap" <br>
	"NetPacket::Ethernet",<br>
	"NetPacket::IP",<br>
	"NetPacket::TCP",<br>
	"LWP::UserAgent",<br>
	"DBD::SQLite",		<br>		 
	"Net::Server::PreFork"<br>
