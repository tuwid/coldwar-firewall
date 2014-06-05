#!/usr/bin/perl
use codebase;


# install/uninstall/ sync

my $version = "0.97";

if($ARGV[0] eq "start"){
	coldwar::print_out("\tColdWar v$version\n","g");
	coldwar::init();
}
elsif($ARGV[0] eq "stop"){
	coldwar::engine_stop();
}
elsif($ARGV[0] eq "restart"){
	coldwar::print_out("Stopping engine\n","g");
	coldwar::engine_stop();
	coldwar::print_out("Starting engine\n","g");
	coldwar::init();
}
elsif($ARGV[0] eq "status"){
	coldwar::engine_status();
}
elsif($ARGV[0] eq "install"){
	# eshte 1 her ?
	coldwar::print_out("Installing perl modules\n","g");

	if(-f "/etc/debian_version"){
		# debian based system
		system("apt-get -y install make"); # y u no complier ?
		system("apt-get -y install libnet-pcap-perl");
		system("apt-get -y install libwww-perl");
		system("apt-get -y install libdbd-sqlite3-perl");
		system("cpan install NetPacket::Ethernet");
		system("cpan install NetPacket::IP");
		system("cpan install NetPacket::TCP");
		system("cpan install LWP::UserAgent");
		system("cpan install Time::HiRes");
		system("cpan install DBD::SQLite");
		system("cpan install JSON");
		system("perl -MCPAN -e 'notest force install Net::Server::PreFork'");
		#system("cpan install Net::Pcap");
	}
	elsif(-f "/etc/redhat-release"){
		# rpm based system
			system("cpan NetPacket::Ethernet");
			system("cpan NetPacket::IP");
			system("cpan NetPacket::TCP");
			system("cpan Time::HiRes");
			system("cpan LWP::UserAgent");
			system("cpan DBD::SQLite");
			system("cpan JSON");
			system("perl -MCPAN -e 'notest force install Net::Server::PreFork'"); # ??
			#system("cpan Net::Server::PreFork");
			system("yum -y install perl-Net-Pcap");
			system("yum install libpcap");
			system("yum install libpcap-devel");

			#yum install libpcap-devel # might come in handy

			#system("cpan Net::Pcap");
			}
	else{
		print_out("As lame as it seems, we couldnt /are too lazy to detect your OS","g");
		print_out("try installing it by hand:\t libnet-pcap-perl","g");
	}
	
	coldwar::check_libs();
}
elsif($ARGV[0] eq "uninstall"){
	# why ?
}
elsif($ARGV[0] eq "removeip"){
	if(coldwar::validate_ip($ARGV[1])){
			coldwar::delete_from_iptbl($ARGV[1]);
	}
	else{
		print "Please insert a valid IP\n";
	}
}
elsif($ARGV[0] eq "help"){
	help();
}
elsif($ARGV[0] eq "check"){
	coldwar::print_out("\tColdWar v$version\n","g");
	print "Checking teh stuffz \n";
	coldwar::check_files();
	coldwar::check_ifroot();
	coldwar::check_libs();
	exit(1);
}
else{
	help();
}

sub help{
	coldwar::print_out("\tColdWar v$version\n","g");
	print "Usage:\n ";
	print "./engine.pl start|stop|status|install|uninstall|check\n";
	print " start|stop|restart \t they start|stop|restart the engine duuhh (stop also removes the lock file) \n";
	print " install|uninstall \t nothing new here \n";
	print " removeip IP \t remove ip from iptables/db \n";
	print " cleardb \t clears teh db \n";
	print " check \t check for all the neccessary stuff  \n";
	exit(1	);
}
