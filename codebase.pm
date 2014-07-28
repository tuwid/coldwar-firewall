package coldwar;


use strict;
use warnings;
#use diagnostics;
use Fcntl qw( :flock );
use Cwd 'abs_path';
use Config;
use Sys::Syslog;

### enable this to put stuff in the background
#Proc::Daemon::Init;


# WIZARDI BREEEE
#use JSON -support_by_pp;
# TO BE FIXED:
# /getafter - parameter last_date 
# - the refreshing funx, and the global syncronization in real-time ( needs the api )
# - the broadcast globaly funx ( needs the api ) 
# - if the program is killed sometimes the instances stay open O_O'
# 	- kjo gjeja me lart duhet zgjidh bre
# - make it run as a service 
# -       make it look like all the ports are open ( implementohet ne nivel sistemi me iptables ) 
# - 
# -      jsonit problem, needs structure validation ( ) 
#### Server responded with status  200 OK 
#### malformed JSON string, neither array, object, number, string or atom, at character offset 0 (before "Po merremi, flasim p...") at codebase.pm line 395
# - define different syslog levels / INFO / ERROR / WARN  ( do we really need this ??)
# - the insertion on the main API might be better if done with a queue not real time 
# - real sshd honeypot

### 
## TO DO
# pcap files 
# web 


# here be dragons ---> 

#use Data::Dumper;
my @deathlist = ();
my $mode = lc(read_config("COLDWAR_MODE"));

my $bind_interface = read_config("BIND_INTERFACE");
my $bind_ip = read_config("BIND_IP");

my $source_port = 0;

# if the debug flag is on, we wont fill up the IPtables 
# or not
# change this to 0 to actually work

my $debug = 1;

my $lockfile = "/tmp/coldwar.lock";
my $flock;

sub lock{
		my $action = shift;
		if($action eq "aquire"){
				print_out("Checking for lock file\n","w");
				if ( -f $lockfile ) {
					print STDERR "Lockfile present: $lockfile, try restarting the service\n";
						die("Lockfile");
					#exit(0);
				}
			    open( $flock, ">$lockfile" ) or do {
					print STDERR "Could not create lock file: $!\n";
				print_out( "Could not create lock file: $!\n","k" );
				die( "Could not create lock file: $!\n" );
			    };

			    eval {
					unless ( flock($flock, LOCK_EX | LOCK_NB) ) {
					    print_out( "Could not create lock file: $!\n","k" );
					    die( "Could not create lock file: $!\n" );
					}
				};
				    if ( $@ ) {
					print STDERR $@."\n";
				        exit(1);
				    }
				    else{
				    	print $flock $$;
				    }
		}
		elsif($action eq "remove"){
			   eval{
			    	close( $flock );
			    };
			    print_out("Removing lockfile \t".$lockfile."\n","k");
			    unlink("$lockfile");
		}
}

sub check_libs{
	my $lib_error = 0;
	my @libs = ("Net::Pcap",
			"NetPacket::Ethernet",
			"NetPacket::IP",
			"NetPacket::TCP",
			"LWP::UserAgent",
			"DBD::SQLite",
			"JSON qw( decode_json )",
			"Time::HiRes",
			"Proc::Daemon",
			"Net::Server::PreFork"
			);

	print_out("Loading perl libraries \n","b");
	foreach(@libs){
		if (load_lib("$_;")) {
				print_out("$_ - \t\t  [OK]\n","g");
			} 
			else {
			  print_out("Error loading $_ \n","k");
			  $lib_error = 1;
			}
	}
	
	if($lib_error == 1){
		die "[!] Check perl depencies ! \n";
	};
}

sub load_lib{
	  my $mod = shift;

	  eval("use $mod");

	  if ($@) {
	    #print "\$@ = $@\n";
	    return(0);
	  }
	  else {
	    return(1);
	  }
}

sub honey_start{

		my @ports = split(',',read_config("PORTS"));
		if(scalar(@ports) eq 0){
		    print_out("No ports defined, we wont listen at any port.. booo \n","k");
		    exit(1);
		}

		my $test_ports = 1;

		foreach my $port (@ports){
			 if(check_openport($port)){

			 }
			 else{
			 	print " $port already taken CTRL+C to stop\n";
			 	exit(1);
			 }
		}	

		## we will disable this for the moment
		shift(@ports);
		my $obj = Net::Server::PreFork->run(        
		        host => read_config("BIND_IP"),
				port => [@ports],
				#log_level => 4,
		        ipv => [4]
				#reverse_lookups => 0
			) or die "[FAILED for some unkown reason]\n";
}

sub init{

	#print "Setting lock\n";
	lock("acquire");
	check_files();
	check_ifroot();
	check_libs();
		if(check_iptables()){
			# chain exists 
		}
		else{
			# creating chain
			create_iptables();
		}
	ban_list();

	print_out("Setting mode in $mode \n","g");

#	my $honey_pid = fork();
#	if($honey_pid == 0){
#		print_out("Opening ports for monitoring\n","g");
#		honey_start();
#	}

	# jane te gjitha checket ktu ? (per tu ri-pa)
#	if($debug){
#		print "Pors opened, moving along \n";
#	}


	engine("start");
	
	#engine_start("eth0","192.168.2.146");
	#engine_start("wlan0","10.92.59.89");
}

sub check_openport{
	my $port = shift;
		# which netstat ?
	my $out = `netstat -an | grep '\*' | grep ":$port " | awk -F" " '{print \$4 }'`;
	if($out ne ""){
		print_out("Port $port is currently already open , remove from the config OR stop the program using it\n","k");
		return 0;
	}
	else{
		print_out("Port $port OK\n","g");
		return 1;
	}
}

sub read_config{
		my $var_d = shift;
		open(FILE,"./config");# or print "[Config Error] : Could not find file /etc/coldwar/config ! / Access Denied\n";
		#	exit(1);
		my @config = <FILE>;
		#	print join('\t',@config);
		foreach(@config){
			if($_ =~ /^$var_d=(.*)/g){
				return "$1";
			}
		}
		print_out("[Config error!]\n","k");
		close(FILE);
		exit(1);
		# merr si agument variablin qe na duhet
		# parse data
		# 
}

sub compile_ipfilter{

	# duhet nej regex ktu me filtru budalliqet potenciale qe mund ti shkojne ne mendje perdoruesit
	my @ports = split(',',read_config("PORTS"));
	my $tcpfilter;
	if($ports[0] eq "ALL"){
			if($ports[1] =~ /\!/){
				$ports[1] =~ s/!//;
				$tcpfilter = "(tcp dst port not $ports[1] )";
			}
			else{
				$tcpfilter = "(tcp dst port $ports[1] )";				
			}

			for(my $i =2; $i< scalar(@ports); $i++){
				if($ports[$i] =~ /\!/){
					$ports[$i] =~ s/\!//;
				$tcpfilter .= " && (tcp dst port not $ports[$i] )";
				}
				else{
					$tcpfilter .= " && (tcp dst port $ports[$i] )";
				}
			}
	}
	elsif($ports[0] eq "SPEC"){
			$tcpfilter = "(tcp dst port $ports[1] )";
		for(my $i =2; $i< scalar(@ports); $i++){
				$tcpfilter .= " || (tcp dst port $ports[$i] )";
			}
	}
	else {
		die "Error in the port config\n";
		# error
		#$tcpfilter = "(tcp dst port $ports[0] )";
	}

	return $tcpfilter;
}

sub block_ip{
	my $banned_ip = shift;	
	push(@deathlist,$banned_ip);
	if($mode eq "proactive"){
		system('iptables -I COLDWAR 1 -s '.$banned_ip.' -j DROP');		
	}
	else{
		print_out("System not in PROACTIVE mode, will skip automatic ban\n","k")
	}
}

sub print_out{
	my ($message,$ng,$log_level) = @_;
	my $ngjyra;

	# to be fixed later
		# if($log_level eq "info"){

		# }
		# elsif($log_level eq "warning"){

		# }
		# elsif($log_level eq "error"){

		# }
		# else{
		# 	#(!defined($log_level)){
		# 	$log_level = 'info';
		# }


	#		if($debug) {
				#cool
	#			print "Got color ".$ng."\n"; 
	#		}

		if(read_config("USE_SYSLOG") eq "YES"){
			if(read_config("SYSLOG_TYPE") eq "LOCAL"){
				openlog("COLDWAR", 'cons,pid', 'user');
				chomp($message);
				syslog('info', '%s', "$message");
				closelog();
			}
			else{

			}
		}


		if($ng eq "k" || $ng eq "r"){
			$ngjyra =  "\033[31m"; # kuqe
			if($debug){
	#			print "Color set to red \n";
			}
		}
		elsif($ng eq "g"){
			$ngjyra = "\033[32m"; # jeshile
			if($debug){
	#			print "Color set to green \n";
			}
		}
		elsif($ng eq "b"){
			$ngjyra = "\033[0m"; # bardh
			if($debug){
	#			print "Color set to white \n";
			}
		}
		elsif($ng eq "o"){
			$ngjyra = "\033[33m"; # si e verdh
			if($debug){
	#			print "Color set to yellow \n";
			}
		}
		else{
			$ngjyra =  "\033[0m";	
			if($debug){
	#			print "Color fallback to white \n";
			}
		}

		print "$ngjyra $message\n\033[0m";
}

sub ban_list{
	my $url = read_config('URL_GET');
	my $ua = LWP::UserAgent->new(Timeout => 10); 
	my @gips;
	my @lips;
	my $decoded_json;
	my $dbh = db_connect();
	my $ips = "";
	my $stmt;
	my $sth;
	my $rv;
	print_out("Getting local IPs\n","g");

		$stmt = qq(SELECT ip FROM data);
		$sth = $dbh->prepare( $stmt );
		$rv = $sth->execute() or die $DBI::errstr;
		if($rv < 0){
			print_out("$DBI::errstr","k");
			exit(1);
		} 
		else{
			while(my @row = $sth->fetchrow_array()) {
			      push(@lips,$row[0]);
			      print $row[0]."\n";
				}
			}

	$dbh->disconnect();
	print_out("Got ".scalar(@lips)." entries from local databasse\n","g");
		print_out("Blocking traffic from local database\n Please be patient as this might take a while","b");
		foreach(@lips){
			if(validate_ip($_)){
				#print_out("Blocking traffic from :\t".$_."\n","g");
				if (!$debug){
					block_ip($_);
				}
			}
		}

	chomp($url);
	$url .= '';
	print_out("URL\t".$url."\n","b");	
		my $response = $ua->get($url);

			## we need some structure validation here
	if ($response->is_success) {
		$ips = $response->decoded_content or die "weird stuff on the web request\n";
		print $ips;
		#exit(1);
			print_out("Server responded with status  ".$response->status_line." \n","g");
		    eval {
		    	$decoded_json = decode_json( $ips );
				#print Dumper $decoded_json;
				#exit(1);
			};
			    if ( $@ ) {
			    	print_out("JSON Parsing issue, moving along \n","k");
			    }

			#print Dumper $decoded_json;
			while (my ($key, $value) = each(%{$decoded_json})){
	     		foreach(@{$value}){
	     			push(@gips,"$_");
	     		}
			}
	    
		print_out("Got ".scalar(@gips)."\n","g");
			#exit(1);
	}
	else{
		print_out("Could not contact main server, getting local IPs only\n","k");
		#die $response->status_line;
	}
	my %list;
	my %local_ips = map{$_=>1} @lips;
	my @deathlist = (@lips,@gips);
	@deathlist = grep !$list{$_}++, @deathlist;
	my @diff =grep(!defined $local_ips{$_}, @deathlist);	
	
		# kjo sduhet bo kshu, lista qe morem nga db-ja nuk duhet 
		# te shtohet ne db 

		print_out("Blocking traffic from remote database\n","b");
		foreach(@diff){
			if(validate_ip($_)){
				#print_out("Blocking traffic from :\t".$_."\n","g");
				add_to_list($_);
				block_ip($_);
			}
		}
}

sub sinjalizo_qendren{
	# request te cevri
	# this must be passed on a queue to avoid delay
	#return 1;
	# uncoment this for multithreading singaling
	my $pid = fork;
    return if $pid;
	print_out("Duke sinjalizuar qendren\n","g");	
	my ($event,$ip,$local_port,$remote_port) = @_;
	#my $url = read_config("URL").'/index.php';
	my $url = read_config("URL");
	chomp($url);
	my $ua = LWP::UserAgent->new();
	my $response = $ua->post( $url, { 'ip' => $ip, 'source_port' => $remote_port , 'target_port' => $local_port, 'attacker_time' => "2013-01-01 00:01" });
		#$url .= '/index.php?action=put&event='.$event.'&ip='.$ip.'&port='.$local_port."&remote_port=".$remote_port;
		#print $url."\n";
		# kontroll ktu per // dyshe
		# my $response = $ua->post($url,  [ 'action' => "put", 'ip' => $ip, 'port' => $port ]); 
		#my $response = $ua->get($url);
		print_out("U sinjalizua qendra dhe u mor ".$response->status_line,"g");
		return $response->status_line."\n";	
}

sub check_files{
	my $error = 0;
	my @files = (
	"./config",
	"./codebase.pm",
	"./bandb.sqlite3",
	"./engine.pl"
	#	"/var/opt/coldwar/engine_stop.pl",
	#	"/var/opt/coldwar/install.pl",
	#	"/var/opt/coldwar/uninstall.pl"
	);

	foreach(@files){
		if (-e "$_") {
	    	print_out("$_ OK\n","g");
		}
		else {
			print_out("Could not access file $_\n","k");
			$error = 1;
		}
	}
	if($error eq "1"){
		print_out("Problem accessing one of the files... exiting\n","k");
		exit(1);
	}
}

sub validate_ip{
	my $ip = shift;

	### well this seems to get the job done so..
	if($ip=~/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/ &&(($1<=255  && $2<=255 && $3<=255  &&$4<=255 ))){
    	return 1;
 	}
	else{
		return 0;
		#log("IP gabim $ip ");
 	}
}

sub check_ifroot{
	if ( $< != 0 ) {
		print_out("Root check \t [FAILED] \n \t This script must be run as root\n","k"); 
		exit(0);
	}
	else{
		print_out("Root check \t\t [OK] \n","g");
	}
}

sub check_iptables{
	#	my $tf = `iptables -L COLDWAR -n`;
	my @out = `iptables -L -n`;
	foreach(@out){
		if($_ =~ m/^Chain COLDWAR/){
			print_out("Ekziston chaini COLDWAR.. skipping... \n","g");
			return 1;
		}
	}
	return 0;
}

sub create_iptables{
	# simple right ? xD 
	system('iptables -N COLDWAR');
	system('iptables -F COLDWAR');
	system('iptables -I INPUT -j COLDWAR');
}

sub get_now{
	my $local_time;
	my @timeD = localtime();  # 3 4 5
		$timeD[4]++; 
		$timeD[5] += 1900;
		$timeD[4] = (($timeD[4] < 10) ? "0".$timeD[4] : $timeD[4]); # nena ternarit jam :D
		$timeD[3] = (($timeD[3] < 10) ? "0".$timeD[3] : $timeD[3]);
		$timeD[2] = (($timeD[2] < 10) ? "0".$timeD[2] : $timeD[2]);
		$timeD[1] = (($timeD[1] < 10) ? "0".$timeD[1] : $timeD[1]);
		$timeD[0] = (($timeD[0] < 10) ? "0".$timeD[0] : $timeD[0]);	
	$local_time = "$timeD[5]-$timeD[4]-$timeD[3] $timeD[2]:$timeD[1]:$timeD[0]";
	return $local_time;
}

sub engine{
	my $action = shift;

			if($action eq "start"){
					# duhet 1 kontroll

				if($bind_interface eq "" or $bind_ip eq ""){
					print_out("No IP/interface specified, edit config file please\n","k");
					exit(3);
				}

				print_out("Binding to interface \t".$bind_interface."\n","g");
				print_out("Binding to ip \t".$bind_ip."\n","g");

				my $dev = $bind_interface;	# ndefaqja ku do bejm bind
				my $port_filters = shift;
				my $total_filter;

				# verifikim a eshte IP-ja e vlefshme ktu
				# verifikim a jan portat ne rregull ktu
				# split portave sipas "," dhe percdo port shto "tcp port $port"
					
				if (!defined($dev)){	# bejm me turnar me vone ket
						die "Snuk nderfaqja! \n";
					}

				if (!defined($bind_ip)){
					die "Snuk IP-ja";
				}
				# ca portash skanohen me shume ? 
				#	$port_filters = '(tcp dst portrange 21-30000)';


				$total_filter = '(dst '.$bind_ip.') && ('.compile_ipfilter().")";
				print_out("Using filter:\t ".$total_filter."\n","g");
				print_out("Waiting for the droids we're looking for...\n","g");
				my $err;

				unless (defined $dev) {
				    $dev = Net::Pcap::lookupdev(\$err);
				    if (defined $err) {
					        print_out('Unable to determine network device for monitoring - '.$err,"k");       
				        die 'Unable to determine network device for monitoring - ', $err;
				    }
				}

				my ($address, $netmask);
				if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
				    die 'Unable to look up device information for ', $dev, ' - ', $err;
				}
				#   Create packet capture object on device

				my $object;
				$object = Net::Pcap::open_live($dev, 1500, 0, 0, \$err);
				unless (defined $object) {
				    die 'Unable to create packet capture on device ', $dev, ' - ', $err;
				}

				my $filter;
				#    '(dst 127.0.0.1) && (tcp[13] & 2 != 0)', # ktu
				Net::Pcap::compile($object,\$filter,$total_filter,0,$netmask ) && die 'Unable to compile packet capture filter';
				Net::Pcap::setfilter($object, $filter) && die 'Unable to set packet capture filter';

				#   Set callback function and initiate packet capture loop
				Net::Pcap::loop($object, -1, \&syn_packets, '') || die 'Unable to perform packet capture';
				Net::Pcap::close($object);
	}
	elsif($action eq "stop"){
				# delete iptables chain
					print_out("Deleting IPTABLES chain COLDWAR\n","b");
					system("iptables-save | grep -v COLDWAR | iptables-restore");	
					# stop teh process
					eval{
						if(-f $lockfile ){
							print_out("PID file found \n","b");
							open FILE,$lockfile;
							my @pid = <FILE>;
							close(FILE);
							#kill 'KILL', $pid[0]; 		
							kill 'SIGINT', $pid[0]; 		
						}
						else{
							print_out("PID file not present.. \n","b");
						}

					};
					# delete lock
					lock("remove");
					# exit
					#exit(1);
	}
	elsif($action eq "status"){
			my @pid = 0;
			# check iptables chain
				check_iptables();

			# check lockfile
				print_out("Checking for lock file\n","g");
				if(-f $lockfile ) {
					print_out("Lockfile present: $lockfile\n, try restarting the service","g");
					open FILE, $lockfile;
					@pid = <FILE>;
					close(FILE);
					#my $exists = kill 0, $pid[0];
					my $exists = `ps -aef | grep "engine" | awk -F" " '{print \$2 }' | grep \`cat /tmp/coldwar.lock\``;
					 if($exists){
					 	print_out("Process is running with correct PID $exists\n","g");
					
					 }
					 else{
					 	print_out("Process not running\n","k");	
					 }
				}
				else{
					print_out("Lock file not present\n","k");
				}

				#exit(0);
			# check running file if its the same with the pid on the lockfile
			# prit se kjo ka icik pune
	}
}

sub syn_packets {
    my ($user_data, $header, $packet) = @_;

    #   Strip ethernet encapsulation of captured packet 
    my $ether_data = NetPacket::Ethernet::strip($packet);
	
    #   Decode contents of TCP/IP packet contained within 
    #   captured ethernet packet

    my $ip = NetPacket::IP->decode($ether_data);
    my $tcp = NetPacket::TCP->decode($ip->{'data'});
    my $source_ip = $ip->{'src_ip'};
    $source_port = $tcp->{'src_port'};
    my $dest_ip = $ip->{'dest_ip'};
    my $dest_port = $tcp->{'dest_port'};
    print $source_port."\n";

   print_out("CONNECTION DETECTED ".$ip->{'src_ip'}.":".$tcp->{'src_port'}." -> ".$ip->{'dest_ip'}.":".$tcp->{'dest_port'}."\n","k");
    #print $ether_data."\n";	# per me vone kjo me kap payloadin
    add_to_list($ip->{'src_ip'},$tcp->{'dest_port'});
    #print $ether_data."\n";
	
    #if(BROADCAST_ALARM)
	sinjalizo_qendren("SCAN",$source_ip,$dest_port,$source_port);
}

sub add_to_list{
	# nqs IP-ja eshte ne whitelist jemi tanet
	# nqs IP-ja eshte e re (nuk gjendet ne @deathlist)
	my $dbh = db_connect();
	my $hits = 0;
	# shtohet ne drop te IPtables dhe tek @deathlist
	my $b_ip = shift;
	my $l_port = shift || "0";
	my $loct = get_now();
	my @whitelist = get_whitelist();
	if ( grep( /^$b_ip$/, @whitelist ) ) {
		print "IP on the whitelist, cant argue with that\n";
	}
	elsif( grep( /^$b_ip$/, @deathlist ) ) {
		print_out("Already on the banlist!\t","o");
	}
	else{
		# duhet pa a eshte IP ne db
		# nqs seshte, shtojm,
		# nqs eshte rrisim hitsin me +1
		# nqs hitsi > 3 e fusim tek blocket e IPtablesave
		my $stmt = qq(Select hits from data WHERE ip = '$b_ip');
		my $sth = $dbh->prepare( $stmt );
		my $rv = $sth->execute() or die $DBI::errstr;
		if($rv < 0){
			print $DBI::errstr;
			exit(1);
		} 
		else{
			while(my @row = $sth->fetchrow_array()) {
			      $hits = $row[0];
				}
			#	print "Hists \t $hits \n";
				
			if($hits > 0){
				$hits++;
				$stmt = qq(UPDATE data set hits = '$hits' WHERE ip = '$b_ip');
				$sth = $dbh->prepare( $stmt );
				$rv = $sth->execute() or die $DBI::errstr;
			}
			else{
				$hits++;
				#print "trying to insert \n";
				$stmt = qq(INSERT INTO data (hits,active,ip,port,timestamp) VALUES ('$hits',1,'$b_ip','$l_port','$loct'));
				$sth = $dbh->prepare( $stmt );
				$rv = $sth->execute() or die $DBI::errstr;
			}				
		}

		if($hits >= 3){
			sinjalizo_qendren("BLOCKED",$b_ip,$l_port,$source_port);    
			block_ip("$b_ip");
		}
		#			block_ip("$b_ip");
		}
	$dbh->disconnect();
}

sub get_whitelist{
	my @whitelist = split(',',read_config("WHITELIST"));
		# duhen perkthy IP-te nga CIDR ne ip shqeto
}

sub delete_from_iptbl{
	my $ip = shift;
	my @blacked = ();
	my @out = `iptables -L COLDWAR -n --line-numbers | grep -v "target" | grep -v "Chain"`;
	#my @out = `iptables -L -n`;
	foreach(@out){

		### we should change the spaces here with \s+
		if($_ =~ m/^(\d+)(\s+)DROP(\s+)all  --  $ip /){
			push(@blacked ,$1);
			#print $1."\n";
		}
	}
		#exit(1);
		#print scalar(@blacked)." - \n";
	if(scalar(@blacked) > 0){
		for(my $i = scalar(@blacked)-1; $i >= 0;$i--){
			
			system("iptables -D gzimi $blacked[$i]");
			print "U fshi $blacked[$i]\n";
		}
	}
	delete_ip($ip);
}

sub delete_ip{

	my $ip = shift;
	my $dbh = db_connect();
	my $stmt = qq(UPDATE data set active = '0' WHERE ip = '$ip');
	my $rv = $dbh->do($stmt) or die $DBI::errstr;
		if($rv < 0){
			return $DBI::errstr;
		} 
		else {
			print "IP deleted successfully\n";
		}
	$dbh->disconnect();	
}

sub db_connect{
	#use DBD::SQLite;
	my $driver   = "SQLite";
	my $database = "./bandb.sqlite3";
	if (-e "$database") {
    # nuffing 
	}
	else {
		die "Could not access database file $database\n";
	}

	my $dsn = "DBI:$driver:dbname=$database";
	my $dbh = DBI->connect($dsn, "", "", { RaiseError => 1 }) or die $DBI::errstr;
	#print "U hap db\n";
	return $dbh;	
}


1
