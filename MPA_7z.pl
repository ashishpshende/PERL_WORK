#!perl
#  
#  Author: Rajesh Nikam. Quick Heal Technologies Pvt. Ltd.
#    
#  Malware Processing Automation
#  Date Created: 02-March-2010
#  Last Updated: 20-March-2012
#
###########################################################################

use Digest::MD5;
use Digest::SHA qw(sha256);
use File::Copy;
use Cwd;
use File::Path;
use Encode;
use Term::ANSIColor qw(:constants);
use LWP::UserAgent;
require HTTP::Request;

#
# To install File::Copy::Recursive - run following command
# ppm install File::Copy::Recursive
#
use File::Copy::Recursive qw(fcopy rcopy dircopy fmove rmove dirmove);

use strict;
use warnings;

##################################################
#
# Global variables
#
#####

my( $APPNAME ) = "mpa.pl";

my $out_dir = "";
my $logs_dir = "";
my $reports_dir = "";
my $samples_dir = "";
my $extract2_dir = "";
my $tools_dir = "c:\\tools";
#my $tools_dir = "f:\\mpa";
my $debug_log = "";

my $now_string = "";
my $source = "";

my $SCANTYPE = "NORMAL";

my %QH_DETECTED;

my %MSAV_DETECTED;
my %MSAV_REPLACEMENT;
my %MSAV_CATEGORY;
my %MSAV_VIRUS;
my %MSAV_SKIP;

my %KAV_REPLACEMENT;
my %KAV_CATEGORY;
my %KAV_VIRUS;
my %KAV_SKIP;

my %SYMC_REPLACEMENT;
my %SYMC_CATEGORY;
my %SYMC_VIRUS;
my %SYMC_SKIP;

my %ESET_REPLACEMENT;
my %ESET_CATEGORY;
my %ESET_VIRUS;
my %ESET_SKIP;

my %BITDEF_REPLACEMENT;
my %BITDEF_CATEGORY;
my %BITDEF_VIRUS;
my %BITDEF_SKIP;

my %SOPHOS_REPLACEMENT;
my %SOPHOS_CATEGORY;
my %SOPHOS_VIRUS;
my %SOPHOS_SKIP;

my %PANDA_REPLACEMENT;
my %PANDA_CATEGORY;
my %PANDA_VIRUS;
my %PANDA_SKIP;

my %KAV_DETECTED;	
my %KAV_ARCHIVE;	
my %KAV_PACKED;

my %FILE_TYPE;
#my %PACKER_EXCLUSION;
my %SIGCHECK_DATA;

my $sample_server = "http://192.168.50.203/nviraddrec.php";

##################################################
#
# 				F U N C T I O N S
#
#####


sub die_handler 
{ # 1st argument is signal name
	my($sig) = @_;
	my $debug_str = "$sig Exiting !!!\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );
	exit(0);
}

$SIG{__DIE__} = \&die_handler;


sub GetFileCountEx( $ );

##################################################
#
# Quick Heal Scan
#
#####

sub QHScan( $ )
{
	my $src_dir = shift;		
	my $scan_log = "$logs_dir\\qh.log";			
		
	my $debug_str = "\n Running Quick Heal Scanner : $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );
	
	my $command = "$tools_dir\\ntvirus\\QH\\QHScan.exe $src_dir /REPORT=$scan_log";					
	my $output = qx( $command );													

	$debug_str = "\n Done";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );	
}


sub QHScanSelfCheck( $ )
{
	my $src_dir = shift;		
		
	my $debug_str = "\n Quick Heal Scanner Self Check: $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );
	
	my $command = "$tools_dir\\ntvirus\\QH\\QHScan.exe $src_dir";					
	my $output = qx( $command );													
	
	if ( $output =~ m/Infected\s:\s\(EICAR\sTest\sFile/ )
	{
		$debug_str = "\n Done.";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str );	

		return 1;	
	}

	$debug_str = "\n FAILED !!!\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );	
	
	return 0;
}


sub QHParseLog( )
{
	my $scan_log = "$logs_dir\\qh.log";	
		
	my $debug_str = "\n Running Quick Heal Scanner log parser : $scan_log ...";		
	print $debug_str;
	WriteToLog( $debug_log, "  $debug_str" );

	open( IN, "< $scan_log" ) or die "\n\n Quick Heal Scanner Error: $! $scan_log !!! \n";
	my @data1 = <IN>;
	close IN;
	
	my $data = join( "\n", @data1 );	
	#my @entries = split( /Scanning\s+:\s+/, $data );	
	my @entries = split( /\[Skipped\]\s+/, $data );	
	my $len =  @entries;
	$len = $len - 1;
	
	$debug_str = "\n Samples detected: " . $len;	
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

		
	$scan_log = "$logs_dir\\qh-parsed.csv";	
	open( OUT, "> $scan_log" ) or die "\n\n Error: $! $scan_log !!! \n\n";	
	foreach my $entry ( @entries )
	{
		my $filename = "";
		my $threatname = "";		
		if ( $entry =~ m/\s+:\s+(.*)\s+Infected\s:\s+\((.*)\)/ )
		{
			$filename = $1;
			$threatname = $2;
			
			# remove path inside archive 
			$filename =~  s/\/.*//;			
			print OUT "$filename, $threatname\n";	
		}
		
		if( $entry =~ m/\s+:\s+(.+)\s+Infected\(Generic\)\s:\s+\((.*)\)/ )
		{
			$filename = $1;
			$threatname = $2;
			
			# remove path inside archive 
			$filename =~  s/\/.*//;			
			print OUT "$filename, $threatname\n";	
			
			if( $filename =~ /([0-9A-F]{32})/i )
			{
				my $md5 = uc( $1 );
				$QH_DETECTED{ $md5 } = $threatname;
			}
		}
	}
	close OUT;

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );									
}


##################################################
#
# Kasparesky Scan
#
#####

sub LoadKAVThreatInfo(  )
{
	my $ini_file = "$tools_dir\\KAV_ThreatNames.ini";
	
	my $debug_str = "\n Loading Kaspersky Threat name information ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

	open( IN, "< $ini_file" ) or die "\n FATAL Error: Can not locate KAV_ThreatNames.ini file.\n $! ( $ini_file ) !!! \n";
	my @data1 = <IN>;
	close IN;
	
	my $data = join( "\n", @data1 );	
	my @sections = split( /\[Section:/, $data );		

	# load KAV Replacements	
	my @replacements= split( /\n/, $sections[1] );	
	foreach my $entry ( @replacements )
	{
		if ( $entry =~ m/(.*)=(.*)/ )
		{
			my $old = $1;
			my $rep = $2;
			$rep =~ s/\s+//;
			$KAV_REPLACEMENT{ $old } = $rep;				
		}
	}	
	
	# load KAV Backdoor
	@replacements= split( /\n/, $sections[2] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$KAV_CATEGORY{ $1 } = "Backdoor";				
		}
	}	

	# load KAV Trojan
	@replacements= split( /\n/, $sections[3] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$KAV_CATEGORY{ $1 } = "Trojan";				
		}
	}	

	# load KAV Worm
	@replacements= split( /\n/, $sections[4] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$KAV_CATEGORY{ $1 } = "Worm";				
		}
	}	

	# load KAV Adware
	@replacements= split( /\n/, $sections[5] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{			
			$KAV_CATEGORY{ $1 } = "Adware";				
		}
	}	

	# load KAV Virus
	@replacements= split( /\n/, $sections[6] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{			
			$KAV_VIRUS{ $1 } = "Virus";				
		}
	}	

	# load KAV Skip
	@replacements= split( /\n/, $sections[7] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{			
			$KAV_SKIP{ $1 } = "Skip";				
		}
	}	


#	my @xlats = keys ( %KAV_REPLACEMENT );	
#	for my $key ( @xlats )
#	{
#		my $rep = $KAV_REPLACEMENT{$key};
#		print "\n[$key], [$rep]";
#	}	
	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

}


sub GetKAV_xlat_Threatname( $ )
{
	my $threatname = shift;	
	my $xlat_name = $threatname;
	
	my @xlats = reverse sort ( keys ( %KAV_REPLACEMENT ) );	
	for my $key ( @xlats )
	{
		my $rep = $KAV_REPLACEMENT{ $key };
		if ( $xlat_name =~ s/$key/$rep/i )
		{
		}		
		#print "\n $key, $rep ==> $threatname, $xlat_name";
	}	
	
## This is causing issue with for-generic	
##	# remove variant name from end of threat name
##	my @arr = split( /\./, $xlat_name ) ;
##	my $len = @arr;
##	if( $len >= 3 )
##	{
##		if( $xlat_name =~ /(.+)\.([a-z]+)/ )	
##		{
##			$xlat_name = $1;
##		}
##	}
	
	return $xlat_name;
}


sub GetKAV_Category( $ )
{
	my $threatname = shift;
	
	# check SKIP names first 
	my @names = keys ( %KAV_SKIP );	
	for my $key ( @names )
	{
		if ( $threatname =~ /^$key/i )
		{			
			#print "$threatname, $key\n";
			return $KAV_SKIP{ $key };
		}		
	}
	
	# check if threat name appears in Virus category
	@names = keys ( %KAV_VIRUS );	
	for my $key ( @names )
	{
		if ( $threatname =~ /^$key/i )
		{			
			#print "$threatname, $key\n";
			return $KAV_VIRUS{ $key };
		}		
	}

	# check if Backdoor, Trojan, Worm or Adware category
	@names = keys ( %KAV_CATEGORY );	
	for my $key ( @names )
	{
		if ( $threatname =~ /^$key/i )
		{			
			#print "$threatname, $key\n";
			return $KAV_CATEGORY{ $key };
		}		
	}
	
	#print "$threatname, Unknown \n";
	return "Unknown";
}


sub KAVScan( $ )
{
	my $scan_log = "$logs_dir\\kav.log";			
	my $src_dir = shift;		
	
	my $debug_str = "\n Running KAV Scanner : $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

	my $dir = cwd;	
	chdir( "$tools_dir\\ntvirus\\KAV" );
	my $command = "$tools_dir\\ntvirus\\KAV\\kavconp.exe /y /! /l$scan_log /x /k /n $src_dir";					
	my $output = qx( $command );													
	chdir( $dir );
	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								
}


sub KAVScanSelfCheck( $ )
{
	my $src_dir = shift;		
	
	my $debug_str = "\n KAV Scanner Self Check: $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

	my $dir = cwd;	
	chdir( "$tools_dir\\ntvirus\\KAV" );
	my $command = "$tools_dir\\ntvirus\\KAV\\kavconp.exe /y /! /x /k /n $src_dir";					
	my $output = qx( $command );													
	chdir( $dir );
	
	if ( $output =~ m/detected\s+EICAR-Test-File/ )
	{
		$debug_str = "\n Done.";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str );								
		return 1;	
	}
	
	$debug_str = "\n FAILED !!!\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								
	return 0;
}


sub KAVParseLog( $ )
{	
	my $stats = shift;
	
	my $scan_log = "$logs_dir\\kav.log";	
	
	my $debug_str = "\n Running KAV Scanner log parser : $scan_log ...";		
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	open( IN, "< $scan_log" )  or die "\n\n FATAL Error: $! $scan_log !!! \n";
	my @data = <IN>;
	close IN;
		
	my %KAV_ARCHIVE_STAT;	
	my %KAV_PACKER_STAT;
	
	foreach my $line ( @data )	
	{			
	  #if ( $line =~ /([0-9A-F]{32})\s+Infected\s+([^\s]+)\s+/ )	  
	  if ( $line =~ /([0-9A-F]{32})\s+detected\s+([^\s]+)\s*/i )	  
	  { 	
	  	my $md5 = uc( $1 );
	  	my $threat_name = $2;	  	
	  	if (!exists( $KAV_DETECTED{ $md5 } ))
	  	{
	  		$KAV_DETECTED{ $md5 } = $threat_name;		
	  	}	  	
	  }
		
		# Archive	  
	  if ( $line =~ /([0-9A-F]{32})\s+archive\s+(.+)\s*/i )
	  { 	
	  	my $md5 = uc( $1 );
	  	my $threat_name = $2;
	  		  	
	  	if (!exists( $KAV_ARCHIVE{ $md5 } ))
	  	{
	  		$KAV_ARCHIVE{ $md5 } = $threat_name;		
	  	}	  	
	  }
	  
	  # Packed
	  if ( $line =~ /([0-9A-F]{32})\s+Packed\s+([^\s]+)\s+/i )
	  { 	
	  	my $md5 = uc( $1 );
	  	my $threat_name = $2;
	  	
	  	if (!exists( $KAV_PACKED{ $md5 } ))
	  	{	  		
	  		$KAV_PACKED{ $md5 } = $threat_name;		
	  	}	  	
	  }	  
	}
  
	my $kav_trojan_log = "$logs_dir\\trojan-kav.csv";
	my $kav_worm_log = "$logs_dir\\worm-kav.csv";
	my $kav_backdoor_log = "$logs_dir\\backdoor-kav.csv";
	my $kav_adware_log = "$logs_dir\\adware-kav.csv";
	my $kav_virus_log = "$logs_dir\\virus-kav.csv";
	my $kav_other_log = "$logs_dir\\other-kav.csv";
	#my $kav_exclu_packer_log = "$logs_dir\\kav_packer-exclusion.csv";
	
	
  # Save logs to files
	open( OUT_TROJAN, "> $kav_trojan_log" ) or die "$! $kav_trojan_log";	
	open( OUT_WORM, "> $kav_worm_log" ) or die "$! $kav_worm_log";		
	open( OUT_BACKDOOR, "> $kav_backdoor_log" ) or die "$! $kav_backdoor_log";	
	open( OUT_ADWARE, "> $kav_adware_log" ) or die "$! $kav_adware_log";		
	open( OUT_VIRUS, "> $kav_virus_log" ) or die "$! $kav_virus_log";	
	open( OUT_OTHER, "> $kav_other_log" ) or die "$! $kav_other_log";	
	#open( OUT_EX_PACKER, "> $kav_exclu_packer_log" ) or die "$! $kav_exclu_packer_log";	
		
	my @keys = keys ( %KAV_DETECTED );	
	for my $key ( @keys )
	{
		my $threatname = $KAV_DETECTED{ $key };
		my $xlat_name = GetKAV_xlat_Threatname( $threatname );		
		my $category = GetKAV_Category ( $xlat_name );
		
		#print "$xlat_name, $category\n";
				
		$key =~ s/\"//g;
		#$key = "\"$key\"";
		
		# if file is packed with Packer from exclusion list		
		my $packer = ""; 
		if ( exists $KAV_PACKED { $key } )
		{
			$packer = $KAV_PACKED { $key };
			my $makedst_dir = "$out_dir\\packers\\$packer";
			mkpath(	$makedst_dir );
			my $src_file = "$samples_dir\\$key";
			copy($src_file, $makedst_dir);
		
			#if ( exists ( $PACKER_EXCLUSION{ $packer } ) )
			#{
			#	print OUT_EX_PACKER "$key, $threatname, $xlat_name, $packer\n";
			#}
		}
		
		# put into appropriate category
		if ( $category =~ m/^Trojan/i )
		{
			print OUT_TROJAN "$key, $threatname, $xlat_name\n";		
		}				
		elsif ( $category =~ m/^Worm/i )
		{
			print OUT_WORM "$key, $threatname, $xlat_name\n";		
		}				
		elsif ( $category =~ m/^Backdoor/i )
		{
			print OUT_BACKDOOR "$key, $threatname, $xlat_name\n";		
		}				
		elsif ( $category =~ m/^Adware/i )
		{
			print OUT_ADWARE "$key, $threatname, $xlat_name\n";		
		}				
		elsif ( $category =~ m/^Virus/i )
		{
			print OUT_VIRUS "$key, $threatname, $xlat_name\n";		
		}				
		else
		{
			print OUT_OTHER "$key, $threatname, $xlat_name\n";		
		}			
	}
	
	close OUT_TROJAN;
	close OUT_WORM;
	close OUT_BACKDOOR;
	close OUT_VIRUS;
	close OUT_OTHER;
	#close OUT_EX_PACKER;

	my $archive_log = "$logs_dir\\kav-archive.csv";
	my $packer_log = "$logs_dir\\kav-packer.csv";

	open( OUT, "> $archive_log" ) or die "$! $archive_log";		
	my @names = keys ( %KAV_ARCHIVE );	
	for my $key ( @names )
	{
		my $t = $KAV_ARCHIVE{ $key };
		$key =~ s/\"//g;
		print OUT "$key, $t\n";	
		
		# Check if installer
		my $type = "";
		if ( exists ( $FILE_TYPE{ $key } ))
		{
			$type = "$FILE_TYPE{$key}";
			$type =~ s/^PE-.*/Installer/i;
			if ( $type =~ s/(.*)-.*//i )
			{
				$type = $1;
			}
			
			$t = "$type, $t";
		}
		
		if ( exists ( $KAV_ARCHIVE_STAT{ $t } ))
		{
			my $t1 = $KAV_ARCHIVE_STAT{ $t };
			$t1 = $t1 + 1;
			$KAV_ARCHIVE_STAT{ $t } = $t1;
		}
		else
		{
			$KAV_ARCHIVE_STAT{ $t } = 1;
		}
	}
	close OUT;

	open( OUT, "> $packer_log" ) or die "$! $packer_log";				
	@names = keys ( %KAV_PACKED );	
	for my $key ( @names )
	{
		my $t = $KAV_PACKED{ $key };
		$key =~ s/\"//g;
		print OUT "$key, $t\n";	
		if ( exists ( $KAV_PACKER_STAT{ $t } ))
		{
			my $t1 = $KAV_PACKER_STAT{ $t };
			$t1 = $t1 + 1;
			$KAV_PACKER_STAT{ $t } = $t1;
		}
		else
		{
			$KAV_PACKER_STAT{ $t } = 1;
		}		
	}
	close OUT;

	if ( $stats == 0 )
	{
		$debug_str = "\n Done.";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str );										
		return;
	}
	
	my $archive_stat = "$reports_dir\\ARCHIVE_$now_string.csv";
	my $packer_stat =  "$reports_dir\\PACKER_$now_string.csv";

	open( OUT, "> $archive_stat" ) or die "$! $archive_stat";	
	print OUT "Source, $source\n";		
	@names = sort keys ( %KAV_ARCHIVE_STAT );	
	for my $key ( @names )
	{
		my $t = $KAV_ARCHIVE_STAT{ $key };
		print OUT "$key, $t\n";
	}
	close OUT;

	open( OUT, "> $packer_stat" ) or die "$! $packer_stat";
	print OUT "Source, $source\n";
	@names = sort keys ( %KAV_PACKER_STAT );		
	for my $key ( @names )
	{
		my $t = $KAV_PACKER_STAT{ $key };		
		#if ( exists ( $PACKER_EXCLUSION{ $key } ) )
		#{			
		#	print OUT "$key, $t, Excluded\n";
		#}		
		#else
		#{
			print OUT "$key, $t\n";
		#}
	}
	close OUT;

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								
}


##################################################
#
# Microsoft Malware Protection Scan
#
#####

sub LoadMSAVThreatInfo(  )
{
	my $ini_file = "$tools_dir\\Microsoft_ThreatNames.ini";

	my $debug_str = "\n Loading Microsoft Threat name information ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

	open( IN, "< $ini_file" ) or die "\n FATAL Error: Can not locate Microsoft_ThreatNames.ini. \n $! $ini_file !!! \n";
	my @data1 = <IN>;
	close IN;
	
	my $data = join( "", @data1 );	
	my @sections = split( /\[Section:/, $data );			                          
		
	my @replacements= split( /\n/, $sections[1] );		
	foreach my $entry ( @replacements )
	{
		if ( $entry =~ m/(.*)=(.*)\s*/ )
		{
			my $old = $1;
			my $rep = $2;
			$rep =~ s/\s+//;
			$MSAV_REPLACEMENT{ $old } = $rep;				
		}
	}	

	# load MSAV Backdoor
	@replacements= split( /\n/, $sections[2] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$MSAV_CATEGORY{ $1 } = "Backdoor";				
		}
	}	

	# load MSAV Trojan
	@replacements= split( /\n/, $sections[3] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$MSAV_CATEGORY{ $1 } = "Trojan";				
		}
	}	

	# load MSAV Worm
	@replacements= split( /\n/, $sections[4] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$MSAV_CATEGORY{ $1 } = "Worm";				
		}
	}	

	# load MSAV Adware
	@replacements= split( /\n/, $sections[5] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$MSAV_CATEGORY{ $1 } = "Adware";				
		}
	}	

	# load MSAV Virus	
	@replacements= split( /\n/, $sections[6] );	
	foreach my $entry ( @replacements )
	{		
		if( $entry =~ /\*(.*)\s*/ )
		{
			$MSAV_VIRUS{ $1 } = "Virus";				
		}		
	}	

	# load MSAV Skip
	@replacements= split( /\n/, $sections[7] );	
	foreach my $entry ( @replacements )
	{		
		if( $entry =~ /\*(.*)\s*/ )
		{
			$MSAV_SKIP{ $1 } = "Skip";				
		}
	}	

#	my @xlats = keys (%MSAV_REPLACEMENT);	
#	for my $key ( @xlats )
#	{
#		my $rep = $MSAV_REPLACEMENT{$key};
#		print "\n$key, $rep";
#	}	
#	my @cats = reverse sort keys (%MSAV_CATEGORY);	
#	for my $key ( @cats)
#	{
#		my $rep = $MSAV_CATEGORY{$key};
#		print "\n[$key], [$rep]";
#	}	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
}


sub GetMSAV_xlat_Threatname( $ )
{
	my $threatname = shift;	
	my $xlat_name = $threatname;
	
	my @xlats = reverse sort ( keys ( %MSAV_REPLACEMENT ) );	
	for my $key ( @xlats )
	{
		my $rep = $MSAV_REPLACEMENT{ $key };
		if ( $xlat_name =~ s/$key/$rep/i )
		{
		}		
		#print "\n $key, $rep ==> $threatname, $xlat_name";
	}	
	
	# make variant name as small	
	my @parts = split( /\./, $xlat_name );	
	my $len = @parts;
	if(( $len > 2 ) and ( $parts[-1] =~ m/([A-Z]{1,4})$/ ))
	{
		$parts[-1] = lc( $parts[-1] );
		$xlat_name = join( ".", @parts ); 
	}
	
	$xlat_name =~ s/\!/\./;
	
	# remove variant name from end of threat name
	my @arr = split( /\./, $xlat_name ) ;
	$len = @arr;
	if( $len >= 3 )
	{
		if( $xlat_name =~ /(.+)\.([a-z]+)/ )	
		{
			$xlat_name = $1;
		}
	}	
	
	#print "\n===> $xlat_name ";
	return $xlat_name;
}


sub GetMSAV_Category( $ )
{
	my $threatname = shift;
  
  # check skip names first
	my @names = sort keys ( %MSAV_SKIP );	
	for my $key ( @names )
	{
		#print "[$threatname], [$key]\n";
		if ( $threatname =~ /^$key/i )
		{
			return $MSAV_SKIP{ $key };
		}		
	}

  # check if threat name appears in Virus category
	@names = sort keys ( %MSAV_VIRUS );	
	for my $key ( @names )
	{
		#print "[$threatname], [$key]\n";
		if ( $threatname =~ /^$key/i )
		{
			return $MSAV_VIRUS{ $key };
		}		
	}
	
	# check if Backdoor, Trojan, Worm or Adware category
	@names = sort keys ( %MSAV_CATEGORY );	
	for my $key ( @names )
	{
		#print "[$threatname], [$key]\n";
		if ( $threatname =~ /^$key/i )
		{
			return $MSAV_CATEGORY{ $key };
		}		
	}
	
	#print "\n$threatname, Unknown ";
	return "Unknown";
}


sub MicrosoftScan( $ )
{
	my $scan_log = "$logs_dir\\microsoft.log";			
	my $src_dir = shift;		
	
	my $debug_str = "\n Running Microsoft MP Scanner : $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	my $command = "$tools_dir\\ntvirus\\MSAV\\mpscanp /spyware /report $scan_log $src_dir";					
	my $output = qx( $command );													
	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								
}


sub MicrosoftScanSelfCheck( $ )
{	
	my $src_dir = shift;		
	
	my $debug_str = "\n Microsoft MP Scanner Self Check: $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	my $command = "$tools_dir\\ntvirus\\MSAV\\mpscanp /spyware $src_dir";						
	my $output = qx( $command );							
	
	if ( $output =~ m/Infected:\sVirus:DOS\/EICAR_Test_File/ )	
	{
		$debug_str = "\n Done.";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str );									
		return 1;
	}
	
	$debug_str = "\n FAILED !!!\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								
	return 0;
}


sub MicrosoftParseLog( )
{
	my $scan_log = "$logs_dir\\microsoft.log";	
		
	my $debug_str = "\n Running Microsoft Scanner log parser : $scan_log ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	open( IN, "< $scan_log" ) or die "\n\n FATAL Error: $! $scan_log !!! \n";	
	my @data = <IN>;
	close IN;
			
	foreach my $entry ( @data )
	{
		my $threatname = "";				
		if ( $entry =~ m/([0-9A-F]{32}).*Infected:\s+(.*)/i )
		{
			my $md5 = uc( $1 );			
			$threatname = $2;
			my $xlat_name = GetMSAV_xlat_Threatname( $threatname );
			  	
	  	if ( !exists( $MSAV_DETECTED{ $md5 } ))
	  	{
	  		$MSAV_DETECTED{ $md5 } = "$threatname, $xlat_name";		
	  	}	  	
		}
	}
	
	my $ms_trojan_log = "$logs_dir\\trojan-msav.csv";	
	my $ms_worm_log = "$logs_dir\\worm-msav.csv";	
	my $ms_backdoor_log = "$logs_dir\\backdoor-msav.csv";	
	my $ms_adware_log = "$logs_dir\\adware-msav.csv";	
	my $ms_virus_log = "$logs_dir\\virus-msav.csv";	
	my $ms_other_log = "$logs_dir\\other-msav.csv";	
	#my $ms_exclu_packer_log = "$logs_dir\\ms_packer-exclusion.csv";
		
	open( OUT_TROJAN, "> $ms_trojan_log" ) or die "\n\n Error: $! $ms_trojan_log !\n";	
	open( OUT_WORM, "> $ms_worm_log" ) or die "\n\n Error: $! $ms_worm_log\n";	
	open( OUT_BACKDOOR, "> $ms_backdoor_log" ) or die "\n\n Error: $! $ms_backdoor_log\n";	
	open( OUT_ADWARE, "> $ms_adware_log" ) or die "\n\n Error: $! $ms_adware_log\n";	
	open( OUT_VIRUS, "> $ms_virus_log" ) or die "\n\n Error: $! $ms_virus_log\n";	
	open( OUT_OTHER, "> $ms_other_log" ) or die "\n\n Error: $! $ms_other_log\n";	
	#open( OUT_EX_PACKER, "> $ms_exclu_packer_log" ) or die "$! $ms_exclu_packer_log";	

	my @ms_detected = keys ( %MSAV_DETECTED );	
	for my $key ( @ms_detected )
	{
		my $threatname = $MSAV_DETECTED{ $key };		
		my @names = split( /, /, $threatname );
				
		my $category = GetMSAV_Category ( $names[1] );
		
		# if file is packed with Packer from exclusion list		
		my $packer = ""; 
				
		if ( exists $KAV_PACKED { $key } )
		{
			$packer = $KAV_PACKED { $key };			
			#if ( exists ( $PACKER_EXCLUSION{ $packer } ) )
			#{
			#	print OUT_EX_PACKER "$key, $threatname, $packer\n";
			#}
		}
		
		# put into appropriate category
		if ( $category =~ m/^Trojan/i )
		{
			print OUT_TROJAN "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Worm/i )
		{
			print OUT_WORM "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Backdoor/i )
		{
			print OUT_BACKDOOR "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Adware/i )
		{
			print OUT_ADWARE "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Virus/i )
		{
			print OUT_VIRUS "$key, $threatname\n";		
		}				
		else
		{
			print OUT_OTHER "$key, $threatname\n";		
		}			
	}	
		
	close OUT_TROJAN;
	close OUT_WORM;
	close OUT_BACKDOOR;
	close OUT_ADWARE;
	close OUT_VIRUS;
	close OUT_OTHER;
	#close OUT_EX_PACKER;
		
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );									
}


##################################################
#
# Trend Micro Scan
#
#####

sub TMScan ( $ )
{
	my $scan_log = "$logs_dir\\trend.log";			
	my $src_dir = shift;		
	
	my $debug_str = "\n Running Trend Micro Scanner : $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	my $command = "$tools_dir\\ntvirus\\trend\\vscantm.exe /S /NM /NB /NC /TMAPTN /SSAPTN /LR=$scan_log $src_dir";					
	my $output = qx( $command );												

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
}


sub TMScanSelfCheck ( $ )
{
	my $scan_log = "$logs_dir\\trend.log";			
	my $src_dir = shift;		
	
	my $debug_str = "\n Trend Micro Scanner Self Check: $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	my $command = "$tools_dir\\ntvirus\\trend\\vscantm.exe /S /NM /NB /NC /TMAPTN /SSAPTN /LR=$scan_log $src_dir";					
	my $output = qx( $command );											
	
	if ( $output =~ m/Eicar_test_file/ )	
	{
		$debug_str = "\n Done.";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str );										
		return 1;	
	}

	$debug_str = "\n FAILED !!!\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	return 0;
}


sub TMParseLog( )
{
	my $scan_log = "$logs_dir\\trend.log";	
	
	my $debug_str = "\n Running Trend Micro Scanner log parser : $scan_log ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	open( IN, "< $scan_log" ) or die "\n\n Error: $! $scan_log !!! \n\n";		
	my @data = <IN>;
	close IN;
	
	$scan_log = "$logs_dir\\virus-trend.csv";	
	open( OUT, "> $scan_log" ) or die "\n\nError: $! $scan_log\n";	
	foreach my $entry ( @data )
	{
		#print $entry;
		my $threatname = "";		
		my $md5 = "";
		if ( $entry =~ m/^Found\s+\[\s*PE_(.+)\sin\s.*([0-9A-F]{32})/i )
		{
			$threatname = "PE_$1";			
			$md5 = $2;
			$threatname =~ s/\s*\]\(\s*//;			
			$threatname =~ s/\s*\)//;			
			print OUT "$md5, Virus, $threatname\n";	
		}

		if ( $entry =~ m/^Found\s+\[\s*Possible_Virus\](.+)\sin\s.*([0-9A-F]{32})/i )
		{	
			$threatname = "Possible_Virus$1";			
			$md5 = $2;
			$threatname =~ s/\s*\(\s*//;			
			$threatname =~ s/\s*\)//;							
			print OUT "$md5, Virus, $threatname\n";	
		}		
	}
	close OUT;

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );											
}


##################################################
#
# AVIRA Scan
#
#####

sub AVIRAScan( $ )
{
	my $src_dir = shift;		
	my $scan_log = "$logs_dir\\avira.log";			
	
	my $debug_str = "\n Running AVIRA : $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	my $command = "$tools_dir\\ntvirus\\AVIRA\\avcls.exe -allfiles -s -z -noboot -nombr -alltypes -lang=EN -rs -rf$scan_log $src_dir";					
	my $output = qx( $command );													

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );											
}


sub AVIRAScanSelfCheck( $ )
{
	my $src_dir = shift;		
		
	my $debug_str = "\n Running AVIRA : $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	my $command = "$tools_dir\\ntvirus\\AVIRA\\avcls.exe -allfiles -s -z -noboot -nombr -alltypes -lang=EN -rs $src_dir";					
	my $output = qx( $command );													
	if ( $output =~ m/Eicar-Test-Signature\svirus/ )
	{
		$debug_str = "\n Done.";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str );											
		return 1;	
	}

	$debug_str = "\n FAILED !!!\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );											
	return 0;
}


sub AVIRAParseLog( )
{
	my $scan_log = "$logs_dir\\avira.log";		

	my $debug_str = "\n Running AVIRA Scanner log parser : $scan_log ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	open( IN, "<:encoding(UTF-16)", $scan_log ) or die "\n\n Error: $! $scan_log !!! \n\n";			
	my @data = <IN>;
	close IN;
	
	$scan_log = "$logs_dir\\avira-parsed.csv";	
	open( OUT, "> $scan_log" ) or die "\n\n Error: $! $scan_log";	
	foreach my $entry ( @data )
	{		
		if ( $entry =~ m/^ALERT:\s+\[([^\]]+)\]\s+([^\s]+).*\s+<<</ )
		{
			my $threatname = $1;
			my $filename = $2;
			#  remove embedded file name 
			if ( $filename =~ m/([0-9A-F]{32})-->/i )
			{
				$filename = $1;
			}
			#print "$filename, $threatname\n";	
			print OUT "$filename, $threatname\n";				
		}
	}
	close OUT;

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );											
}


##################################################
#
# Symantec Scan
#
#####

sub LoadSYMCThreatInfo( )
{
	my $ini_file = "$tools_dir\\SYMC_ThreatNames.ini";

	my $debug_str = "\n Loading Symantec Threat name information ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

	open( IN, "< $ini_file" ) or die "\n FATAL Error: Can not locate SYMC_ThreatNames.ini. \n $! $ini_file !!! \n";
	my @data1 = <IN>;
	close IN;
	
	my $data = join( "", @data1 );	
	my @sections = split( /\[Section:/, $data );			                          
		
	my @replacements= split( /\n/, $sections[1] );		
	foreach my $entry ( @replacements )
	{
		if ( $entry =~ m/(.*)=(.*)\s*/ )
		{
			my $old = $1;
			my $rep = $2;
			$rep =~ s/\s+//;
			$SYMC_REPLACEMENT{ $old } = $rep;				
		}
	}	

	# load SYMC Backdoor
	@replacements= split( /\n/, $sections[2] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$SYMC_CATEGORY{ $1 } = "Backdoor";				
		}
	}	

	# load SYMC Trojan
	@replacements= split( /\n/, $sections[3] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$SYMC_CATEGORY{ $1 } = "Trojan";				
		}
	}	

	# load SYMC Worm
	@replacements= split( /\n/, $sections[4] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$SYMC_CATEGORY{ $1 } = "Worm";				
		}
	}	

	# load SYMC Adware
	@replacements= split( /\n/, $sections[5] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$SYMC_CATEGORY{ $1 } = "Adware";				
		}
	}	

	# load SYMC Virus	
	@replacements= split( /\n/, $sections[6] );	
	foreach my $entry ( @replacements )
	{		
		if( $entry =~ /\*(.*)\s*/ )
		{
			$SYMC_VIRUS{ $1 } = "Virus";				
		}		
	}	

	# load SYMC Skip
	@replacements= split( /\n/, $sections[7] );	
	foreach my $entry ( @replacements )
	{		
		if( $entry =~ /\*(.*)\s*/ )
		{
			$SYMC_SKIP{ $1 } = "Skip";				
		}
	}	

#	my @xlats = sort keys (%SYMC_REPLACEMENT);	
#	for my $key ( @xlats )
#	{
#		my $rep = $SYMC_REPLACEMENT{$key};
#		print "\n $key, $rep";
#	}	
#	
#	my @cats = reverse sort keys (%SYMC_CATEGORY);	
#	for my $key ( @cats)
#	{
#		my $rep = $SYMC_CATEGORY{$key};
#		print "\n CAT [$key], [$rep]";
#	}	
#
#	my @v = reverse sort keys (%SYMC_VIRUS);	
#	for my $key ( @v)
#	{
#		my $rep = $SYMC_VIRUS{$key};
#		print "\n VIRUS [$key], [$rep]";
#	}	
#
#	my @s = reverse sort keys (%SYMC_SKIP);	
#	for my $key ( @s)
#	{
#		my $rep = $SYMC_SKIP{$key};
#		print "\n SKIP [$key], [$rep]";
#	}	
	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
}


sub GetSYMC_xlat_Threatname( $ )
{
	my $threatname = shift;	
	my $xlat_name = $threatname;
	
	my @xlats = sort ( keys ( %SYMC_REPLACEMENT ) );	
	for my $key ( @xlats )
	{
		my $rep = $SYMC_REPLACEMENT{ $key };
		if ( $xlat_name =~ s/$key/$rep/i )
		{
		}		
		#print "\n $key, $rep ==> $threatname, $xlat_name";
	}	
	
	# make variant name as small	
	my @parts = split( /\./, $xlat_name );	
	my $len = @parts;
	if(( $len > 2 ) and ( $parts[-1] =~ m/([A-Z]{1,4})$/ ))
	{
		$parts[-1] = lc( $parts[-1] );
		$xlat_name = join( ".", @parts ); 
	}
	
	$xlat_name =~ s/\!/\./;
	#print "\n===> $xlat_name ";
	return $xlat_name;
}


sub GetSYMC_Category( $ )
{
	my $threatname = shift;
  
  # check skip names first
	my @names = sort keys ( %SYMC_SKIP );	
	for my $key ( @names )
	{
		#print "[$threatname], [$key]\n";
		if ( $threatname =~ /^$key/i )
		{
			return $SYMC_SKIP{ $key };
		}		
	}

  # check if threat name appears in Virus category
	@names = sort keys ( %SYMC_VIRUS );	
	for my $key ( @names )
	{
		#print "[$threatname], [$key]\n";
		if ( $threatname =~ /$key/i )
		{
			return $SYMC_VIRUS{ $key };
		}		
	}
	
	# check if Backdoor, Trojan, Worm or Adware category
	@names = sort keys ( %SYMC_CATEGORY );	
	for my $key ( @names )
	{
		#print "[$threatname], [$key]\n";
		if ( $threatname =~ /$key/i )
		{
			return $SYMC_CATEGORY{ $key };
		}		
	}
	
	#print "\n$threatname, Unknown ";
	return "Unknown";
}


sub SymantecScan ( $ )
{
	my $src_dir = shift;		
	my $scan_log = "$logs_dir\\symc.log";			
	
	my $debug_str = "\n Running Symantec Scanner : $src_dir ...";
	print $debug_str;
	
	unlink( $scan_log );
	
	my $command = "$tools_dir\\ntvirus\\SYMANTEC\\elegharn.exe  file /defs=$tools_dir\\ntvirus\\SYMANTEC /md5 /LEG4 /multieng=1 /UBERCAT=1,2,3,4,7 /dir=$src_dir /flog=$scan_log";	
	my $output = qx( $command );												

	$debug_str = "\n Done.";
	print $debug_str;
}


sub SymantecSelfCheck ( $ )
{
	my $src_dir = shift;		
		
	my $debug_str = "\n Running Symantec Scanner Self Check : $src_dir ...";
	print $debug_str;
				
	my $command = "$tools_dir\\ntvirus\\SYMANTEC\\elegharn.exe  file /defs=$tools_dir\\ntvirus\\SYMANTEC /md5 /LEG4 /multieng=1 /UBERCAT=1,2,3,4,7 /dir=$src_dir";	
	my $output = qx( $command );													
	
	if ( $output =~ m/Virus Name: EICAR Test String/ )
	{
		$debug_str = "\n Done.";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str );											
		return 1;	
	}

	$debug_str = "\n FAILED !!!\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );											
	return 0;
}


sub SymantecParseLog( )
{
	my $scan_log = "$logs_dir\\symc.log";	
	
	my $debug_str = "\n Running Symantec Scanner log parser : $scan_log ...";
	print $debug_str;
	
	open( IN, "< $scan_log" ) or die "\n\n Error: $! $scan_log !!! \n\n";		
	#open(OUT, ">$logs_dir\\symc-parsed.csv");
		
	my $md5 = "";	
	my $vid = "";
	my $threatname = "";
	my $fname = "";
	my $xlat_name = "";
	my $category = "";

	my %SYMC_DETECTED;	
	
	while (<IN>)
	{
		#print ">$_";
		chomp;
		if (m/^Scanning file \(multi\)\.\.\./)
		{
			$fname = <IN>;
			#print "$fname\n";
			chomp($fname);
			
			if ( $fname =~ m/([0-9A-F]{32})$/i )
			{
				$md5 = uc( $1 );			
			}
			
			$_ = <IN>;
			$_ = <IN>;
			$_ = <IN>;
			$_ = <IN>;
			
			if (m/^Clean/)
			{
		    next;
			}
		}
			
		if (m/VID: 0x([0-9A-Fa-f]{8}), Virus Name: ([^,]+), /)
		{
			$vid = $1;
			$threatname = $2;
			$xlat_name = GetSYMC_xlat_Threatname( $threatname );
			#printf OUT "$md5, $threatname, $xlat_name, $vid\n";		
			
			$SYMC_DETECTED{ $md5 } = "$threatname, $xlat_name";					
		}
	}
	close(IN);		
	#close(OUT);		
	
	my $symc_trojan_log = "$logs_dir\\trojan-symc.csv";	
	my $symc_worm_log = "$logs_dir\\worm-symc.csv";	
	my $symc_backdoor_log = "$logs_dir\\backdoor-symc.csv";	
	my $symc_adware_log = "$logs_dir\\adware-symc.csv";	
	my $symc_virus_log = "$logs_dir\\virus-symc.csv";	
	my $symc_other_log = "$logs_dir\\other-symc.csv";	
		
	open( OUT_TROJAN, "> $symc_trojan_log" ) or die "\n\n Error: $! $symc_trojan_log !\n";	
	open( OUT_WORM, "> $symc_worm_log" ) or die "\n\n Error: $! $symc_worm_log\n";	
	open( OUT_BACKDOOR, "> $symc_backdoor_log" ) or die "\n\n Error: $! $symc_backdoor_log\n";	
	open( OUT_ADWARE, "> $symc_adware_log" ) or die "\n\n Error: $! $symc_adware_log\n";	
	open( OUT_VIRUS, "> $symc_virus_log" ) or die "\n\n Error: $! $symc_virus_log\n";	
	open( OUT_OTHER, "> $symc_other_log" ) or die "\n\n Error: $! $symc_other_log\n";	

	my @symc_detected = keys ( %SYMC_DETECTED );	
	for my $key ( @symc_detected )
	{
		my $threatname = $SYMC_DETECTED{ $key };		
		my @names = split( /, /, $threatname );
		
		my $category = GetSYMC_Category ( $names[1] );
		
		#print "$names[1], $category\n";
		
		# put into appropriate category
		if ( $category =~ m/^Trojan/i )
		{
			print OUT_TROJAN "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Worm/i )
		{
			print OUT_WORM "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Backdoor/i )
		{
			print OUT_BACKDOOR "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Adware/i )
		{
			print OUT_ADWARE "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Virus/i )
		{
			print OUT_VIRUS "$key, $threatname\n";		
		}				
		else
		{
			print OUT_OTHER "$key, $threatname\n";		
		}			
	}	
		
	close OUT_TROJAN;
	close OUT_WORM;
	close OUT_BACKDOOR;
	close OUT_ADWARE;
	close OUT_VIRUS;
	close OUT_OTHER;
		
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	
}


##################################################
#
# BitDefender Scan
#
#####

sub LoadBitDefThreatInfo( )
{
	my $ini_file = "$tools_dir\\BitDef_ThreatNames.ini";

	my $debug_str = "\n Loading BitDefender Threat name information ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

	open( IN, "< $ini_file" ) or die "\n FATAL Error: Can not locate BitDef_ThreatNames.ini. \n $! $ini_file !!! \n";
	my @data1 = <IN>;
	close IN;
	
	my $data = join( "", @data1 );	
	my @sections = split( /\[Section:/, $data );			                          
		
	my @replacements= split( /\n/, $sections[1] );		
	foreach my $entry ( @replacements )
	{
		if ( $entry =~ m/(.*)=(.*)\s*/ )
		{
			my $old = $1;
			my $rep = $2;
			$rep =~ s/\s+//;
			$BITDEF_REPLACEMENT{ $old } = $rep;				
		}
	}	

	# load BITDEF Backdoor
	@replacements= split( /\n/, $sections[2] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$BITDEF_CATEGORY{ $1 } = "Backdoor";				
		}
	}	

	# load BITDEF Trojan
	@replacements= split( /\n/, $sections[3] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$BITDEF_CATEGORY{ $1 } = "Trojan";				
		}
	}	

	# load BITDEF Worm
	@replacements= split( /\n/, $sections[4] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$BITDEF_CATEGORY{ $1 } = "Worm";				
		}
	}	

	# load BITDEF Adware
	@replacements= split( /\n/, $sections[5] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$BITDEF_CATEGORY{ $1 } = "Adware";				
		}
	}	

	# load BITDEF Virus	
	@replacements= split( /\n/, $sections[6] );	
	foreach my $entry ( @replacements )
	{		
		if( $entry =~ /\*(.*)\s*/ )
		{
			$BITDEF_VIRUS{ $1 } = "Virus";				
		}		
	}	

	# load BITDEF Skip
	@replacements= split( /\n/, $sections[7] );	
	foreach my $entry ( @replacements )
	{		
		if( $entry =~ /\*(.*)\s*/ )
		{
			$BITDEF_SKIP{ $1 } = "Skip";				
		}
	}	

#	my @xlats = sort keys (%BITDEF_REPLACEMENT);	
#	for my $key ( @xlats )
#	{
#		my $rep = $BITDEF_REPLACEMENT{$key};
#		print "\n $key, $rep";
#	}	
#	
#	my @cats = reverse sort keys (%BITDEF_CATEGORY);	
#	for my $key ( @cats)
#	{
#		my $rep = $BITDEF_CATEGORY{$key};
#		print "\n CAT [$key], [$rep]";
#	}	
#
#	my @v = reverse sort keys (%BITDEF_VIRUS);	
#	for my $key ( @v)
#	{
#		my $rep = $BITDEF_VIRUS{$key};
#		print "\n VIRUS [$key], [$rep]";
#	}	
#
#	my @s = reverse sort keys (%BITDEF_SKIP);	
#	for my $key ( @s)
#	{
#		my $rep = $BITDEF_SKIP{$key};
#		print "\n SKIP [$key], [$rep]";
#	}	
	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
}


sub GetBitDef_xlat_Threatname( $ )
{
	my $threatname = shift;	
	my $xlat_name = $threatname;
	
	my @xlats = sort ( keys ( %BITDEF_REPLACEMENT ) );	
	for my $key ( @xlats )
	{
		my $rep = $BITDEF_REPLACEMENT{ $key };
		#print "\n [$key], [$rep] ";
		if ( $xlat_name =~ s/$key/$rep/i )
		{
		}		
		#print "\n [$key], [$rep] ==> [$threatname], [$xlat_name]\n";
	}	

	$xlat_name =~ s/\!/\./;
	$xlat_name =~ s/\.$//;
	
	# make variant name as small	
	my @parts = split( /\./, $xlat_name );	
	my $len = @parts;
	if(( $len > 2 ) and ( $parts[-1] =~ m/([A-Z]{1,4})$/ ))
	{
		$parts[-1] = lc( $parts[-1] );
		$xlat_name = join( ".", @parts ); 
	}
	
	#print "\n===> $xlat_name ";
	return $xlat_name;
}


sub GetBitDef_Category( $ )
{
	my $threatname = shift;
  
  # check skip names first
	my @names = sort keys ( %BITDEF_SKIP );	
	for my $key ( @names )
	{
		#print "[$threatname], [$key]\n";
		if ( $threatname =~ /^$key/i )
		{
			return $BITDEF_SKIP{ $key };
		}		
	}

  # check if threat name appears in Virus category
	@names = sort keys ( %BITDEF_VIRUS );	
	for my $key ( @names )
	{
		#print "[$threatname], [$key]\n";
		if ( $threatname =~ /$key/i )
		{
			return $BITDEF_VIRUS{ $key };
		}		
	}
	
	# check if Backdoor, Trojan, Worm or Adware category
	@names = sort keys ( %BITDEF_CATEGORY );	
	for my $key ( @names )
	{
		#print "[$threatname], [$key]\n";
		if ( $threatname =~ /$key/i )
		{
			return $BITDEF_CATEGORY{ $key };
		}		
	}
	
	#print "\n$threatname, Unknown ";
	return "Unknown";
}


sub BitDefScan ( $ )
{
	my $src_dir = shift;				
	my $scan_log = "$logs_dir\\bitdef.log";			
	
	my $debug_str = "\n Running BitDefender Scanner : $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	
	my $command = "$tools_dir\\ntvirus\\SOFTWINBDC\\bdc.exe $src_dir /arc /mail /log=$scan_log";
	my $output = qx( $command );												

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
}


sub BitDefScanSelfCheck ( $ )
{	
	my $src_dir = shift;			
	
	my $debug_str = "\n BitDefender Scanner Self Check: $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	
	my $command = "$tools_dir\\ntvirus\\SOFTWINBDC\\bdc.exe $src_dir /arc /mail";
	my $output = qx( $command ); 	
	
	if( $output =~ m/infected:\sEICAR-Test-File/ )	
	{
		$debug_str = "\n Done.";
		print $debug_str;
		return 1;	
	}

	$debug_str = "\n FAILED !!!\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	return 0;
}


sub BitDefParseLog( )
{	
	my $scan_log = "$logs_dir\\bitdef.log";	
	
	my $debug_str = "\n Running BitDefender Scanner log parser : $scan_log ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	
	open( IN, "< $scan_log" ) or die "\n\n Error: $! $scan_log !!! \n\n";		
	my @data = <IN>;
	close IN;
	
	my %BITDEF_DETECTED;
	
	$scan_log = "$logs_dir\\bitdef-parsed.csv";	
	open( OUT, "> $scan_log" ) or die "\n\nError: $! $scan_log\n";	
	foreach my $entry ( @data )
	{
		#print $entry;
		my $threatname = "";		
		my $path = "";
		
		if( $entry =~ m/(.+)\sinfected:\s(.+)/i )
		{	
			$path = $1;				
			$threatname = $2;		
			
			$path =~ s/(=>.*)//;			
		
			if( $path =~ m/([0-9A-F]{32})/i )
			{
				my $md5 = $1;
				my @t = split(/:/, $threatname);
				if( @t >= 2)
				{
					$threatname = $t[-1];
				}				

				my $xlat_name = GetBitDef_xlat_Threatname( $threatname );
				$BITDEF_DETECTED{ $md5 } = "$threatname, $xlat_name";
				print OUT "$md5, $threatname, $xlat_name\n";					
			}			
		}
	}
	close OUT;

	my $bitdef_trojan_log = "$logs_dir\\trojan-bitdef.csv";	
	my $bitdef_worm_log = "$logs_dir\\worm-bitdef.csv";	
	my $bitdef_backdoor_log = "$logs_dir\\backdoor-bitdef.csv";	
	my $bitdef_adware_log = "$logs_dir\\adware-bitdef.csv";	
	my $bitdef_virus_log = "$logs_dir\\virus-bitdef.csv";	
	my $bitdef_other_log = "$logs_dir\\other-bitdef.csv";	
		
	open( OUT_TROJAN, "> $bitdef_trojan_log" ) or die "\n\n Error: $! $bitdef_trojan_log !\n";	
	open( OUT_WORM, "> $bitdef_worm_log" ) or die "\n\n Error: $! $bitdef_worm_log\n";	
	open( OUT_BACKDOOR, "> $bitdef_backdoor_log" ) or die "\n\n Error: $! $bitdef_backdoor_log\n";	
	open( OUT_ADWARE, "> $bitdef_adware_log" ) or die "\n\n Error: $! $bitdef_adware_log\n";	
	open( OUT_VIRUS, "> $bitdef_virus_log" ) or die "\n\n Error: $! $bitdef_virus_log\n";	
	open( OUT_OTHER, "> $bitdef_other_log" ) or die "\n\n Error: $! $bitdef_other_log\n";	

	my @bitdef_detected = keys ( %BITDEF_DETECTED );	
	for my $key ( @bitdef_detected )
	{
		my $threatname = $BITDEF_DETECTED{ $key };		
		my @names = split( /, /, $threatname );
		
		my $category = GetBitDef_Category( $names[1] );
		
		#print "$names[1], $category\n";
		
		# put into appropriate category
		if ( $category =~ m/^Trojan/i )
		{
			print OUT_TROJAN "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Worm/i )
		{
			print OUT_WORM "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Backdoor/i )
		{
			print OUT_BACKDOOR "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Adware/i )
		{
			print OUT_ADWARE "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Virus/i )
		{
			print OUT_VIRUS "$key, $threatname\n";		
		}				
		else
		{
			print OUT_OTHER "$key, $threatname\n";		
		}			
	}	
		
	close OUT_TROJAN;
	close OUT_WORM;
	close OUT_BACKDOOR;
	close OUT_ADWARE;
	close OUT_VIRUS;
	close OUT_OTHER;
		
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );											
}


##################################################
#
# ESET Scan
#
#####

sub LoadESETThreatInfo( )
{
	my $ini_file = "$tools_dir\\ESET_ThreatNames.ini";

	my $debug_str = "\n Loading ESET Threat name information ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

	open( IN, "< $ini_file" ) or die "\n FATAL Error: Can not locate ESET_ThreatNames.ini. \n $! $ini_file !!! \n";
	my @data1 = <IN>;
	close IN;
	
	my $data = join( "", @data1 );	
	my @sections = split( /\[Section:/, $data );			                          
		
	my @replacements= split( /\n/, $sections[1] );		
	foreach my $entry ( @replacements )
	{
		if ( $entry =~ m/(.*)=(.*)\s*/ )
		{
			my $old = $1;
			my $rep = $2;
			$rep =~ s/\s+//;
			$ESET_REPLACEMENT{ $old } = $rep;				
		}
	}	

	# load ESET Backdoor
	@replacements= split( /\n/, $sections[2] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$ESET_CATEGORY{ $1 } = "Backdoor";				
		}
	}	

	# load ESET Trojan
	@replacements= split( /\n/, $sections[3] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$ESET_CATEGORY{ $1 } = "Trojan";				
		}
	}	

	# load ESET Worm
	@replacements= split( /\n/, $sections[4] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$ESET_CATEGORY{ $1 } = "Worm";				
		}
	}	

	# load ESET Adware
	@replacements= split( /\n/, $sections[5] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$ESET_CATEGORY{ $1 } = "Adware";				
		}
	}	

	# load ESET Virus	
	@replacements= split( /\n/, $sections[6] );	
	foreach my $entry ( @replacements )
	{		
		if( $entry =~ /\*(.*)\s*/ )
		{
			$ESET_VIRUS{ $1 } = "Virus";				
		}		
	}	

	# load ESET Skip
	@replacements= split( /\n/, $sections[7] );	
	foreach my $entry ( @replacements )
	{		
		if( $entry =~ /\*(.*)\s*/ )
		{
			$ESET_SKIP{ $1 } = "Skip";				
		}
	}	

#	my @xlats = sort keys (%ESET_REPLACEMENT);	
#	for my $key ( @xlats )
#	{
#		my $rep = $ESET_REPLACEMENT{$key};
#		print "\n $key, $rep";
#	}	
#	
#	my @cats = reverse sort keys (%ESET_CATEGORY);	
#	for my $key ( @cats)
#	{
#		my $rep = $ESET_CATEGORY{$key};
#		print "\n CAT [$key], [$rep]";
#	}	
#
#	my @v = reverse sort keys (%ESET_VIRUS);	
#	for my $key ( @v)
#	{
#		my $rep = $ESET_VIRUS{$key};
#		print "\n VIRUS [$key], [$rep]";
#	}	
#
#	my @s = reverse sort keys (%ESET_SKIP);	
#	for my $key ( @s)
#	{
#		my $rep = $ESET_SKIP{$key};
#		print "\n SKIP [$key], [$rep]";
#	}	
	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
}


sub GetESET_xlat_Threatname( $ )
{
	my $threatname = shift;	
	
	my @a = split(/\//, $threatname);
	my $len = @a;
	if($len < 2)
	{
		return "Error";
	}
	
	my $xlat_name = $a[1];
	
	my @xlats = sort ( keys ( %ESET_REPLACEMENT ) );	
	for my $key ( @xlats )
	{
		my $rep = $ESET_REPLACEMENT{ $key };
		#print "\n [$key], [$rep] ";
		if ( $xlat_name =~ s/$key/$rep/i )
		{
		}		
		#print "\n [$key], [$rep] ==> [$threatname], [$xlat_name]\n";
	}	

	$xlat_name =~ s/\!/\./;
	$xlat_name =~ s/\.$//;
	
	# make variant name as small	
	my @parts = split( /\./, $xlat_name );	
	$len = @parts;
	if(( $len > 2 ) and ( $parts[-1] =~ m/([A-Z]{1,4})$/ ))
	{
		$parts[-1] = lc( $parts[-1] );
		$xlat_name = join( ".", @parts ); 
	}
	
	#print "\n===> $xlat_name ";
	return $xlat_name;
}


sub GetESET_Category( $$ )
{
	my $threatname = shift;
	my $xlat_name = shift;

  ########
  # check using: $xlat_name
  ####
  
  # check skip names first
	my @names = sort keys ( %ESET_SKIP );	
	for my $key ( @names )
	{
		#print "[$xlat_name], [$key]\n";
		if ( $xlat_name =~ /^$key/i )
		{
			return $ESET_SKIP{ $key };
		}		
	}

	# check if Backdoor, Trojan, Worm or Adware category
	@names = sort keys ( %ESET_CATEGORY );	
	for my $key ( @names )
	{
		#print "[$xlat_name], [$key]\n";
		if ( $xlat_name =~ /$key/i )
		{
			return $ESET_CATEGORY{ $key };
		}		
	}

  # check if threat name appears in Virus category
	@names = sort keys ( %ESET_VIRUS );	
	for my $key ( @names )
	{
		#print "[$xlat_name], [$key]\n";
		if ( $xlat_name =~ /$key/i )
		{
			return $ESET_VIRUS{ $key };
		}		
	}
	
  ########
  # check using: $threatname
  ####
  
  # check skip names first
	@names = sort keys ( %ESET_SKIP );	
	for my $key ( @names )
	{
		#print "[$threatname], [$key]\n";
		if ( $threatname =~ /^$key/i )
		{
			return $ESET_SKIP{ $key };
		}		
	}

	# check if Backdoor, Trojan, Worm or Adware category
	@names = sort keys ( %ESET_CATEGORY );	
	for my $key ( @names )
	{
		#print "[$threatname], [$key]\n";
		if ( $threatname =~ /$key/i )
		{
			return $ESET_CATEGORY{ $key };
		}		
	}

  # check if threat name appears in Virus category
	@names = sort keys ( %ESET_VIRUS );	
	for my $key ( @names )
	{
		#print "[$threatname], [$key]\n";
		if ( $threatname =~ /$key/i )
		{
			return $ESET_VIRUS{ $key };
		}		
	}
		
	
	#print "\n$threatname, Unknown ";
	return "Unknown";
}

sub ESETScan ( $ )
{
	my $src_dir = shift;		
	
	my $scan_log = "$logs_dir\\nod32.log";			
	
	my $debug_str = "\n Running ESET Scanner : $src_dir ...";
	print $debug_str;
	
	my $command = "$tools_dir\\ntvirus\\ESET\\nod32.exe $src_dir /scanmem- /mapi- /list+ /all /pack+ /arch+ /sfx+ /ah /program /adware /unsafe /quit+ /log=$scan_log";
	my $output = qx( $command );												

	$debug_str = "\n Done.";
	print $debug_str;
}


sub ESETScanSelfCheck ( $ )
{	
	my $src_dir = shift;		
		
	my $scan_log = "$logs_dir\\nod32.log";			
	
	my $debug_str = "\n ESET Scanner Self Check: $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	
	unlink( $scan_log );
	my $command = "$tools_dir\\ntvirus\\ESET\\nod32.exe $src_dir /scanmem- /mapi- /list+ /all /pack+ /arch+ /sfx+ /ah /program /adware /unsafe /quit+ /log=$scan_log";
	qx( $command ); 
	
	open( IN, "< $scan_log" ) or die "\n\n Error: $! $scan_log !!! \n\n";		
	my @data = <IN>;
	close IN;	
	unlink( $scan_log );
	
	my $output = join( "", @data );											
	
	if( $output =~ m/\s-\sEicar\stest\sfile/ )	
	{
		$debug_str = "\n Done.";
		print $debug_str;
		return 1;	
	}

	$debug_str = "\n FAILED !!!\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	return 0;
}


sub ESETParseLog( )
{
	my $scan_log = "$logs_dir\\nod32.log";	
	
	my $debug_str = "\n Running ESET Scanner log parser : $scan_log ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	
	open( IN, "< $scan_log" ) or die "\n\n Error: $! $scan_log !!! \n\n";		
	my @data = <IN>;
	close IN;
	
	my %ESET_DETECTED;
	
	$scan_log = "$logs_dir\\eset-parsed.csv";	
	open( OUT, "> $scan_log" ) or die "\n\nError: $! $scan_log\n";	
	foreach my $entry ( @data )
	{
		#print $entry;
		my $threatname = "";		
		my $path = "";
		if( !( $entry =~ m/\s-\sis\sOK$/i) )
		{		
			if( $entry =~ m/(.+)\s-\s(.+)/i )
			{
				$path = $1;				
				$threatname = $2;							
				$path =~ s/(\s».*)//;
				
				if( $path =~ m/([0-9A-F]{32})/i )
				{
					my $md5 = $1;					
					if( $threatname =~ m/([^\s]+\/[^\s]+)/ )
					{
						$threatname = $1;
					}
					
					my $xlat_name = GetESET_xlat_Threatname( $threatname );
					$ESET_DETECTED{ $md5 } = "$threatname, $xlat_name";
					print OUT "$path, $threatname\n";	
				}
			}
		}
	}
	close OUT;
	
	my $eset_trojan_log = "$logs_dir\\trojan-eset.csv";	
	my $eset_worm_log = "$logs_dir\\worm-eset.csv";	
	my $eset_backdoor_log = "$logs_dir\\backdoor-eset.csv";	
	my $eset_adware_log = "$logs_dir\\adware-eset.csv";	
	my $eset_virus_log = "$logs_dir\\virus-eset.csv";	
	my $eset_other_log = "$logs_dir\\other-eset.csv";	
		
	open( OUT_TROJAN, "> $eset_trojan_log" ) or die "\n\n Error: $! $eset_trojan_log !\n";	
	open( OUT_WORM, "> $eset_worm_log" ) or die "\n\n Error: $! $eset_worm_log\n";	
	open( OUT_BACKDOOR, "> $eset_backdoor_log" ) or die "\n\n Error: $! $eset_backdoor_log\n";	
	open( OUT_ADWARE, "> $eset_adware_log" ) or die "\n\n Error: $! $eset_adware_log\n";	
	open( OUT_VIRUS, "> $eset_virus_log" ) or die "\n\n Error: $! $eset_virus_log\n";	
	open( OUT_OTHER, "> $eset_other_log" ) or die "\n\n Error: $! $eset_other_log\n";	

	my @eset_detected = keys ( %ESET_DETECTED );	
	for my $key ( @eset_detected )
	{
		my $threatname = $ESET_DETECTED{ $key };		
		my @names = split( /, /, $threatname );
		
		my $category = GetESET_Category( $names[0], $names[1] );
		
		#print "$names[1], $category\n";
		
		# put into appropriate category
		if ( $category =~ m/^Trojan/i )
		{
			print OUT_TROJAN "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Worm/i )
		{
			print OUT_WORM "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Backdoor/i )
		{
			print OUT_BACKDOOR "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Adware/i )
		{
			print OUT_ADWARE "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Virus/i )
		{
			print OUT_VIRUS "$key, $threatname\n";		
		}				
		else
		{
			print OUT_OTHER "$key, $threatname\n";		
		}			
	}	
		
	close OUT_TROJAN;
	close OUT_WORM;
	close OUT_BACKDOOR;
	close OUT_ADWARE;
	close OUT_VIRUS;
	close OUT_OTHER;

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
}


##################################################
#
# SOPHOS Scan
#
#####

sub LoadSOPHOSThreatInfo( )
{
	my $ini_file = "$tools_dir\\SOPHOS_ThreatNames.ini";

	my $debug_str = "\n Loading SOPHOS Threat name information ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

	open( IN, "< $ini_file" ) or die "\n FATAL Error: Can not locate SOPHOS_ThreatNames.ini. \n $! $ini_file !!! \n";
	my @data1 = <IN>;
	close IN;
	
	my $data = join( "", @data1 );	
	my @sections = split( /\[Section:/, $data );			                          
		
	my @replacements= split( /\n/, $sections[1] );		
	foreach my $entry ( @replacements )
	{
		if ( $entry =~ m/(.*)=(.*)\s*/ )
		{
			my $old = $1;
			my $rep = $2;
			$rep =~ s/\s+//;
			$SOPHOS_REPLACEMENT{ $old } = $rep;				
		}
	}	

	# load SOPHOS Backdoor
	@replacements= split( /\n/, $sections[2] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$SOPHOS_CATEGORY{ $1 } = "Backdoor";				
		}
	}	

	# load SOPHOS Trojan
	@replacements= split( /\n/, $sections[3] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$SOPHOS_CATEGORY{ $1 } = "Trojan";				
		}
	}	

	# load SOPHOS Worm
	@replacements= split( /\n/, $sections[4] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$SOPHOS_CATEGORY{ $1 } = "Worm";				
		}
	}	

	# load SOPHOS Adware
	@replacements= split( /\n/, $sections[5] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$SOPHOS_CATEGORY{ $1 } = "Adware";				
		}
	}	

	# load SOPHOS Virus	
	@replacements= split( /\n/, $sections[6] );	
	foreach my $entry ( @replacements )
	{		
		if( $entry =~ /\*(.*)\s*/ )
		{
			$SOPHOS_VIRUS{ $1 } = "Virus";				
		}		
	}	

	# load SOPHOS Skip
	@replacements= split( /\n/, $sections[7] );	
	foreach my $entry ( @replacements )
	{		
		if( $entry =~ /\*(.*)\s*/ )
		{
			$SOPHOS_SKIP{ $1 } = "Skip";				
		}
	}	

#	my @xlats = sort keys (%SOPHOS_REPLACEMENT);	
#	for my $key ( @xlats )
#	{
#		my $rep = $SOPHOS_REPLACEMENT{$key};
#		print "\n $key, $rep";
#	}	
#	
#	my @cats = reverse sort keys (%SOPHOS_CATEGORY);	
#	for my $key ( @cats)
#	{
#		my $rep = $SOPHOS_CATEGORY{$key};
#		print "\n CAT [$key], [$rep]";
#	}	
#
#	my @v = reverse sort keys (%SOPHOS_VIRUS);	
#	for my $key ( @v)
#	{
#		my $rep = $SOPHOS_VIRUS{$key};
#		print "\n VIRUS [$key], [$rep]";
#	}	
#
#	my @s = reverse sort keys (%SOPHOS_SKIP);	
#	for my $key ( @s)
#	{
#		my $rep = $SOPHOS_SKIP{$key};
#		print "\n SKIP [$key], [$rep]";
#	}	
	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
}

sub GetSOPHOS_xlat_Threatname( $ )
{
	my $threatname = shift;	
	
	my $xlat_name = $threatname;
	$xlat_name =~ s/\s//g;
	$xlat_name =~ s/-/./;
	
	my @xlats = sort ( keys ( %SOPHOS_REPLACEMENT ) );	
	for my $key ( @xlats )
	{
		my $rep = $SOPHOS_REPLACEMENT{ $key };
		#print "\n [$key], [$rep] ";
		if ( $xlat_name =~ s/$key/$rep/i )
		{
		}		
		#print "\n [$key], [$rep] ==> [$threatname], [$xlat_name]\n";
	}	

	$xlat_name =~ s/\!/\./;
	$xlat_name =~ s/\.$//;
	
	# make variant name as small	
	my @parts = split( /\./, $xlat_name );	
	my $len = @parts;
	if(( $len > 2 ) and ( $parts[-1] =~ m/([A-Z]{1,4})$/ ))
	{
		$parts[-1] = lc( $parts[-1] );
		$xlat_name = join( ".", @parts ); 
	}
	
	#print "\n===> $xlat_name ";
	return $xlat_name;
}


sub GetSOPHOS_Category( $ )
{
	my $xlat_name = shift;

  ########
  # check using: $xlat_name
  ####
  
  # check skip names first
	my @names = sort keys ( %SOPHOS_SKIP );	
	for my $key ( @names )
	{
		#print "[$xlat_name], [$key]\n";
		if ( $xlat_name =~ /^$key/i )
		{
			return $SOPHOS_SKIP{ $key };
		}		
	}

	# check if Backdoor, Trojan, Worm or Adware category
	@names = sort keys ( %SOPHOS_CATEGORY );	
	for my $key ( @names )
	{
		#print "[$xlat_name], [$key]\n";
		if ( $xlat_name =~ /$key/i )
		{
			return $SOPHOS_CATEGORY{ $key };
		}		
	}

  # check if threat name appears in Virus category
	@names = sort keys ( %SOPHOS_VIRUS );	
	for my $key ( @names )
	{
		#print "[$xlat_name], [$key]\n";
		if ( $xlat_name =~ /$key/i )
		{
			return $SOPHOS_VIRUS{ $key };
		}		
	}
	
	#print "\n$xlat_name, Unknown ";
	return "Unknown";
}


sub SOPHOSScan ( $ )
{
	my $src_dir = shift;		
	
	my $scan_log = "$logs_dir\\sophos.log";			
	
	my $debug_str = "\n Running SOPHOS Scanner : $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	
	unlink( $scan_log );
	my $command = "$tools_dir\\ntvirus\\SOPHOS\\sav32cli.exe $src_dir -f -s -ss -nc -nb -all -eec -v -mac -archive -idedir=$tools_dir\\ntvirus\\SOPHOS\\ides -p=$scan_log";
	my $output = qx( $command );												

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
}


sub SOPHOSScanSelfCheck ( $ )
{	
	my $src_dir = shift;			
	
	my $debug_str = "\n SOPHOS Scanner Self Check: $src_dir ...\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	
	my $command = "$tools_dir\\ntvirus\\SOPHOS\\sav32cli.exe $src_dir -f -ns -nc -nb -all -dn -ss -eec -v -mac -archive -idedir=$tools_dir\\ntvirus\\SOPHOS\\ides";
	my $output = qx( $command ); 	
	
	if( $output =~ m/Virus\s'EICAR-AV-Test'\sfound\sin\sfile/ )	
	{
		$debug_str = "\n Done.";
		print $debug_str;
		return 1;	
	}

	$debug_str = "\n FAILED !!!\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	return 0;
}


sub SOPHOSParseLog( )
{
	my $scan_log = "$logs_dir\\sophos.log";	
	
	my $debug_str = "\n Running SOPHOS Scanner log parser : $scan_log ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	
	open( IN, "< $scan_log" ) or die "\n\n Error: $! $scan_log !!! \n\n";		
	my @data = <IN>;
	close IN;
	
	my %SOPHOS_DETECTED;
	
	$scan_log = "$logs_dir\\sophos-parsed.csv";	
	open( OUT, "> $scan_log" ) or die "\n\nError: $! $scan_log\n";	
	foreach my $entry ( @data )
	{
		#print $entry;
		my $threatname = "";		
		my $path = "";
		
		if( $entry =~ m/'(.+)'\sfound\sin\sfile\s(.+)/i )
		{
			$path = $2;				
			$threatname = $1;					
		
			$path =~ s/(\\FILE:.*)//;
			$path =~ s/(\\SfxArchiveData\\.*)//;
			$path =~ s/(\\\/.*)//;

			if( $path =~ m/([0-9A-F]{32})/i )
			{
				my $md5 = $1;	
			
				my $xlat_name = GetSOPHOS_xlat_Threatname( $threatname );
				$SOPHOS_DETECTED{ $md5 } = "$threatname, $xlat_name";								
				print OUT "$path, $threatname\n";	
			}
		}
	}
	close OUT;

	my $sophos_trojan_log = "$logs_dir\\trojan-sophos.csv";	
	my $sophos_worm_log = "$logs_dir\\worm-sophos.csv";	
	my $sophos_backdoor_log = "$logs_dir\\backdoor-sophos.csv";	
	my $sophos_adware_log = "$logs_dir\\adware-sophos.csv";	
	my $sophos_virus_log = "$logs_dir\\virus-sophos.csv";	
	my $sophos_other_log = "$logs_dir\\other-sophos.csv";	
		
	open( OUT_TROJAN, "> $sophos_trojan_log" ) or die "\n\n Error: $! $sophos_trojan_log !\n";	
	open( OUT_WORM, "> $sophos_worm_log" ) or die "\n\n Error: $! $sophos_worm_log\n";	
	open( OUT_BACKDOOR, "> $sophos_backdoor_log" ) or die "\n\n Error: $! $sophos_backdoor_log\n";	
	open( OUT_ADWARE, "> $sophos_adware_log" ) or die "\n\n Error: $! $sophos_adware_log\n";	
	open( OUT_VIRUS, "> $sophos_virus_log" ) or die "\n\n Error: $! $sophos_virus_log\n";	
	open( OUT_OTHER, "> $sophos_other_log" ) or die "\n\n Error: $! $sophos_other_log\n";	

	my @sophos_detected = keys ( %SOPHOS_DETECTED );	
	for my $key ( @sophos_detected )
	{
		my $threatname = $SOPHOS_DETECTED{ $key };		
		my @names = split( /, /, $threatname );
		
		my $category = GetSOPHOS_Category( $names[1] );
		
		#print "$names[1], $category\n";
		
		# put into appropriate category
		if ( $category =~ m/^Trojan/i )
		{
			print OUT_TROJAN "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Worm/i )
		{
			print OUT_WORM "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Backdoor/i )
		{
			print OUT_BACKDOOR "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Adware/i )
		{
			print OUT_ADWARE "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Virus/i )
		{
			print OUT_VIRUS "$key, $threatname\n";		
		}				
		else
		{
			print OUT_OTHER "$key, $threatname\n";		
		}			
	}	
		
	close OUT_TROJAN;
	close OUT_WORM;
	close OUT_BACKDOOR;
	close OUT_ADWARE;
	close OUT_VIRUS;
	close OUT_OTHER;

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );											
}


##################################################
#
# PANDA Scan
#
#####

sub LoadPANDAThreatInfo( )
{
	my $ini_file = "$tools_dir\\PANDA_ThreatNames.ini";

	my $debug_str = "\n Loading PANDA Threat name information ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

	open( IN, "< $ini_file" ) or die "\n FATAL Error: Can not locate PANDA_ThreatNames.ini. \n $! $ini_file !!! \n";
	my @data1 = <IN>;
	close IN;
	
	my $data = join( "", @data1 );	
	my @sections = split( /\[Section:/, $data );			                          
		
	my @replacements= split( /\n/, $sections[1] );		
	foreach my $entry ( @replacements )
	{
		if ( $entry =~ m/(.*)=(.*)\s*/ )
		{
			my $old = $1;
			my $rep = $2;
			$rep =~ s/\s+//;
			$PANDA_REPLACEMENT{ $old } = $rep;				
		}
	}	

	# load PANDA Backdoor
	@replacements= split( /\n/, $sections[2] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$PANDA_CATEGORY{ $1 } = "Backdoor";				
		}
	}	

	# load PANDA Trojan
	@replacements= split( /\n/, $sections[3] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$PANDA_CATEGORY{ $1 } = "Trojan";				
		}
	}	

	# load PANDA Worm
	@replacements= split( /\n/, $sections[4] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$PANDA_CATEGORY{ $1 } = "Worm";				
		}
	}	

	# load PANDA Adware
	@replacements= split( /\n/, $sections[5] );	
	foreach my $entry ( @replacements )
	{
		if( $entry =~ /\*(.*)\s*/ )
		{
			$PANDA_CATEGORY{ $1 } = "Adware";				
		}
	}	

	# load PANDA Virus	
	@replacements= split( /\n/, $sections[6] );	
	foreach my $entry ( @replacements )
	{		
		if( $entry =~ /\*(.*)\s*/ )
		{
			$PANDA_VIRUS{ $1 } = "Virus";				
		}		
	}	

	# load PANDA Skip
	@replacements= split( /\n/, $sections[7] );	
	foreach my $entry ( @replacements )
	{		
		if( $entry =~ /\*(.*)\s*/ )
		{
			$PANDA_SKIP{ $1 } = "Skip";				
		}
	}	

#	my @xlats = sort keys (%PANDA_REPLACEMENT);	
#	for my $key ( @xlats )
#	{
#		my $rep = $PANDA_REPLACEMENT{$key};
#		print "\n $key, $rep";
#	}	
#	
#	my @cats = reverse sort keys (%PANDA_CATEGORY);	
#	for my $key ( @cats)
#	{
#		my $rep = $PANDA_CATEGORY{$key};
#		print "\n CAT [$key], [$rep]";
#	}	
#
#	my @v = reverse sort keys (%PANDA_VIRUS);	
#	for my $key ( @v)
#	{
#		my $rep = $PANDA_VIRUS{$key};
#		print "\n VIRUS [$key], [$rep]";
#	}	
#
#	my @s = reverse sort keys (%PANDA_SKIP);	
#	for my $key ( @s)
#	{
#		my $rep = $PANDA_SKIP{$key};
#		print "\n SKIP [$key], [$rep]";
#	}	
	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
}


sub GetPANDA_xlat_Threatname( $ )
{
	my $threatname = shift;	
	
	my $xlat_name = $threatname;
	$xlat_name =~ s/^\s+//;
	$xlat_name =~ s/\s+$//;
	
	my @xlats = sort ( keys ( %PANDA_REPLACEMENT ) );	
	for my $key ( @xlats )
	{
		my $rep = $PANDA_REPLACEMENT{ $key };
		#print "\n [$key], [$rep] ";
		if ( $xlat_name =~ s/$key/$rep/i )
		{
		}		
		#print "\n [$key], [$rep] ==> [$threatname], [$xlat_name]\n";
	}	

	$xlat_name =~ s/\!/\./;
	$xlat_name =~ s/\.$//;
	
	# make variant name as small	
	my @parts = split( /\./, $xlat_name );	
	my $len = @parts;
	
	#print "$xlat_name, $len, [ @parts ]";	
	if(( $len > 2 ) and ( $parts[-1] =~ m/([A-Z]{1,4})$/ ))
	{
		$parts[-1] = lc( $parts[-1] );
		$xlat_name = join( ".", @parts ); 
	}
	
	#print "\n===> $xlat_name ";
	return $xlat_name;
}


sub GetPANDA_Category( $ )
{
	my $xlat_name = shift;

  ########
  # check using: $xlat_name
  ####
  
  # check skip names first
	my @names = sort keys ( %PANDA_SKIP );	
	for my $key ( @names )
	{
		#print "[$xlat_name], [$key]\n";
		if ( $xlat_name =~ /^$key/i )
		{
			return $PANDA_SKIP{ $key };
		}		
	}

	# check if Backdoor, Trojan, Worm or Adware category
	@names = sort keys ( %PANDA_CATEGORY );	
	for my $key ( @names )
	{
		#print "[$xlat_name], [$key]\n";
		if ( $xlat_name =~ /$key/i )
		{
			return $PANDA_CATEGORY{ $key };
		}		
	}

  # check if threat name appears in Virus category
	@names = sort keys ( %PANDA_VIRUS );	
	for my $key ( @names )
	{
		#print "[$xlat_name], [$key]\n";
		if ( $xlat_name =~ /$key/i )
		{
			return $PANDA_VIRUS{ $key };
		}		
	}
	
	#print "\n$threatname, Unknown ";
	return "Unknown";
}


sub PANDAScan ( $ )
{
	my $src_dir = shift;		
	
	my $scan_log = "$logs_dir\\panda.log";			
	
	my $debug_str = "\n Running PANDA Scanner : $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	
	unlink( $scan_log );
	my $command = "$tools_dir\\ntvirus\\PANDA\\pavcl.exe $src_dir -cmp  -heu:3 -noscr -nos -rpt:$scan_log -aex -nomem";	
	my $output = qx( $command );												

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
}


sub PANDAScanSelfCheck ( $ )
{	
	my $src_dir = shift;			
	
	my $debug_str = "\n PANDA Scanner Self Check: $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	
	my $command = "$tools_dir\\ntvirus\\PANDA\\pavcl.exe $src_dir -cmp  -heu:3 -nos -aex -nomem";		
	my $output = qx( $command ); 	
		
	if( $output =~ m/Found\svirus\s:EICAR-AV-TEST-FILE/ )	
	{
		$debug_str = "\n Done.";
		print $debug_str;
		return 1;	
	}

	$debug_str = "\n FAILED !!!\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	return 0;
}


sub PANDAParseLog( )
{
	my $scan_log = "$logs_dir\\panda.log";	
	
	my $debug_str = "\n Running PANDA Scanner log parser : $scan_log ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	
	open( IN, "< $scan_log" ) or die "\n\n Error: $! $scan_log !!! \n\n";		
	my @data = <IN>;
	close IN;
	
	my %PANDA_DETECTED;
	
	$scan_log = "$logs_dir\\panda-parsed.csv";	
	open( OUT, "> $scan_log" ) or die "\n\nError: $! $scan_log\n";	
	
	my $t = join( "\n", @data);
	my @data1 = split(/[-]{51}/, $t);
		
	foreach my $entry ( @data1 )
	{
		#print $entry;
		my $threatname = "";		
		my $path = "";
		
		if( $entry =~ m/File\schecked\s+:\s(.+)/i )
		{
			$path = $1;							
		}
		
		$path =~ s/(\[.*\])*$//;
				
		if( $entry =~ m/Found\s.+\s+:(.+)/i )
		{
			$threatname = $1;
		}
		
		#print "$path, $threatname\n";					
		if( $path && $threatname )
		{
			if( $path =~ m/([0-9A-F]{32})/i )
			{
				my $md5 = $1;
		
				my $xlat_name = GetPANDA_xlat_Threatname( $threatname );
				$PANDA_DETECTED{ $md5 } = "$threatname, $xlat_name";
				print OUT "$md5, $threatname, $xlat_name\n";					
			}
		}
	}
	close OUT;


	my $panda_trojan_log = "$logs_dir\\trojan-panda.csv";	
	my $panda_worm_log = "$logs_dir\\worm-panda.csv";	
	my $panda_backdoor_log = "$logs_dir\\backdoor-panda.csv";	
	my $panda_adware_log = "$logs_dir\\adware-panda.csv";	
	my $panda_virus_log = "$logs_dir\\virus-panda.csv";	
	my $panda_other_log = "$logs_dir\\other-panda.csv";	
		
	open( OUT_TROJAN, "> $panda_trojan_log" ) or die "\n\n Error: $! $panda_trojan_log !\n";	
	open( OUT_WORM, "> $panda_worm_log" ) or die "\n\n Error: $! $panda_worm_log\n";	
	open( OUT_BACKDOOR, "> $panda_backdoor_log" ) or die "\n\n Error: $! $panda_backdoor_log\n";	
	open( OUT_ADWARE, "> $panda_adware_log" ) or die "\n\n Error: $! $panda_adware_log\n";	
	open( OUT_VIRUS, "> $panda_virus_log" ) or die "\n\n Error: $! $panda_virus_log\n";	
	open( OUT_OTHER, "> $panda_other_log" ) or die "\n\n Error: $! $panda_other_log\n";	

	my @panda_detected = keys ( %PANDA_DETECTED );	
	for my $key ( @panda_detected )
	{
		my $threatname = $PANDA_DETECTED{ $key };		
		my @names = split( /, /, $threatname );
		
		my $category = GetPANDA_Category( $names[1] );
		
		#print "$names[1], $category\n";
		
		# put into appropriate category
		if ( $category =~ m/^Trojan/i )
		{
			print OUT_TROJAN "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Worm/i )
		{
			$threatname =~ s/(\.worm)$//;
			
			# make variant name as small	
			my @parts = split( /\./, $threatname );	
			my $len = @parts;			
			
			if(( $len > 2 ) and ( $parts[-1] =~ m/([A-Z]{1,4})$/ ))
			{
				$parts[-1] = lc( $parts[-1] );
				$threatname = join( ".", @parts ); 
			}			
			
			print OUT_WORM "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Backdoor/i )
		{
			print OUT_BACKDOOR "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Adware/i )
		{
			print OUT_ADWARE "$key, $threatname\n";		
		}				
		elsif ( $category =~ m/^Virus/i )
		{
			print OUT_VIRUS "$key, $threatname\n";		
		}				
		else
		{
			print OUT_OTHER "$key, $threatname\n";		
		}			
	}	
		
	close OUT_TROJAN;
	close OUT_WORM;
	close OUT_BACKDOOR;
	close OUT_ADWARE;
	close OUT_VIRUS;
	close OUT_OTHER;

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
}


sub AddSecondaryDetections( )
{
	my @category = ( "trojan", "backdoor", "worm", "adware"	);
	my @avs = ( "eset", "bitdef", "sophos", "panda" );
	
	my $debug_str = "\n Adding Secondary Detections ...\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
	
	my %DETECTIONS;
	
	for my $d1 ( @avs ) 
	{
		for my $d2 ( @category ) 
		{
			my $filename = "$d2-$d1.csv";
			#print "$filename\n";
			
			open( IN, "< $logs_dir\\$filename" ) or die "\n\n Error: $! $filename !!! \n\n";		
			my @data = <IN>;
			close IN;
	
			for my $d3 ( @data )		
			{
				chomp( $d3 );
				$d3 =~ s/\s//g;
				my @a = split( /,/, $d3 );
				my $len = @a;
				if ( $len == 3 )
				{
					my $md5 = lc( $a[0] );
					
					if ( exists ( $DETECTIONS{ $md5 } ) )
					{
						my $t = $DETECTIONS{ $md5 };
						$DETECTIONS{ $md5 } = "$t,$a[1],$a[2],$d2";
					}
					else
					{
						$DETECTIONS{ $md5 } = "$a[1],$a[2],$d2";
					}					
				}				
			}			
		}
	}

	my $trojan_log = "$logs_dir\\trojan-2.csv";	
	my $worm_log = "$logs_dir\\worm-2.csv";	
	my $backdoor_log = "$logs_dir\\backdoor-2.csv";	
	my $adware_log = "$logs_dir\\adware-2.csv";	
		
	open( OUT_TROJAN, "> $trojan_log" ) or die "\n\n Error: $! $trojan_log !\n";	
	open( OUT_WORM, "> $worm_log" ) or die "\n\n Error: $! $worm_log\n";	
	open( OUT_BACKDOOR, "> $backdoor_log" ) or die "\n\n Error: $! $backdoor_log\n";	
	open( OUT_ADWARE, "> $adware_log" ) or die "\n\n Error: $! $adware_log\n";	

	my @d4 = sort keys ( %DETECTIONS );	
	for my $key ( @d4 )
	{
		my $t = $DETECTIONS { $key };
		my @a = split( /,/, $t );
		my $len = @a;
		$len = $len / 3;
		
		if( $len >= 2 )
		{
			my $threatname = "$a[0],$a[1]";			
			my $category = $a[2];
			
			#print "$threatname, $category\n";
			
			# put into appropriate category
			if ( $category =~ m/^trojan/i )
			{
				print OUT_TROJAN "$key, $threatname\n";		
			}				
			elsif ( $category =~ m/^worm/i )
			{
				print OUT_WORM "$key, $threatname\n";		
			}				
			elsif ( $category =~ m/^backdoor/i )
			{
				print OUT_BACKDOOR "$key, $threatname\n";		
			}				
			elsif ( $category =~ m/^adware/i )
			{
				print OUT_ADWARE "$key, $threatname\n";		
			}										
		}		
	}		

	close OUT_TROJAN;
	close OUT_WORM;
	close OUT_BACKDOOR;
	close OUT_ADWARE;

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );											
	
}


##################################################
#
# General Functions 
#
#####

sub ReportInfo($)
{
	my $infile = shift;		
	my $ua = LWP::UserAgent->new;
	
	my $debug_str = "\n Reporting MD5s to Sample Information Server ... ";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );											
		
	open( IN, "< $infile" );	
	my @data = <IN>;
	close IN;
		
	foreach my $entry ( @data )
	{		
		my @parts = split( /,\s*/, $entry );
		
		if( $parts[0] =~ /([0-9A-F]{32})/i )
		{
			my $md5  = uc( $1 );
			my $sha1 = uc( $parts[1] );
			my $sha2 = uc( $parts[2] );
			my $filesize = $parts[5];
						
			my $url = "$sample_server?MD5=$md5&SHA1=$sha1&SHA2=$sha2&SOURCE=$source";
			# TYPE=$type&SIZE=$size&SOURCE=$source&QHDET=$qhdet&KAVDET=$kavdet&MSDET=$msdet&PACKAGE=$package
						
			if( exists( $FILE_TYPE{ $md5 } ) )
			{
				$url = $url . "&TYPE=" . $FILE_TYPE{ $md5 };
			}
			
			$url = $url . "&SIZE=" . $filesize;

			if( exists( $QH_DETECTED{ $md5 } ) )
			{
				$url = $url . "&QHDET=" . $QH_DETECTED{ $md5 };
			}

			if( exists( $KAV_DETECTED{ $md5 } ) )
			{
				my @a = split( /,/ , $KAV_DETECTED{ $md5 } );
				$url = $url . "&KAVDET=" . $a[0];
			}

			if( exists( $MSAV_DETECTED{ $md5 } ) )
			{
				my @a = split( /,/ , $MSAV_DETECTED{ $md5 } );
				$url = $url . "&MSDET=" . $a[0];
			}

			if( exists( $KAV_PACKED{ $md5 } ) )
			{
				$url = $url . "&PACKAGE=" . $KAV_PACKED{ $md5 };
			}

			if( exists( $KAV_ARCHIVE{ $md5 } ) )
			{
				$url = $url . "&PACKAGE=" . $KAV_ARCHIVE{ $md5 };
			}			  
						                                                                         
			my $request = HTTP::Request->new(GET => $url);
			my $response = $ua->request($request);
			
			if ($response->is_success) 
			{
			    if ( $response->decoded_content =~ /INSERT INTO tbl_sampleshare_samples/) 
			    {
						# SUCCESS
						#print "$md5, reported\n";
			    }
			    else
			    {
			    	print "$md5, $sha2, $response->decoded_content\n";					
			    }
			}
			else
			{			
				print "$md5, $sha2, Error: ", $response->status_line, "\n";					
			}
		}
	}

	$debug_str = "\n Done. ";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );											
	
	return;
}

                     
sub RenamewithMD5( $$ );

sub RenamewithMD5( $$ )
{
	my $src_dir = shift;
	my $dst_dir = shift;
		
	my $src_file = "";
	my $dst_file = "";
	
	my $debug_str = "\n Copying files with MD5 : $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, "  $debug_str" );

	opendir( SRCDIR, $src_dir ) or die "\n\n Error: $src_dir $! !!! \n\n";			
	my( @files ) = grep( !/^\./, readdir( SRCDIR ));
	closedir( SRCDIR );	
	my $md5;		
	
	for my $filename ( @files )
	{
		$src_file = "$src_dir\\$filename";	    
    stat( $src_file );           
    RenamewithMD5( $src_file, $dst_dir ) if ( -d $src_file );	
     
    open( FILE, $src_file ) or next;
    binmode( FILE );
    $md5 = Digest::MD5->new->addfile( *FILE )->hexdigest;
    close FILE;    

    open( FILE, $src_file ) or next;
    binmode( FILE );     
    my $oSha1 = Digest::SHA->new("SHA-1");
    my $sha1 = $oSha1->addfile( *FILE )->hexdigest;
    close FILE;

    open( FILE, $src_file ) or next;
    binmode( FILE );     
    my $oSha = Digest::SHA->new("SHA256");
    my $sha2 = $oSha->addfile( *FILE )->hexdigest;
    close FILE;
            
    $dst_file = "$dst_dir\\$md5";    
		open FH, ">> $logs_dir\\sample-md5.csv"  or die "\n\n Error: $! $logs_dir\\sample-md5.csv\n";	
		print FH $md5, ", $sha1, $sha2, $src_file, $filename, ", -s $src_file, ", \n";    		   
		close FH;
    copy( $src_file, $dst_file );    
	}			
}


sub RunTrID( $ )
{
	my $src_dir = shift;		
	
	my $debug_str = "\n Running TrID: $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

	if(! ( -e "$tools_dir\\TrID\\trid.exe" ) )
	{
		$debug_str = "\n FATAL Error: $tools_dir\\TrID\\trid.exe not found !!! \n";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str );		
		exit;
	}

	my $command = "$tools_dir\\TrID\\trid.exe $src_dir\\*.* > $logs_dir\\trid.log";					
	my $output = qx( $command );													
	
	# parse TrID output 
	open( IN, "<$logs_dir\\trid.log" ) or die "\n\n Error: $! $logs_dir\\trid.log !!! \n\n";			
	my @data = <IN>;
	close IN;
	
	my $data1 = join( "\n", @data );	
	my @entries = split( /File:\s*/, $data1 );	
	my $len =  @entries;
	$len = $len - 1;
	$debug_str = "\n Entries: " . $len;
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	open FH, "> $logs_dir\\trid-parsed.csv" or die "\n\n Error: $! $logs_dir\\trid-parsed.csv";
	print FH "file, extension, TrID\n";    
		
	foreach my $entry ( @entries )
	{
		if ( $entry =~ /(.*)\s+[0-9\.\%]+\s+\(\.([^\s]*)\)\s+([^\(]+)/g )
		{
			print FH "$1, $2, $3,\n"
		}
	}

	close FH;	
	
	$debug_str = "\n Done.\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
}


sub Run7Zip( $$ )
{
	my $src_dir = shift;		
	my $out_dir = shift;
	
	my $debug_str = "\n\n Running 7Zip: $src_dir ...\n";		
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );
	
	if(! ( -e "$tools_dir\\7-Zip\\7z.exe" ) )
	{
		$debug_str = " FATAL Error: $tools_dir\\7-Zip\\7z.exe not found !!! \n";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str );		
		exit;
	}

	my $command = "$tools_dir\\7-Zip\\7z.exe x $src_dir -o$out_dir -pinfected -y";					
	my $output = qx( $command );							
	WriteToLog( $debug_log, $output );							

	$debug_str = " Done.\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
}


sub RunFileType( $$ )
{
	my $src_dir = shift;		
	my $out_file = shift;
	
	my $debug_str = "\n\n Running FileType: $src_dir ...\n";		
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );
	
	if(! ( -e "$tools_dir\\mpa_filetype.exe" ) )
	{
		$debug_str = " FATAL Error: $tools_dir\\mpa_filetype.exe not found !!! \n";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str );		
		exit;
	}

	my $command = "$tools_dir\\mpa_filetype.exe /rd $src_dir> $out_file";						
	#print "$command\n";
	
	my $output = qx( $command );							

	$debug_str = " Done.\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
}


sub RunPEiD( $ )
{
	my $src_dir = shift;		
	
	my $debug_str = "\n Running PEiD: $src_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

	opendir( SRCDIR, $src_dir ) or return;
	my( @files ) = grep( !/^\./, readdir( SRCDIR ));
	closedir( SRCDIR );	
		
	open FH, "> $logs_dir\\peid-parsed.csv";
	print FH "file, PEiD, Section, EPOffset, Linker, SubSystem, \n";	
	for my $filename ( @files )
	{
		my $src_file = "$src_dir\\$filename";	
		if ( -f $src_file )	
		{			
			unlink( "$logs_dir\\PEiDOutput.TXT" );
			
			my $command = "$tools_dir\\PEiD\\peid.exe $src_file -Save -QuitAfter -IDPath:$logs_dir";					
			my $output = qx( $command );													
			
			# parse PEiD output 
			open( IN, "<$logs_dir\\PEiDOutput.TXT" ) or die "\n\n Error: $! $logs_dir\\PEiDOutput.TXT !!! \n\n";				
			my @data = <IN>;
			close IN;
			
			my $data1 = join( "\n", @data );
			if( $data1 =~ /(.*)\s+Section:\s+(.*)\s+EPOffset:\s+([0-9A-F]+)\s+Linker\sInfo:\s+([0-9\.]+)\s+SubSystem:\s+(.*)\s*/i )
			{
				my $filetype = $1;
				my $section = $2;
				my $epoffset = $3;
				my $linker = $4;
				my $subsystem = $5;
				
				$filetype =~ s/,//;
				
				print FH "$src_file, $filetype, $section, $epoffset, $linker, $subsystem, \n";				
			}
		}
	}
		
	close FH;	
	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );											
}


sub RunSigCheck( $ )
{
	my $src_dir = shift;		
	my $log_file = "$logs_dir\\mpa_sigcheck.csv";
	my $signed_list = "$logs_dir\\signed-files.csv";
	my $version_ms_list = "$logs_dir\\version-ms.csv";
	
	my $debug_str = "\n\n Running Sigcheck: $src_dir ...\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

	if (! ( -e "$tools_dir\\mpa_sigcheck.exe" ) )
	{
		$debug_str = "\n FATAL Error: $tools_dir\\mpa_sigcheck.exe not found !!! \n";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str );		
		exit;
	}
	
	my $command = "$tools_dir\\mpa_sigcheck.exe -a -v -q $src_dir\\*.* > $log_file";					
	my $output = qx( $command );													

	# Get signed files 
	open( IN, "<$log_file" )  or die "\n\n Error: $! $log_file !!! \n\n";				
	open FH, "> $signed_list" or die "\n\n Error: $! $signed_list !!! \n\n";				
	open FH1, "> $version_ms_list" or die "\n\n Error: $! $version_ms_list !!! \n\n";				
		
	foreach my $entry ( <IN> )
	{				
		chomp $entry;
		my @parts = split( /","/, $entry );		
		my $len = @parts;
				
		my  $md5 = "";
		if ( $parts[0] =~ /([0-9A-F]{32})/i )
		{
			$md5 = uc ( $1 );			
			my $info = "";
			my $skip = 1;
			foreach my $d (@parts)
			{
			 	# skip first entry
				if( $skip == 0)
				{
					$info = "$info , $d";
				}
				else
				{
					$skip = 0
				}							
			}			
			$SIGCHECK_DATA { $md5 } = $info;
		}				
				
		$entry = "$entry\n";			
		if ( $len > 2 && $parts[1] =~ m/\"Signed\"/ )
		{
			print FH $entry;
		} 		
		# Check if 'Publisher' contains Microsoft
		elsif ( $len >= 4 && $parts[3] =~ m/Microsoft/ )
		{
			print FH1 $entry;
		}# Check if 'Description' contains Microsoft
		elsif ( $len >= 5 && $parts[4] =~ m/Microsoft/ )
		{
			print FH1 $entry;
		} # Check if 'Product' contains Microsoft
		elsif ( $len >= 6 && $parts[5] =~ m/Microsoft/ )
		{
			print FH1 $entry;
		} # Check if 'File version' contains Microsoft
		elsif ( $len >= 8 && $parts[7] =~ m/Microsoft/ )
		{
			print FH1 $entry;			
		} # Check if 'Copyright' contains Microsoft
		elsif ( $len >= 12 && $parts[11] =~ m/Microsoft/ )
		{
			print FH1 $entry;
		}		
	}
	
	close IN;
	close FH;		
	close FH1;			
	
	$debug_str = " Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
}	


sub GetVersionInfo( $ )
{
	my $in_file = shift;
	my $version_file = "$logs_dir\\version-bulk-add.csv";
                  
	my $debug_str = "\n Getting version information for $in_file ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
                                                                             
	open( IN, "< $in_file" ) or return 0;	
	open( OUT, ">> $version_file" ) or die "\n\n Error: $! $version_file !!! \n\n";					
	
	my @data = <IN>;
	close IN;

	foreach my $entry ( @data )
	{			
		if ( $entry =~ m/([0-9A-F]{32})\s+(.*)\s*/i )
		{
			my $md5 = uc( $1 );						
			my $threatname = $2; 
			#print "$md5, $threatname\n";
			if( exists ( $SIGCHECK_DATA{ $md5 } ) )
			{
				 my $ver = $SIGCHECK_DATA{ $md5 }; 
				 print OUT "$md5, $threatname $ver\n";
			}
			else
			{
				 print OUT "$md5, $threatname, NO VERSION INFO\n";
			}
		}
	}	
	
	close OUT;
	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								
}


sub MoveSignedFiles( )
{
	my $csv_file = "$logs_dir\\signed-files.csv";	
	my $dst_dir = "$out_dir\\signed";	
	
	my $debug_str = "\n Moving signed files : $dst_dir ...";	
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	open( IN, "< $csv_file" );
	my @data = <IN>;
	close IN;
		
	foreach my $entry ( @data )
	{		
		my @parts = split( /,/, $entry );				
		my $filename = $parts[0];
		if( $parts[0] =~ /\"(.*)\"/ ) 
		{
			$filename = $1;
		}
		#print "$filename ==> $dst_dir\n";
		move( $filename, $dst_dir );			
	}
	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	$csv_file = "$logs_dir\\version-ms.csv";
	$dst_dir = "$out_dir\\version-ms";	
		
	$debug_str = "\n Moving files with Microsoft Version : $dst_dir ...";	
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	open( IN, "< $csv_file" );	
	@data = <IN>;
	close IN;
		
	foreach my $entry ( @data )
	{		
		my @parts = split( /,/, $entry );				
		my $filename = $parts[0];
		if( $parts[0] =~ /\"(.*)\"/ ) 
		{
			$filename = $1;
		}
		#print "$filename ==> $dst_dir\n";
		move( $filename, $dst_dir );			
	}	
	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
}


sub CreateLog ( $$ )
{
	my $log_filename = shift;
	my $data = shift;	
	open( LOG, "> $log_filename" ) or die "\n$log_filename, $!";
	printf LOG "\n Malware Processing Automation  $now_string\n\n";
	printf LOG $data;
	
	close LOG;	
}


sub WriteToLog( $$ )
{
	my $log_filename = shift;
	my $data = shift;
	open( LOG, ">> $log_filename" ) or return;	
	print LOG $data;
	close LOG;
}


sub CreateDirectoryStructure ( $ )
{
	my $root = shift;		
	#my @dirs = ("logs", "reports", "undetected", "archives", "bulk-add", "nonpe-add", "infectors", "qh-detected", "signed", "version-ms", "skip", "packer-exclusion", "for-generic" );
	my @dirs = ("logs", "reports", "undetected", "archives", "bulk-add", "bulk-add-2", "nonpe-add", "infectors",  "qh-detected", "skip", "for-generic", "symc-generic", "7zip-extracted", "corrupt", "packers");
	
	print "\n Creating output directory structure ...\n\n";
	my $ret = rmtree(	$root, 	{error => \my $err} );		
	
  for my $diag ( @$err ) {
    my ( $file, $message ) = each %$diag;
    print "problem unlinking $file: $message\n";    
  }
	
	mkpath( "$root", {verbose => 1, cleanup => 1} );	
	chdir "$root";
  
  for ( @dirs ) { mkpath( "$_", {verbose => 1} ); }
  
  CreateLog( $debug_log, " Creating output directory structure ...\n" );
  WriteToLog( $debug_log, " Done.\n\n" ); 
  my $debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

}


sub MoveDetectedSamples( $$ )
{	
	my $scan_log = shift; 
	my $dst_dir = shift;
	
	my $debug_str = "\n Moving detected files : $dst_dir ...";	
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

	open( IN, "< $scan_log" );	
	my @data = <IN>;
	close IN;
		
	foreach my $entry ( @data )
	{
		my $threatname = "";		
		if ( $entry =~ m/(.+),\s*(.*)/ )
		{
			my $src_file = $1;
			my $threatname = 	$2;

			if ( -e $src_file ) # if source file exists
			{			
				if ( $src_file =~ m/([0-9A-F]{32})/i )			
				{
					my $md5 = uc( $1 );
					my $category = "UNKNOWN";
					if ( exists( $FILE_TYPE{$md5} ))
					{
						$category = $FILE_TYPE{ $md5 };
						#$category =~ s/-/\\/;
						$category =~ s/-.+//;
					}
					
					$threatname =~ s/\./\\/g; 			
					$threatname =~ s/\//\\/g; 			
					$threatname =~ s/://g;
					$threatname =~ s/\s//g;
					
					my $dst_file = "$dst_dir\\$category\\$threatname"; 															
					
					mkpath( $dst_file );
					
					move( $src_file, "$dst_file\\$md5" );			
					
					print "\nMOVE: $src_file==> $dst_file\\$md5 ";
				}
			}
		}
	}			
	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
}


sub MoveUnDetectedSamples( $$ )
{	
	my $scan_log = shift; 
	my $dst_dir = shift;
	
	my $debug_str = "\n Moving undetected files : $dst_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							
	
	open( IN, "< $scan_log" );	
	my @data = <IN>;
	close IN;
	
	my %DETECTED;		
	foreach my $entry ( @data )
	{
		if ( $entry =~ m/([0-9A-F]{32})/i )
		{
			my $md5 = uc( $1 );			
			$DETECTED{ $md5 } = "AVIRA-Detected";
		}
	}			

	my $src_dir = "$out_dir\\undetected";
	opendir( SRCDIR, $src_dir ) or die "\n\n Error: MoveUnDetectedSamples : $src_dir $! !!! \n\n";			
	my( @files ) = grep( !/^\./, readdir( SRCDIR ));
	closedir( SRCDIR );		
	
	for my $filename ( @files )
	{
		my $src_file = "$src_dir\\$filename";			
		$filename = uc( $filename );
		if( !( exists ( $DETECTED{ $filename } )))
		{			
			move ( $src_file, $dst_dir );
		}
	}		
	
	$debug_str = "\n Done.\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								
}


sub MoveFiles( $$ )
{
	my $log_file = shift;
	my $dst_dir = shift;
	
	my $debug_str = "\n Moving files : $dst_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								
	
	open( IN, "< $log_file" ) or return;	
	my @data = <IN>;
	close IN;
		
	
	open( OUT, "> $log_file" ) or return;		
	
	foreach my $entry ( @data )
	{			
		if ( $entry =~ m/([0-9A-F]{32}),\s*(.*)/i )
		{
			my $md5 = uc( $1 );
			my $filetype = $2;
			my $src_file = "$out_dir\\undetected\\$md5";		

			if ( -e $src_file ) # if source file exists
			{						
				my $category = "UNKNOWN";
				if ( exists( $FILE_TYPE{ $md5 } ))
				{
					$category = $FILE_TYPE{ $md5 };
					$category =~ s/-/\\/;
				}
				
				# DO NOT move PE Archive files
				if ( ! ($category =~ /^PE/) )
				{				
					my $dst_file = "$dst_dir\\$category\\$filetype"; 										
					mkpath( $dst_file );
					
					print OUT $entry;
						
					move( $src_file, "$dst_file\\$md5" );			
				}
			}
		}
	}			

	close OUT;
	
	$debug_str = "\n Done.\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );									
}


sub MovePEFiles( $$ )
{
	my $log_file = shift;
	my $dst_dir = shift;
	
	my $debug_str = "\n Moving PE files : $dst_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								
	
	open( IN, "< $log_file" ) or return;	
	my @data = <IN>;
	close IN;
		
	foreach my $entry ( @data )
	{			
		if ( $entry =~ m/(.+),\s*(.+),/i )
		{
			my $src_file = $1;
			my $filetype = $2;

			if ( ($filetype =~ /^PE/) )
			{
				if ( -e $src_file ) # if source file exists
				{						
			    open( FILE, $src_file ) or next;
			    binmode( FILE );
			    my $md5 = Digest::MD5->new->addfile( *FILE )->hexdigest;
			    close FILE;
					
					$debug_str = "Copy: $src_file ==> $dst_dir\\$md5 \n" ;
					WriteToLog( $debug_log, $debug_str );													

			    open( FILE, $src_file ) or next;
			    binmode( FILE );     
			    my $oSha1 = Digest::SHA->new("SHA-1");
			    my $sha1 = $oSha1->addfile( *FILE )->hexdigest;
			    close FILE;
			
			    open( FILE, $src_file ) or next;
			    binmode( FILE );     
			    my $oSha = Digest::SHA->new("SHA256");
			    my $sha2 = $oSha->addfile( *FILE )->hexdigest;
			    close FILE;
			    			    
					open FH, ">> $logs_dir\\sample-md5.csv"  or die "\n\n Error: $! $logs_dir\\sample-md5.csv\n";	
					print FH $md5, ", $sha1, $sha2, $src_file, , ", -s $src_file, ", \n";    		   
					close FH;					
					
					move( $src_file, "$dst_dir\\$md5" );			
				}
			}				
		}
	}			
	
	$debug_str = "\n Done.\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );									
}


sub MoveFilesWithThreatName( $$ )
{
	my $log_file = shift;
	my $dst_dir = shift;
	
	my @parts = split( /\\/, $log_file );
	my @parts1 = split( /-/, $parts[-1] );
	my $type = uc ( $parts1[0] );
	my $final = "$reports_dir\\$type.txt";
	my $nonpe = "$reports_dir\\NON-PE.txt";
		
	my $debug_str = "\n Moving $type files : $dst_dir ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								
	
	open( IN, "< $log_file" );	
	my @data = <IN>;
	close IN;
	
	open( OUT, ">> $final" );	
	open( OUT1, ">> $nonpe" );	
	
	foreach my $entry ( @data )
	{			
		chomp( $entry );
				
		my @parts = split( /,\s*/, $entry );
		my $nLen = @parts;
#		print "MoveFilesWithThreatName: nLen ($nLen) $entry\n";

		if ( 3 == $nLen || 4 == $nLen)
		{
			my $md5 = uc( $parts[0] );
			my $threatname = $parts[2];
			my $temp_threatname = $threatname;
			$threatname =~ s/\./\\/g; 			
			
#			print "MoveFilesWithThreatName: md5 ($md5) $threatname\n";
			my $src_file = "$out_dir\\undetected\\$md5";		
			
#			print "MoveFilesWithThreatName: srcfile ($src_file)\n";
			if ( -e $src_file ) # if source file exists
			{
				my $category = "UNKNOWN";
				if ( exists( $FILE_TYPE{ $md5 } ))
				{
					$category = $FILE_TYPE{ $md5 };
					#$category =~ s/-/\\/;
					$category =~ s/-.*//;					
				}
				
				my $dst_file = "";
				my $sub_dir = "";
				if( $category =~ m/^PE/ )
				{
					if ( $nLen == 4 )
					{
						my $packer = $parts[3];
						$sub_dir = "$dst_dir\\$packer\\$category\\$threatname";
					}
					else
					{
						$sub_dir = "$dst_dir\\$category\\$threatname";
					}
					$dst_file = "$sub_dir\\$md5";
					printf OUT "%-100s %s\n", $dst_file, $temp_threatname;
				}
				else
				{
					$sub_dir = "$out_dir\\nonpe-add\\$category\\$threatname";
					$dst_file = "$sub_dir\\$md5";					
					printf OUT1 "%-100s %s\n", $dst_file, $temp_threatname;
				}
				
#				print "MoveFilesWithThreatName: dstfile ($dst_file)\n";
#				print $sub_dir;
				mkpath( $sub_dir );
				
#				print " $src_file==> $dst_file\\$md5\n";
				move( $src_file, "$dst_file" );			
				
			}
		}
	}			
	
	close ( OUT );
	close ( OUT1 );

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );										
}


sub MoveCorruptFiles( $$ )
{
	my $src_dir = shift;
	my $dst_dir = shift;

	my $debug_str = "\n\n Moving Corrupt files ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								

	if( -d $src_dir && -d $dst_dir )
	{
		opendir( SRCDIR, $src_dir ) or die "\n\n Error: $src_dir $! !!! \n\n";			
		my( @files ) = grep( !/^\./, readdir( SRCDIR ));
		closedir( SRCDIR );	
		
		for my $filename ( @files )
		{
			my $src_file = "$src_dir\\$filename";
			my %type = readFileType($src_file);
			my $file_type = $type{'info'} . "\n";
	
			if( $file_type =~ /corrupted\/obfuscated sections/ )		
			{
				$debug_str = "\n $filename, Corrupt File";
				print $debug_str;
				WriteToLog( $debug_log, $debug_str );								
				
				move( $src_file, $dst_dir );			
			}
		}
	}

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								
	
}


sub MoveAsFileType( $$ )
{
	my $src_dir = shift;
	my $dst_dir = shift;

	my $debug_str = "\n MoveAsFileType: $src_dir";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								

	opendir( SRCDIR, $src_dir ) or die "\n\n Error: $src_dir $! !!! \n\n";			
	my( @files ) = grep( !/^\./, readdir( SRCDIR ));
	closedir( SRCDIR );	

	for my $filename ( @files )
	{		
		$filename = uc($filename);
		my $src_file = "$src_dir\\$filename";	    
		
		next if( -d $src_file);			

#			print "MoveAsFileType: srcfile ($src_file)\n";
			if ( -e $src_file ) # if source file exists
			{
				my $category = "UNKNOWN";
				if ( exists( $FILE_TYPE{ $filename } ))
				{
					$category = $FILE_TYPE{ $filename };
					#$category =~ s/-/\\/g;
					$category =~ s/-.+//g;					
					$category =~ s/_/\\/g;					
				}
				
				my $dst_file = "";
				my $sub_dir = "";
				if( $category =~ m/^PE/ )
				{				
					#print "$filename, $category \n";
					if( exists( $KAV_PACKED{ $filename } ))
					{
						my $packer = $KAV_PACKED{ $filename };						
						#print "$filename, $packer \n";						
						$sub_dir = "$dst_dir\\$category\\$packer";						
					}
					else
					{
						$sub_dir = "$dst_dir\\$category";
					}
					$dst_file = "$sub_dir\\$filename";
					#printf OUT "%-100s %s\n", $dst_file;
					#printf "%-100s %s\n", $dst_file;
				}
				else
				{
					$sub_dir = "$dst_dir\\non-PE\\$category";
					$dst_file = "$sub_dir\\$filename";					
					#printf OUT1 "%-100s \n", $dst_file;
					#printf "%-100s \n", $dst_file;
				}
				
#				print "MoveAsFileType: dstfile ($dst_file)\n";
#				print $sub_dir;
				mkpath( $sub_dir );
				
#				print " $src_file==> $dst_file\\$filename\n";
				move( $src_file, "$dst_file" );							
			}		
	}		
	
	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								
	
}


sub readFileType
{
	my %ret;
	my $filename = shift;
	my $fsiz     = -s $filename;
	my $data;

	$ret{'info'}='Unknown';
	if (!-f $filename) { return %ret; }
	my $keywords="if|then|while|loop|for|left|mid|right|eval|alert|find|replace|\.write|unescape";

	open    (FILE, '<'.$filename);
	binmode (FILE);
	read    (FILE, $data, 512);
	close   (FILE);
	#print $data;
	   if ($data =~ /^MSCF/)             { $ret{'info'}="MSCF -> CAB file"; return %ret; }
	elsif ($data =~ /^PK/)               { $ret{'info'}="PK -> ZIP file"; return %ret; }
	elsif ($data =~ /^Rar!/)             { $ret{'info'}="Rar! -> RAR file"; return %ret; }
	elsif ($data =~ /^SZDD/)             { $ret{'info'}="SZDD -> MS compress file"; return %ret; }
	elsif ($data =~ /^\x1F\x8B/)         { $ret{'info'}="MSI -> MSI file"; return %ret; }
	#elsif ($data =~ /^\xD0\xCF\x11\xE0/) { $ret{'info'}="OLE -> MS DOC,XLS,PPT,MSG etc..."; return %ret; }
	elsif ($data =~ /^<!D/) { $ret{'info'}="HTML/XML"; return %ret; }
	elsif ($data =~ /^<\?xml/) { $ret{'info'}="XML"; return %ret; }
	elsif ($data =~ /^<html/i) { $ret{'info'}="HTML"; return %ret; }

	elsif ($data =~ /\[[a-z0-9 _-]{4,}\].*[\r\n].*\[[a-z0-9 _-]{4,}\].*[\r\n].*\[[a-z0-9 _-]{4,}\]/si) { $ret{'info'}="INI"; return %ret; }
	elsif ($data =~ /:.*del .*if exist .*goto/si) { $ret{'info'}="BAT-deleting script"; return %ret; }
	elsif ($data =~ /echo off.*if exist/si) { $ret{'info'}="BAT"; return %ret; }
	elsif ($data =~ /$keywords[\s;\(\)]+$keywords[\s;\(\)]+$keywords[\s;\(\)]+/si) { $ret{'info'}="Programming Language"; return %ret; }
	
	elsif ($data =~ /^\x1F\x8B\x08\x00/) { $ret{'info'}=".tgz"; return %ret; }

	#images
	elsif ($data =~ /^BM/) { $ret{'info'}="BMP -> Bitmap image"; return %ret; }
	elsif ($data =~ /^GIF8/) { $ret{'info'}="GIF -> GIF image"; return %ret; }
	elsif ($data =~ /^\x89PNG/) { $ret{'info'}="PNG -> PNG image"; return %ret; }
	elsif ($data =~ /^\xFF\xD8\xFF\xE0/) { $ret{'info'}="JPG -> JPEG image"; return %ret; }
	elsif ($data =~ /^\xD7\xCD\xC6\x9A/) { $ret{'info'}="WMF -> Windows Metafile"; return %ret; }

	#others
	elsif ($data =~ /^\%PDF/)				{ $ret{'info'}="PDF -> Adobe PDF document"; return %ret; }
	elsif ($data =~ /^ITSF/)				{ $ret{'info'}="CHM -> CHM help file"; return %ret; }
	elsif ($data =~ /^{\\rt/)				{ $ret{'info'}="RTF -> RTF document"; return %ret; }
	elsif ($data =~ /^CWS/)					{ $ret{'info'}="SWF -> Adobe Flash file"; return %ret; }
	elsif ($data =~ /^\xCA\xFE\xBA\xBE/)	{ $ret{'info'}="CLASS -> Java class file"; return %ret; }

	#riff
	elsif ($data =~ /^RIFF....ACON/)	{ $ret{'info'}="ANI -> Animated cursor file"; return %ret; }
	elsif ($data =~ /^RIFF....AVI /)	{ $ret{'info'}="AVI -> AVI video file"; return %ret; }

	#office
	elsif ($data =~ /^\x00...Standa/)		{ $ret{'info'}="MDB -> Microsoft Access database"; return %ret; }
	elsif ($data =~ /^\xFE\x37\00x\x23/){ $ret{'info'}="MAC"; return %ret; }

	elsif ($data =~ /^\xD0\xCF\x11\xE0/)
	{
		$ret{'info'}="OLE -> MS DOC,XLS,PPT,MSG etc...";

		my $mtool_info = ""; #`mtool /ole \"$filename\" -d 2>nul`;


		foreach my $line (split(/\n/, $mtool_info))
		{
			#print "Line: $line\n";
			if($line =~ m/STREAM/)
			{
				if($line =~ m/WordDocument/)
				{
					$ret{'info'}="OLE -> Word DOC";
				}

				elsif($line =~ m/__substg/)
				{
					$ret{'info'}="OLE -> Outlook MSG";
				}

				elsif($line =~ m/Workbook/)
				{
					$ret{'info'}="OLE -> Excel XLS";
				}

				elsif($line =~ m/JSRV/)
				{
					$ret{'info'}="OLE -> JTD";
				}

				elsif($line =~ m/EscherStm/)
				{
					$ret{'info'}="OLE -> Publisher PUB";
				}

				elsif($line =~ m/SPELLING/)
				{
					$ret{'info'}="OLE -> Works WPS";
				}

			}
		}
	}

  open    (FILE, '<'.$filename);
  binmode (FILE);
  read    (FILE, $data, 2);  
  if ($fsiz >= 128 && $data eq 'MZ')
      {
      	seek (FILE, 0x3C, 0); read (FILE, my $o2PE,4); $o2PE=unpack("I32",$o2PE);
      	if ($o2PE>16384) { $ret{'info'}="MZ - DOS Executable"; close (FILE); return %ret }
      	else
      	{
      		seek (FILE, $o2PE, 0);
          read (FILE, my $PEHeader,2);
             if ($PEHeader eq 'LE') { $ret{'info'}="LE - Win 9x Linear Executable (VXD Driver)"; close (FILE); return %ret}
          elsif ($PEHeader eq 'NE') { $ret{'info'}="NE - Win 3.x NEW Executable"; close (FILE); return %ret}
          elsif ($PEHeader eq 'PE')
          {
			#0x44 offset into optional header of subsystem flag
            seek (FILE, $o2PE+6      ,0); read (FILE, my $NumOfSections,2);   $NumOfSections   = unpack("S16",$NumOfSections);
            seek (FILE, $o2PE+22     ,0); read (FILE, my $Characteristics,2); $Characteristics = unpack("S16",$Characteristics);
            seek (FILE, $o2PE+20     ,0); read (FILE, my $OptHdrSize,2);      $OptHdrSize      = unpack("S16",$OptHdrSize);
            seek (FILE, $o2PE+24+0   ,0); read (FILE, my $OptHdrMagic,2);     $OptHdrMagic     = unpack("S16",$OptHdrMagic);
            seek (FILE, $o2PE+24+16  ,0); read (FILE, my $EntryPointRVA,4);   $EntryPointRVA   = unpack("I32",$EntryPointRVA);
            seek (FILE, $o2PE+24+28  ,0); read (FILE, my $ImageBase,4);       $ImageBase       = unpack("I32",$ImageBase);
			seek (FILE, $o2PE+24+68  ,0); read (FILE, my $Subsystem,2);       $Subsystem       = unpack("S16",$Subsystem);
            seek (FILE, $o2PE+24+96  ,0); read (FILE, my $ExpTblRVA,4);       $ExpTblRVA       = unpack("I32",$ExpTblRVA);
                                          read (FILE, my $ExpTblSize,4);      $ExpTblSize      = unpack("I32",$ExpTblSize);
            seek (FILE, $o2PE+24+96+8,0); read (FILE, my $ImpTblRVA,4);       $ImpTblRVA       = unpack("I32",$ImpTblRVA);
                                          read (FILE, my $ImpTblSize,4);      $ImpTblSize      = unpack("I32",$ImpTblSize);
            my $elast=0; my $ExpTblFile=0;
            my $ilast=0; my $ImpTblFile=0;
            my $eplast=0;my $EntryPointFile=0;
            my $sectiondata;
            my $AppdDataOfs=0;
            for (my $k=0;$k<$NumOfSections;$k++)
            {
              seek (FILE, $o2PE + 24 + $OptHdrSize + $k*40 + 8, 0);
              read (FILE, $sectiondata,4);my $vs = unpack("I32",$sectiondata);
              read (FILE, $sectiondata,4);my $vo = unpack("I32",$sectiondata);
              read (FILE, $sectiondata,4);my $fs = unpack("I32",$sectiondata);
              read (FILE, $sectiondata,4);my $fo = unpack("I32",$sectiondata);
              if ($AppdDataOfs<$fs+$fo && $fs != 0) { $AppdDataOfs=$fs+$fo; }
              if ($elast<=$ExpTblRVA)
               {
                   if  ($elast==0&&$ExpTblRVA<$vo) { $ExpTblFile=$ExpTblRVA; }
                 elsif ($ExpTblRVA<$vo+$vs)        { $ExpTblFile=$ExpTblRVA+$fo-$vo;}
                 $elast=$vo+$vs;
               }
              if ($ilast<=$ImpTblRVA)
               {
                   if  ($ilast==0&&$ImpTblRVA<$vo) { $ImpTblFile=$ImpTblRVA; }
                 elsif ($ImpTblRVA<$vo+$vs)        { $ImpTblFile=$ImpTblRVA+$fo-$vo;}
                 $ilast=$vo+$vs;
               }
              if ($eplast<=$EntryPointRVA)
               {
                   if  ($eplast==0&&$EntryPointRVA<$vo) { $EntryPointFile=$EntryPointRVA; }
                 elsif ($EntryPointRVA<$vo+$vs)         { $EntryPointFile=$EntryPointRVA+$fo-$vo;}
                 $eplast=$vo+$vs;
               }
            } # for ... num of section

            $ret{'ep'}=sprintf("ImageBase=%08lX, EntryPointRVA=%08lX, EntryPointFile=%08lX",$ImageBase,$EntryPointRVA,$EntryPointFile);

            my %ImpFuns;
            my %ExpFuns;

#            if ($ExpTblFile>0)
#             {
#              seek (FILE, $ExpTblFile,0);
#              read (FILE, my $exportdata,$ExpTblSize);
#              $exportdata=~s/[\x00-\x31]/ /g;
#              while ($exportdata=~/([A-Za-z0-9_]+)/g) { $ExpFuns{$1}=1; }
#
#            }
#
#            if ($ImpTblFile>0)
#            {
#            	seek (FILE, $ImpTblFile,0); read (FILE, my $importdata,$ImpTblSize);
#            	$importdata=~s/[\x00-\x31]/ /g;
#            	while ($importdata=~/([A-Za-z0-9_]+)/g) { $ImpFuns{$1}=1; }
#            }
#
#            my $isDLL=(($Characteristics & 0x2000) >>13);
#            my $isCOMSrv=defined($ExpFuns{'DllCanUnloadNow'})   || defined($ExpFuns{'DllGetClassObject'})
#                      || defined($ExpFuns{'DllRegisterServer'}) || defined($ExpFuns{'DllUnregisterServer'});
#
            my $DLLType='';
            $DLLType=" (DLL)";
#            if ($isDLL)
#            {
#            	  if ($isCOMSrv) { $DLLType=" (DLL, COM Server)"; }
#            	else             { $DLLType=" (DLL)"; }
#            }

		   if (1 == $Subsystem) { $ret{'info'}="PE - SYS File"; close (FILE); return %ret}
           if (0 == $AppdDataOfs)
           {
           	$ret{'info'}="PE - Portable Executable File$DLLType . No appended data"; close (FILE); return %ret
           }

           else # appdata>0
             {
             	      # somethign wrong with the calculation of sections/appended data; likely corrupted/obfuscated
             	   if ($fsiz<$AppdDataOfs)
             	      { $ret{'info'}="PE - Portable Executable File$DLLType , corrupted/obfuscated sections, $fsiz, $AppdDataOfs"; close (FILE); return %ret}

             	elsif ($fsiz==$AppdDataOfs)
             	      {
             	      	# "normal PE file - no appd data
         	 	          seek (FILE, 0, 0); read (FILE,$data,$fsiz);
                      if ($data =~ /AU([1-9])!(EA[0-9]{1,2})/igs)
                          { $ret{'info'}="PE - AutoIt, version: $1 ($2)"; close (FILE); return %ret; }

                      if ($data =~ /\<description\>AutoIt v?(.*?)\<\/description\>/igs)
                          { $ret{'info'}="PE - AutoIt, version: $1"; close (FILE); return %ret; }

             	      	$ret{'info'}="PE - Portable Executable File$DLLType . No appended data"; close (FILE); return %ret
             	      }
             	else # appd data
             	 {
             	 	seek (FILE, 0x0030, 0); read (FILE,$data,4);
             	 	if  ($data eq 'Inno') { $ret{'info'}="PE - InnoSetup Installer"; close (FILE); return %ret}

             	 	seek (FILE, $AppdDataOfs, 0); read (FILE,$data,3);
             	 	if  ($data eq 'zlb')  { $ret{'info'}="PE - InnoSetup Installer"; close (FILE); return %ret}

             	 	seek (FILE, $AppdDataOfs, 0); read (FILE,$data,4);
             	 	if  ($data eq 'Rar!')  { $ret{'info'}="PE - WinRar SFX (SelF-eXtracting archive)"; close (FILE); return %ret}

             	 	seek (FILE, $AppdDataOfs, 0); read (FILE,$data,2);
             	 	if  ($data eq '7z')
             	 	{
         	 	      seek (FILE, 0, 0); read (FILE,$data,$fsiz);
         	 	      $data =~ s/\x00//sig; #quick&dirty&wrong unicode->ansi
                  if ($data =~ /LexLib/igs)
                  { $ret{'info'}="PE - 7z Lexlib installer"; close (FILE); return %ret; }
                }

             	 	seek (FILE, $AppdDataOfs, 0); read (FILE,$data,4);
             	 	if  ($data eq '50AE')  { $ret{'info'}="PE - AutoIt version 5"; close (FILE); return %ret}

             	 	seek (FILE, $AppdDataOfs, 0); read (FILE,$data,4);
             	 	if  ($data eq '60AE')  { $ret{'info'}="PE - AutoIt version 6"; close (FILE); return %ret}

             	 	seek (FILE, $AppdDataOfs+1, 0); read (FILE,$data,3);
             	 	if  ($data eq '0AE')  { $ret{'info'}="PE - AutoIt Unknown version"; close (FILE); return %ret}

             	 	seek (FILE, $AppdDataOfs, 0); read (FILE,$data,40);
             	 	#if  ($data =~ /\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7.*irsetup\.exe/) { $ret{'info'}="PE - IndigoRose Setup Factory Installer"; close (FILE); return %ret }

             	 	seek (FILE, $AppdDataOfs, 0); read (FILE,$data,256);
             	 	if  ($data =~ /Wise Installation/) { $ret{'info'}="PE - Wise Installer"; close (FILE); return %ret}

             	 	seek (FILE,$AppdDataOfs+1,0); read (FILE,$data,8);
             	 	if  ($data eq 'TMSAMVOH') { $ret{'info'}="PE - Trymedia Activemark Installer/packer"; close (FILE); return %ret}

                seek (FILE,$AppdDataOfs+4, 0);
                read (FILE,$data, 4);my $hexbytes     = unpack("H32",$data);
                read (FILE,$data,12);my $NullsoftInst = unpack("a12",$data);
                if  (($hexbytes eq 'efbeadde')&&($NullsoftInst eq 'NullsoftInst'))
                {
                   seek (FILE,0,0);
                   read (FILE, my $stubdata, $fsiz-$AppdDataOfs);
                   my $nullver='Unknown'; if ($stubdata =~ /\<description\>Nullsoft Install System v?(.*?)\<\/description\>/igs) { $nullver=$1; }
                   $ret{'info'}="PE - NullSoft Installer, version: $nullver"; close (FILE); return %ret
                }

             	 	seek (FILE,$fsiz-8, 0); read (FILE,$data,4);
             	 	if  ($data =~ /ESIV/i) { $ret{'info'}="PE - Vise Installer"; close (FILE); return %ret}

             	 	seek (FILE, -16, 2);   read (FILE,$data,4);
             	 	if  ($data eq 'sRBV') { $ret{'info'}="PE - AWInstall Installer"; close (FILE); return %ret}

                seek (FILE,$AppdDataOfs,0);
                read (FILE,$data,$fsiz-$AppdDataOfs);
                if  ( ($data =~ /\x1F\x8B\x08\x00\x00\x00\x00\x00\x00\x0B/i) && ($data =~ /\RTT/) && ($data =~ /\\rtf/) ) { $ret{'info'}="PE - Astrum Installer"; close (FILE); return %ret}

                seek (FILE, $AppdDataOfs, 0); read (FILE,$data,$fsiz);
             	 	if  ($data =~ /installshield/i && $data =~ /data1\.cab/i) { $ret{'info'}="PE - InstallShield Installer"; close (FILE); return %ret}

         	 	    seek (FILE, 0, 0); read (FILE,$data,$fsiz);
                if ($data =~ /AU([1-9])!(EA[0-9]{1,2})/igs)
                    { $ret{'info'}="PE - AutoIt, version: $1 ($2)"; close (FILE); return %ret; }

                if ($data =~ /\<description\>AutoIt v?(.*?)\<\/description\>/igs)
                    { $ret{'info'}="PE - AutoIt, version: $1"; close (FILE); return %ret; }

                seek (FILE, 0, 0); read (FILE,$data,$fsiz);
             	 	$data =~ s/\x00//sig; #quick&dirty&wrong unicode->ansi
             	 	if  ($data =~ /indigo rose/i) { $ret{'info'}="PE - IndigoRose Setup Factory Installer"; close (FILE); return %ret }
             	 	pos $data=0;if  ($data =~ /Compiled AutoIt Script/igs) { $ret{'info'}="PE - AutoIt, unknown version"; close (FILE); return %ret; }
             	 	pos $data=0;if  ($data =~ /AutoIt/igs) { $ret{'info'}="PE - AutoIt (weak detection)"; close (FILE); return %ret; }


                $ret{'info'}=sprintf("PE - Portable Executable File$DLLType , Appended Data",$AppdDataOfs,$AppdDataOfs); close (FILE); return %ret;
               }

             }  # appdata>0

          } # PE header
      	} # o2PE<16384
      }

  seek (FILE, 0, 0); read (FILE,$data,$fsiz);
  my $istext=1; 
  
  for (my $k=0;$k<$fsiz;$k++)
  {
  	my $c=ord(substr($data,$k,1));
  	if ($c>128) { $istext=0; last; }
  }
  if ($istext==1)
  {
  	$ret{'info'}="TextFile"; close (FILE); return %ret; 
  }
  close   (FILE);

  return %ret
}



sub LoadFileTypes( )
{
	my $filetypes_csv = "$logs_dir\\filetype.csv";
	
	open( IN, "< $filetypes_csv" ) or die "\n Error: LoadFileTypes : $! $filetypes_csv !!! \n";				
	my @data = <IN>;
	close IN;
	
	foreach my $entry ( @data )
	{		
		if ( $entry =~ m/([0-9A-F]{32}),\s*(.*),/i )
		{
			my $md5 = uc( $1 );
			my $type = $2;
			$FILE_TYPE{ $md5 } = $type;				
		}
	}	
}


#sub LoadPackerExclusion( )
#{
#	my $packer_exclusion = "$tools_dir\\PackerExclusion.ini";
#
#	my $debug_str = "\n\n Loading Packer Exclsion List ...";
#	print $debug_str;
#	WriteToLog( $debug_log, $debug_str );							
#
#	open( IN, "< $packer_exclusion" ) or die "\n FATAL Error: $! ( $packer_exclusion ) !!! \n";
#	my @data = <IN>;
#	close IN;
#	
#	foreach my $entry ( @data )
#	{		
#		$entry =~ s/\s+//g;
#		$PACKER_EXCLUSION{ $entry } = "Excluded";						
#	}	
#	
#	$debug_str = "\n Done.";
#	print $debug_str;
#	WriteToLog( $debug_log, $debug_str );								
#}


# counts MD5 in each line
sub GetNumberOfEntries( $ )
{
	my $file = shift; 
	open( IN, "< $file" ) or return 0;	
	my @data = <IN>;
	close IN;

	my $count = 0;
	foreach my $entry ( @data )
	{		
		if ( $entry =~ m/([0-9A-F]{32})/i )
		{
			$count = $count + 1;
		}
	}	
	return $count;
}

# counts MD5 in each line
sub GetNumberOfEntriesForBulk( $ )
{
	my $file = shift; 
	open( IN, "< $file" ) or return 0;	
	my @data = <IN>;
	close IN;

	my $count = 0;
	my $count_bulk2 = 0;
	
	foreach my $entry ( @data )
	{		
		if ( $entry =~ m/([0-9A-F]{32})/i )
		{
			if($entry =~ m/bulk-add-2/ )	
			{
				$count_bulk2 = $count_bulk2 + 1;
			}
			else
			{
				$count = $count + 1;
			}
		}
	}	
	return $count, $count_bulk2;
}


sub GetUniqueMD5( $ )
{
	my $file = shift; 
	open( IN, "< $file" ) or return 0;	
	my @data = <IN>;
	close IN;

	my $count = 0;
	my %HASH_MD5;
	foreach my $entry ( @data )
	{		
		if ( $entry =~ m/([0-9A-F]{32})/i )
		{
			my $md5 = uc( $1 );
			if (!exists ( $HASH_MD5{ $md5 }) )
			{
				$count = $count + 1;
				$HASH_MD5{ $md5 } = "";
			}
		}
	}	
	return $count;
}


sub GetFileCount( $ )
{
	my $src_dir = shift; 
	
	opendir( SRCDIR, $src_dir ) or return -1;
	my( @files ) = grep( !/^\./, readdir( SRCDIR ));
	closedir( SRCDIR );	

	my $count = 0;
	foreach my $entry ( @files )
	{		
		if ( -e "$src_dir\\$entry" )
		{
			$count = $count + 1;
		}
	}	
	return $count;
}

sub GetFileCountEx( $ )
{
	my $src_dir = shift; 
	
	opendir( SRCDIR, $src_dir ) or return 0;
	my( @files ) = grep( !/^\./, readdir( SRCDIR ));
	closedir( SRCDIR );	

	my $count = 0;
	foreach my $entry ( @files )
	{		
		if ( -f "$src_dir\\$entry" )
		{
			$count = $count + 1;
		}

		if ( -d "$src_dir\\$entry" )
		{
			$count = $count + GetFileCountEx( "$src_dir\\$entry" );
		}		
	}	
	#print "\n GetFileCountEx $src_dir: $count";
	
	return $count;
}

sub GetDateTime( )
{  
	use POSIX qw( strftime );
	my $now_string = strftime "%d-%m-%Y_%H%M%S", localtime;	
	return $now_string;
}


sub GenerateDetectedThreatStat( $$$$ )
{
	my $in_file = shift;
	my $rpt_file = shift;
	my $grouping_file = shift;
	my $grouping_threshold = shift;
	                                                                                
	#print "$in_file \n$rpt_file \n";
	open( IN, "< $in_file" ) or return 0;	
	my @data = <IN>;
	close IN;

	my %THREAT_STATS;

	foreach my $entry ( @data )
	{		
		if ( $entry =~ m/([0-9A-F]{32}),\s+(.*)\s*/i )
		{
			my $threatname = $2;						
			if( exists ( $THREAT_STATS{ $threatname } ) )
			{
				 $THREAT_STATS{ $threatname } = $THREAT_STATS{ $threatname } +  1;				
			}
			else
			{
				 $THREAT_STATS{ $threatname }  = 1;
			}
		}
	}	

	open( OUT, "> $rpt_file" );	 
	open( GRP, "> $grouping_file" ) if ( $grouping_threshold > 0 );

	my @names = sort keys ( %THREAT_STATS );
	foreach my $name ( @names )
	{
		my $count = $THREAT_STATS{ $name };
		if( $grouping_threshold > 0 )
		{
			if( $count >= $grouping_threshold )
			{
				print GRP "$name, $count\n";
			}			
		}
		print OUT "$name, $count\n";
	}
	close( OUT );	
	close( GRP ) if ( $grouping_threshold > 0 );	
}


sub GenerateThreatStat( $$$$ )
{
	my $in_file = shift;
	my $rpt_file = shift;
	my $grouping_file = shift;
	my $grouping_threshold = shift;
	                                                                                
	#print "\n\n$in_file \n$rpt_file \n$grouping_file\nTH: $grouping_threshold\n";
	open( IN, "< $in_file" ) or return 0;	
	my @data = <IN>;
	close IN;

	my %THREAT_STATS;

	foreach my $entry ( @data )
	{		
		if ( $entry =~ m/([0-9A-F]{32})\s+(.*)\s*/i )
		{
			my $threatname = $2;						
			if( exists ( $THREAT_STATS{ $threatname } ) )
			{
				 $THREAT_STATS{ $threatname } = $THREAT_STATS{ $threatname } +  1;				
			}
			else
			{
				 $THREAT_STATS{ $threatname }  = 1;
			}
		}
	}	

	open( OUT, "> $rpt_file" );	 
	my @names = sort keys ( %THREAT_STATS );
	foreach my $name ( @names )
	{
		my $count = $THREAT_STATS{ $name };
		print OUT "$name, $count\n";
	}
	close( OUT );	

	return if ( $grouping_threshold <= 0 );

	open( OUT, "> $in_file" );	 
	open( GRP, "> $grouping_file" ) ;

	@data = sort @data;
	foreach my $entry ( @data )
	{		
		if ( $entry =~ m/(.+)([0-9A-F]{32})\s+(.*)\s*/i )
		{
			my $path = $1;
			my $md5 = uc( $2 );
			my $threatname = $3;						
			if( exists ( $THREAT_STATS{ $threatname } ) )
			{
				my $count = $THREAT_STATS{ $threatname };				
				if( $count >= $grouping_threshold )
				{
					print GRP $entry;
					# move file to "for-generic" folder
					
					my $category = "UNKNOWN";
					if ( exists( $FILE_TYPE{$md5} ))
					{
						$category = $FILE_TYPE{ $md5 };
						$category =~ s/-/\\/;
					}
					
					$threatname =~ s/\./\\/g; 			
					$threatname =~ s/\//\\/g; 			
					
					my $dst_dir = "$out_dir\\for-generic\\$category\\$threatname"; 										
					mkpath( $dst_dir );
					
					print "MOVE: $path$md5 ==> $dst_dir\\$md5\n";
					
					move( "$path$md5", "$dst_dir\\$md5" );			
					rmdir( $path );					# delete current directory if empty
					# it doesn't delete parent directory
				}
				else
				{
					print OUT $entry;
				}
			}
		}
	}	

	close( OUT );
	close( GRP );
}


sub DeleteOldStats( )
{	
	my $debug_str = "\n Deleting old stats ...";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );								
	
	opendir( SRCDIR, $reports_dir ) or die "\n\n Error: $reports_dir $! !!! \n\n";			
	my( @files ) = grep( !/^\./, readdir( SRCDIR ));
	closedir( SRCDIR );	
	
	for my $filename ( @files )
	{
		if ( $filename =~ /^PACKER.*CSV$/i || $filename =~ /^ARCHIVE.*CSV$/i || $filename =~ /^STATS.*CSV$/i )
		{
			my $src_file = "$reports_dir\\$filename";	    
			unlink( $src_file );
		}
	}

	$debug_str = "\n Done.";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );									
}

#
# Generate stats  
#
sub GetStats( )
{
	my $count = 0;
	my $count_bulk2 = 0;
	my $temp = 0;
	
	
	open( OUT, " > $reports_dir\\STATS_$now_string.csv" ) or return 0;	
	
	$count = GetNumberOfEntries( "$logs_dir\\sample-md5.csv" );
	print "\n\n Statistics: \n\n";
	print "  Total Received: $count\n";
	print OUT "Source, $source\n";
	print OUT "Total Received, $count\n";
	
	$count = GetUniqueMD5( "$logs_dir\\sample-md5.csv" );
	print "  Unique samples: $count\n";
	print OUT "Unique samples, $count\n";
	
	$count = GetNumberOfEntries( "$logs_dir\\qh-parsed.csv" );
	print "  QH Detected: $count\n";
	print OUT "QH Detected, $count\n";
	
	($count, $temp) = GetNumberOfEntriesForBulk( "$reports_dir\\ADWARE.txt" );
	$count_bulk2 = $temp;
	print "  Adware: $count\n";
	print OUT "Adware, $count\n";
	($count, $temp) = GetNumberOfEntriesForBulk( "$reports_dir\\BACKDOOR.txt" );
	$count_bulk2 = $count_bulk2 + $temp;
	print "  Backdoor: $count\n";
	print OUT "Backdoor, $count\n";
	($count, $temp) = GetNumberOfEntriesForBulk( "$reports_dir\\TROJAN.txt" );
	$count_bulk2 = $count_bulk2 + $temp;
	print "  Trojan: $count\n";
	print OUT "Trojan, $count\n";
	($count, $temp) = GetNumberOfEntriesForBulk( "$reports_dir\\WORM.txt" );
	$count_bulk2 = $count_bulk2 + $temp;
	print "  Worm: $count\n";
	print OUT "Worm, $count\n";
	($count, $temp) = GetNumberOfEntriesForBulk( "$reports_dir\\VIRUS.txt" );
	$count_bulk2 = $count_bulk2 + $temp;
	print "  Virus: $count\n";
	print OUT "Virus, $count\n";

	print "  Bulk-Add-2: $count_bulk2\n";
	print OUT "Bulk-Add-2, $count_bulk2\n";
	
	# combined packer exclusion entries from KAV and MS
	$count = GetNumberOfEntries( "$reports_dir\\KAV_PACKER.txt" );
	$count += GetNumberOfEntries( "$reports_dir\\MS_PACKER.txt" );
	
	print "  Packer-Exclusion: $count\n";
	print OUT "Packer-Exclusion, $count\n";	
	$count = GetNumberOfEntries( "$reports_dir\\NON-PE.txt" );
	print "  Non-PE: $count\n";
	print OUT "Non-PE, $count\n";
	
	$count = GetNumberOfEntries( "$logs_dir\\signed-files.csv" );
	print "  Signed: $count\n";  	
	print OUT "Signed, $count\n";  	
	$count = GetNumberOfEntries( "$logs_dir\\version-ms.csv" );
	print "  Version-MS: $count\n"; 
	print OUT "Version-MS, $count\n"; 
	$count = GetNumberOfEntries( "$logs_dir\\kav-archive.csv" );
	print "  Archive: $count\n"; 
	print OUT "Archive, $count\n"; 

	$count = GetFileCountEx( "$out_dir\\for-generic" );
	print "  For-Generic: $count\n"; 
	print OUT "For-Generic, $count\n"; 
	
	$count = GetFileCountEx( "$out_dir\\symc-generic" );
	print "  Symc-Generic: $count\n"; 
	print OUT "Symc-generic, $count\n"; 
	
	$count = GetFileCountEx( "$out_dir\\skip" );
	print "  Skipped: $count\n";
	print OUT "Skipped, $count\n";

	$count = GetFileCountEx( "$out_dir\\undetected\\PE" );
	print "  Undetected Total PE: $count\n";
	print OUT "Undetected Total PE, $count\n";	

	$count = GetFileCountEx( "$out_dir\\undetected\\non-PE" );
	print "  Undetected Total non-PE: $count\n";
	print OUT "Undetected Total non-PE, $count\n";	

	$count = GetFileCountEx( "$out_dir\\undetected\\PE\\EXE" );
	print "  Undetected PE-EXE: $count\n";
	print OUT "Undetected PE-EXE, $count\n";	

	$count = GetFileCountEx( "$out_dir\\undetected\\PE\\DLL" );
	print "  Undetected PE-DLL: $count\n";
	print OUT "Undetected PE-DLL, $count\n";	

	$count = GetFileCountEx( "$out_dir\\undetected\\PE\\NTDRIVER" );
	print "  Undetected PE-DRIVER: $count\n";
	print OUT "Undetected PE-DRIVER, $count\n";	

	#$count = GetFileCountEx( "$out_dir\\undetected\\PE\\EXE_VB" );
	#print "  Undetected PE-VB: $count\n";
	#print OUT "Undetected PE-VB, $count\n";	

	$count = GetFileCountEx( "$out_dir\\undetected\\PE64\\EXE" );
	print "  Undetected PE64-EXE: $count\n";
	print OUT "Undetected PE64-EXE, $count\n";	

	$count = GetFileCountEx( "$out_dir\\undetected\\PE64\\DLL" );
	print "  Undetected PE64-DLL: $count\n";
	print OUT "Undetected PE64-DLL, $count\n";	

	$count = GetFileCountEx( "$out_dir\\undetected\\PE64\\NTDRIVER" );
	print "  Undetected PE64-DRIVER: $count\n";
	print OUT "Undetected PE64-DRIVER, $count\n";	

	$count = GetFileCountEx( "$out_dir\\archives\\MISC\\PDF" );
	print "  PDF: $count\n";
	print OUT "PDF, $count\n";	

	$count = GetFileCountEx( "$out_dir\\undetected\\non-PE\\SCRIPT" );
	print "  SCRIPT: $count\n";
	print OUT "SCRIPT, $count\n";	

	$count = GetFileCountEx( "$out_dir\\archives\\ANDRIOD" );
	print "  ANDRIOD APK: $count\n";
	print OUT "ANDRIOD APK, $count\n";	

	$count = GetFileCountEx( "$out_dir\\undetected\\non-PE\\ANDRIOD\\DEX" );
	print "  ANDRIOD DEX: $count\n";
	print OUT "ANDRIOD DEX, $count\n";	

	$count = GetFileCountEx( "$out_dir\\undetected\\non-PE\\MAC" );
	print "  Mac: $count\n";
	print OUT "Mac, $count\n";	

	$count = GetFileCountEx( "$out_dir\\archives\\MAC" );
	print "  Mac-Archive: $count\n";
	print OUT "Mac-Archive, $count\n";	
	
	$count = GetFileCount( "$out_dir\\corrupt" );
	print "  Corrupt: $count\n";
	print OUT "Corrupt, $count\n";	

	
###################
# AVIRA Scanner is removed.
#	
#	$count = GetFileCount( "$out_dir\\avira-undetected" );
#	print "  CLEAN: $count\n";
#	print OUT "CLEAN, $count\n";
###
	
	close OUT;
}

sub PrintUsage( )
{

 print <<EOF;

Quick Heal Tecnhologies Pvt. Ltd.
Malware Processing Automation v 2.2

To process samples ==>

Usage: $APPNAME <source folder> <destination folder> <colletction name> [SCANTYPE=NORMAL]

 SCANTYPE: NORMAL, ALL, EXTENDED
   NORMAL: Run Kaspersky, Microsoft and Symantec Scanners
      ALL: Run all Scanners 
 EXTENDED: Run ESET, BitDefender, SOPHOS and PANDA Scanners

e.g. $APPNAME c:\\samples c:\\processed VirusTotal


To generate stats Archive, packer and samles statistics ==>

Usage: $APPNAME STATS <destination folder> <colletction name> [Thresold for generic grouping, default=10]
e.g. $APPNAME STATS c:\\processed VirusTotal 10

for comments or suggestions please contact Rajesh (at) QuickHeal (dot) com
EOF
	
	exit;
}


sub Pause( )
{
	#print "\n Please press ENTER key: ";
	#my $str = <stdin>;
}

sub IsFilePresent( $ )
{
	my $filepath = shift;
	#print "\n   $filepath";
	if(! ( -e  $filepath) )
	{
		my $debug_str = "\n   FATAL Error: $filepath not found !!!";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str );		
		return 0;
	}
	
	return 1;
}


sub SelfCheck( )
{
	# check for required ini files, tools and AntiVirus Scanners
	my $debug_str = "\n Running self check ...\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );							

	my $present = 0;
	
	#my $b_trid = IsFilePresent( "$tools_dir\\TrID\\trid.exe" ); 
	my $b_filetype = IsFilePresent( "$tools_dir\\mpa_filetype.exe" ); 
	#my $b_sigcheck = IsFilePresent( "$tools_dir\\mpa_sigcheck.exe" ); 	

	my $b_kav_ini = IsFilePresent( "$tools_dir\\KAV_ThreatNames.ini" );
	my $b_ms_ini = IsFilePresent( "$tools_dir\\Microsoft_ThreatNames.ini" );
	#my $b_packer_exclusion = IsFilePresent( "$tools_dir\\PackerExclusion.ini" );	
	my $b_eicar_test = IsFilePresent( "$tools_dir\\ntvirus\\EICAR\\EICAR-TESTFILE.COM" );	
	
	#$present = $b_trid + $b_filetype + $b_sigcheck + $b_kav_ini + $b_ms_ini + $b_packer_exclusion + $b_eicar_test;
	$present = $b_filetype + $b_kav_ini + $b_ms_ini + $b_eicar_test;
		
	#if( $present != 7 ) 
	if( $present != 4 ) 
	{
		$debug_str = "\n\n FATAL Error: Self check FAILED !!! \n";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str );		
		exit;
	}
	
	my $qh = QHScanSelfCheck( "$tools_dir\\ntvirus\\EICAR" );
	#my $avira = AVIRAScanSelfCheck( "$tools_dir\\ntvirus\\EICAR" );
	
	my $kav = 0;
	my $ms = 0;
	my $tm = 0;
	my $symc = 0;
	my $bitdef = 0;
	my $eset = 0;
	my $sophos = 0;
	my $panda = 0; 
	
	if ( $SCANTYPE =~ /^NORMAL$/i || $SCANTYPE =~ /^ALL$/i )
	{	
		$kav = KAVScanSelfCheck( "$tools_dir\\ntvirus\\EICAR" );
		$ms = MicrosoftScanSelfCheck( "$tools_dir\\ntvirus\\EICAR" );
		$tm = TMScanSelfCheck( "$tools_dir\\ntvirus\\EICAR" );	
		$symc = SymantecSelfCheck( "$tools_dir\\ntvirus\\EICAR" );	
	}
	
	if ( $SCANTYPE =~ /^EXTENDED$/i || $SCANTYPE =~ /^ALL$/i )
	{	
		$bitdef = BitDefScanSelfCheck( "$tools_dir\\ntvirus\\EICAR" );
		$eset = ESETScanSelfCheck( "$tools_dir\\ntvirus\\EICAR" );		
		$sophos = SOPHOSScanSelfCheck( "$tools_dir\\ntvirus\\EICAR" );		
		$panda = PANDAScanSelfCheck( "$tools_dir\\ntvirus\\EICAR" );		
	}
		
	$present = $qh + $kav + $ms + $tm + $symc + $bitdef + $eset + $sophos + $panda;
	
	if ( 
			( $present != 5 ) && ( $SCANTYPE =~ /^NORMAL$/i || $SCANTYPE =~ /^EXTENDED$/i ) ||
			( $present != 9 ) && ( $SCANTYPE =~ /^ALL$/i )
	)
	{
		$debug_str = "\n\n FATAL Error: Commanad line scanner check FAILED !!! \n";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str );		
		exit;		
	}
	
	$debug_str = "\n\n Self check PASSED :)\n";
	print $debug_str;
	WriteToLog( $debug_log, $debug_str );		
}

##################################################
#
#     M A I N   F U N C T I O N
#
#####

my $argc = @ARGV; 

# to flush output 
$| = 1;

if ( $argc == 3 || $argc == 4 )
{		
	# set global directory paths	
	$out_dir = $ARGV[1];
	$source = $ARGV[2];
	$samples_dir = "$out_dir\\undetected";
	$logs_dir = "$out_dir\\logs";		
	$reports_dir = "$out_dir\\reports";
	$debug_log = "$reports_dir\\progress.log";

	$now_string = GetDateTime( );
	my $args = join ( ", ", @ARGV );
	
	if ( $ARGV[0] =~ /^STATS$/i )	
	{		
		# Create combined reports				
		WriteToLog( $debug_log, "\n\n\n Command line arguments: $args\n" );
		
		DeleteOldStats( );
		# Load file information
		LoadFileTypes( );
		# Load Packer Exclusion list
#		LoadPackerExclusion( );
		
		my $threshold = 10;
		if ( $argc == 4 )
		{
			$threshold = $ARGV[3];
		}

		my $debug_str = "\n\n Gathering information for generic detection ...\n";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str);
		
		GenerateDetectedThreatStat( "$logs_dir\\qh-parsed.csv", "$reports_dir\\Stats-QH-DETECTED", "$reports_dir\\GROUPED-QH-DETECTED.csv", $threshold );		
		
		GenerateThreatStat( "$reports_dir\\ADWARE.txt", "$reports_dir\\Stats-ADWARE.csv", "$reports_dir\\ForGeneric-ADWARE.csv", $threshold );		
		GenerateThreatStat( "$reports_dir\\BACKDOOR.txt", "$reports_dir\\Stats-BACKDOOR.csv", "$reports_dir\\ForGeneric-BACKDOOR.csv", $threshold );		
		GenerateThreatStat( "$reports_dir\\TROJAN.txt", "$reports_dir\\Stats-TROJAN.csv", "$reports_dir\\ForGeneric-TROJAN.csv", $threshold );		
		GenerateThreatStat( "$reports_dir\\WORM.txt", "$reports_dir\\Stats-WORM.csv", "$reports_dir\\ForGeneric-WORM.csv", $threshold );				
		GenerateThreatStat( "$reports_dir\\VIRUS.txt", "$reports_dir\\Stats-VIRUS.csv", "", 0 );		

		$debug_str = " Done.\n";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str);
		Pause( );					
		$debug_str = "\n\n Generating Threat statistics ...\n";
		print $debug_str;
		WriteToLog( $debug_log, $debug_str);

		GetStats( );		
		Pause( );			                                                                                 
		$debug_str = "\n\n Generating Archive and Packer statistics ...\n";
		print $debug_str;
		WriteToLog( $debug_log, "\n\n Generating Archive and Packer statistics ...\n");
		KAVParseLog( 1 );
		Pause( );					
		exit;
	}
	else
	{		
		# check input folder	
		if ( ! (-d $ARGV[0] ) )
		{
			print "\n\nError: $ARGV[0] folder does not exists !!!\n\n";
			PrintUsage( );
			exit;
		}
				
		
		if( $argc == 4 )
		{
			$SCANTYPE = uc( $ARGV[3] );
		}
		
	
		# Create Output directory structure		
		CreateDirectoryStructure( $out_dir );		
		Pause( );
		WriteToLog( $debug_log, " Command line arguments: $args\n" );

		# Do self check
		#SelfCheck( );		
			
		# copy samples with MD5 name
		open FH, "> $logs_dir\\sample-md5.csv";
		close FH;
		RenamewithMD5( $ARGV[0], $samples_dir );
		print "\n Done.\n";		
		WriteToLog( $debug_log, "\n Done.\n" );		
		Pause( );
		
		# extract archive & installers using 7-Zip
		$extract2_dir = "$out_dir\\7zip-extracted";
		
		Run7Zip( $samples_dir,  $extract2_dir );		
		Pause( );
				
		# Run filetype on extracted samples
		RunFileType( $extract2_dir, "$logs_dir\\filetype_extracted.csv" );		
		Pause( );

		# move only PE files to undetected folder
		MovePEFiles( "$logs_dir\\filetype_extracted.csv", $samples_dir );
				
		# Run filetype 
		RunFileType( $samples_dir, "$logs_dir\\filetype.csv" );		
		Pause( );
		# load file type for samples
		LoadFileTypes( );
		
		## Run TrID 
		#RunTrID( $samples_dir ); # TriD not required
		# Run PEiD 
		# RunPEiD( $samples_dir );		
		Pause( );		

		# Run Quick Heal Scan
		QHScan( $samples_dir );	
		QHParseLog( );
		# Move Detected samples 
		MoveDetectedSamples( "$logs_dir\\qh-parsed.csv", "$out_dir\\qh-detected" );		
		Pause( );		
			
		#
		# Could think on not removing corrupt files > Date 20 Mar 2012 	
		#
		MoveCorruptFiles($samples_dir, "$out_dir\\corrupt");

		if ( $SCANTYPE =~ /^NORMAL$/i || $SCANTYPE =~ /^ALL$/i )
		{

#######
## Check for Microsoft Version files removed
## Start
###		
#		# Run Sigcheck
#		RunSigCheck( $samples_dir );	
#		# Remove signed files	and files with Microsoft as version information
#		MoveSignedFiles( );
#		Pause( );				
#######
## Check for Microsoft Version files removed
## End
###		

#######
## Check for Packer Exclusion removed
## Start
###				
#		# Load Packer Exclusion list
#		LoadPackerExclusion( );
#######
## Check for Packer Exclusion removed
## Start
###				
					
		# Run Kasparsky Scan
		LoadKAVThreatInfo( );
		KAVScan( $samples_dir );  	
		KAVParseLog( 0 );		
		Pause( );
		
		# Run Trend Micro Scan
		TMScan( $samples_dir );	
		TMParseLog( );
		Pause( );		
		
		# Move samples to appropriate folders
		# Move KAV detected archives / installers
		MoveFiles( "$logs_dir\\kav-archive.csv", "$out_dir\\archives" );
		Pause( );
		# Move Infectors
		MoveFilesWithThreatName( "$logs_dir\\virus-kav.csv", 		"$out_dir\\infectors" );	
		MoveFilesWithThreatName( "$logs_dir\\virus-trend.csv", 	"$out_dir\\infectors" );	
		Pause( );
		
		# Move KAV bulk-add samples 
		#MoveFilesWithThreatName( "$logs_dir\\kav_packer-exclusion.csv", 			"$out_dir\\packer-exclusion" );
		MoveFilesWithThreatName( "$logs_dir\\trojan-kav.csv", 		"$out_dir\\bulk-add" ); #\\kaspersky" );
		MoveFilesWithThreatName( "$logs_dir\\worm-kav.csv", 			"$out_dir\\bulk-add" ); #\\kaspersky" );
		MoveFilesWithThreatName( "$logs_dir\\backdoor-kav.csv", 	"$out_dir\\bulk-add" ); #\\kaspersky" );
		MoveFilesWithThreatName( "$logs_dir\\adware-kav.csv", 		"$out_dir\\bulk-add" ); #\\kaspersky" );
		MoveFilesWithThreatName( "$logs_dir\\other-kav.csv", 			"$out_dir\\skip" );
		Pause( );									
		
#######
## AVIRA Detection removed
## Start
###					
		# Run AVIRA Scan		
		#AVIRAScan( $samples_dir );	
		#AVIRAParseLog( );				
		#MoveUnDetectedSamples( "$logs_dir\\avira-parsed.csv", "$out_dir\\avira-undetected" );
		#Pause( );			
#######
## AVIRA Detection removed
## End
###					
		
		# Run Microsoft AV Scan	
		LoadMSAVThreatInfo( );
		MicrosoftScan( $samples_dir );	
		MicrosoftParseLog( );			

		# Move Infectors
		MoveFilesWithThreatName( "$logs_dir\\virus-msav.csv", "$out_dir\\infectors" );
		Pause( );					
		# Move MSAV bulk-add samples 
		#MoveFilesWithThreatName( "$logs_dir\\ms_packer-exclusion.csv", 			"$out_dir\\packer-exclusion" );
		MoveFilesWithThreatName( "$logs_dir\\adware-msav.csv",   "$out_dir\\bulk-add" ); #\\microsoft" );
		MoveFilesWithThreatName( "$logs_dir\\trojan-msav.csv",   "$out_dir\\bulk-add" ); #\\microsoft" );
		MoveFilesWithThreatName( "$logs_dir\\worm-msav.csv",     "$out_dir\\bulk-add" ); #\\microsoft" );
		MoveFilesWithThreatName( "$logs_dir\\backdoor-msav.csv", "$out_dir\\bulk-add" ); #\\microsoft" );
		MoveFilesWithThreatName( "$logs_dir\\other-msav.csv", 	 "$out_dir\\skip" );
		Pause( );			

		# Run Symantec Scan
		LoadSYMCThreatInfo( );
		SymantecScan( $samples_dir );	
		SymantecParseLog( );		
		
		MoveFilesWithThreatName( "$logs_dir\\adware-symc.csv",   "$out_dir\\bulk-add" ); #\\symantec" );
		MoveFilesWithThreatName( "$logs_dir\\trojan-symc.csv",   "$out_dir\\bulk-add" ); #\\symantec" );
		MoveFilesWithThreatName( "$logs_dir\\worm-symc.csv",     "$out_dir\\bulk-add" ); #\\symantec" );
		MoveFilesWithThreatName( "$logs_dir\\backdoor-symc.csv", "$out_dir\\bulk-add" ); #\\symantec" );
			
		}
		
		if ( $SCANTYPE =~ /^EXTENDED$/i || $SCANTYPE =~ /^ALL$/i )
		{			
		# Run ESET Scan
		LoadESETThreatInfo( );
		ESETScan( $samples_dir );	 		
		ESETParseLog( );		
		
		# Run BitDefender Scan
		LoadBitDefThreatInfo( );                        
		BitDefScan( $samples_dir );	 		                  
		BitDefParseLog( );                        
                            
		# Run SOPHOS Scan                        
		LoadSOPHOSThreatInfo( );                        
		SOPHOSScan( $samples_dir );	 		                  
		SOPHOSParseLog( );                        
                            
		# Run PANDA Scan                        
		LoadPANDAThreatInfo( );                        
		PANDAScan( $samples_dir );	 		                  
		PANDAParseLog( );                        
                            
		AddSecondaryDetections( );                        

		# Move samples detected with more than 2 vendors
		MoveFilesWithThreatName( "$logs_dir\\adware-2.csv",   "$out_dir\\bulk-add-2" ); #\\symantec" );
		MoveFilesWithThreatName( "$logs_dir\\trojan-2.csv",   "$out_dir\\bulk-add-2" ); #\\symantec" );
		MoveFilesWithThreatName( "$logs_dir\\worm-2.csv",     "$out_dir\\bulk-add-2" ); #\\symantec" );
		MoveFilesWithThreatName( "$logs_dir\\backdoor-2.csv", "$out_dir\\bulk-add-2" ); #\\symantec" );
		}
		
		if ( $SCANTYPE =~ /^NORMAL$/i || $SCANTYPE =~ /^ALL$/i )
		{
		# Move Infectors
		MoveFilesWithThreatName( "$logs_dir\\virus-symc.csv", "$out_dir\\infectors" );		
		Pause( );		

		MoveFilesWithThreatName( "$logs_dir\\other-symc.csv", 	 "$out_dir\\symc-generic" );
		}

########
				
		GetVersionInfo( "$reports_dir\\ADWARE.txt" );
		GetVersionInfo( "$reports_dir\\BACKDOOR.txt" );
		GetVersionInfo( "$reports_dir\\TROJAN.txt" );
		GetVersionInfo( "$reports_dir\\WORM.txt" );
		GetVersionInfo( "$reports_dir\\VIRUS.txt" ); 		

		# move undetected files as per filetype
		MoveAsFileType("$out_dir\\undetected", "$out_dir\\undetected");

		# Report all MD5s to Samples Information Server
		ReportInfo("$logs_dir\\sample-md5.csv");
				
		Pause( );			
		
		exit;	
	}	
}
	
PrintUsage( );

##################################################
#
#    E N D 
#
#####
