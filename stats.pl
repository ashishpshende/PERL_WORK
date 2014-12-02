#! perl
#  
#  Author:  Rajesh Nikam.
#    
#  Malware Processing Automation
#  Date Created: 15-March-2010
#
#

use strict;
use File::Copy;
use Cwd;
use File::Path;
use DateTime;

#
# To install File::Copy::Recursive - run following command
# ppm install File::Copy::Recursive
# 
# To install Datetime package
# ppm install DateTime
#

use File::Copy::Recursive qw(fcopy rcopy dircopy fmove rmove dirmove);

use strict;
use warnings;

###

my( $APPNAME ) = "stats.pl";

my $archive_stat_file = "";
my $packer_stat_file = "";
my $samples_stat_file = "";

my $detailed_archive_stat_file = "";
my $detailed_packer_stat_file = "";
my $detailed_samples_stat_file = "";

sub CopyStats( $$ ) 
{
	my $src_dir = shift;
	my $dst_dir = shift;

	print "\n  Copying stats: $src_dir ==> $dst_dir\n";
	
	opendir( SRCDIR, "$src_dir\\reports" );	
	my( @files ) = grep( !/^\./, readdir( SRCDIR ));
	closedir( SRCDIR );	

 	for my $filename ( @files )
	{		
		# Stats
		if ( $filename =~ m/STATS_([0-9]{2})-([0-9]{2})-([0-9]{4})_([0-9]{6})/i )
		{			
			my $src_file = "$src_dir\\reports\\$filename";	
			my $dst_file = "$dst_dir\\$3\\$2\\$1";	
			
			mkpath ( $dst_file, {verbose => 1} );
						
			copy( $src_file, "$dst_file\\$filename" );
		}

		# Archive
		if ( $filename =~ m/ARCHIVE_([0-9]{2})-([0-9]{2})-([0-9]{4})_([0-9]{6})/i )
		{			
			my $src_file = "$src_dir\\reports\\$filename";	
			my $dst_file = "$dst_dir\\$3\\$2\\$1";	
			
			mkpath ( $dst_file, {verbose => 1} );
						
			copy( $src_file, "$dst_file\\$filename" );
		}

		# PACKER
		if ( $filename =~ m/PACKER_([0-9]{2})-([0-9]{2})-([0-9]{4})_([0-9]{6})/i )
		{			
			my $src_file = "$src_dir\\reports\\$filename";	
			my $dst_file = "$dst_dir\\$3\\$2\\$1";	
			
			mkpath ( $dst_file, {verbose => 1} );
						
			copy( $src_file, "$dst_file\\$filename" );
		}			
	} 		
}

# Global variables

my %KAV_ARCHIVE_STAT;	
my %KAV_PACKER_STAT;
my %SAMPLE_STATS;

my %TOTAL_KAV_ARCHIVE_STAT;	
my %TOTAL_KAV_PACKER_STAT;
my %TOTAL_SAMPLE_STATS;

sub LoadSampleStats ( $$ )
{
	my $rpt_file = shift;
	my $label = shift;
	
	my $source = "UNKNOWN";
	open( IN, "< $rpt_file" ) or return 0;	
	my @data = <IN>;
	close IN;
	
	foreach my $entry ( @data )
	{
		if ( $entry =~ /Source,\s*(.*)\s*/i )
		{
			$source = lc($1);			 			
		}
		elsif ( $entry =~ m/(.*),\s*([0-9]{1,8})/i )
		{
			# Save sourcewise count
			my $t = "$label, $source, $1";
			my $count = $2;
			
			if ( exists ($SAMPLE_STATS{ $t }) )
			{
				my $t1 = $SAMPLE_STATS{ $t };
				$t1 = $t1 + $count;
				$SAMPLE_STATS{ $t } = $t1;
			}
			else
			{
				$SAMPLE_STATS{$t} = $count;
			}					
			
			# Save Total count 
			$t = "$label, $1";			
			
			if ( exists ($TOTAL_SAMPLE_STATS{ $t } ) )
			{
				my $t1 = $TOTAL_SAMPLE_STATS{ $t };
				$t1 = $t1 + $count;
				$TOTAL_SAMPLE_STATS{ $t } = $t1;
			}
			else
			{
				$TOTAL_SAMPLE_STATS{ $t } = $count;
			}								
		}
	}	
}

sub LoadArchiveStats ( $$ )
{
	my $rpt_file = shift;
	my $label = shift;
	
	my $source = "UNKNOWN";
	open( IN, "< $rpt_file" ) or return 0;	
	my @data = <IN>;
	close IN;
	
	foreach my $entry ( @data )
	{
		if ( $entry =~ /Source,\s*(.*)\s*/i )
		{
			$source = lc($1);			 			
		}
		elsif ( $entry =~ m/(.*),\s*([0-9]{1,8})/i )
		{
			#print "$entry\n";
			# Save sourcewise count
			my $t = "$label, $source, $1";
			my $count = $2;
			my $a = $1;
			
			if( ! ( $entry =~ /UNKNOWN,\s+([0-9]+)/ ) )
			{						
				if ( exists ($KAV_ARCHIVE_STAT{ $t } ) )
				{
					my $t1 = $KAV_ARCHIVE_STAT{ $t };
					$t1 = $t1 + $count;
					$KAV_ARCHIVE_STAT{ $t } = $t1;
				}
				else
				{
					$KAV_ARCHIVE_STAT{ $t } = $count;
				}							
				
				# Save Total count
				$t = "$label, $1";		
				
				if ( exists ( $TOTAL_KAV_ARCHIVE_STAT{ $t } ) )
				{
					my $t1 = $TOTAL_KAV_ARCHIVE_STAT{ $t };
					$t1 = $t1 + $count;
					$TOTAL_KAV_ARCHIVE_STAT{ $t } = $t1;
				}
				else
				{
					$TOTAL_KAV_ARCHIVE_STAT{$t} = $count;
				}
			}
			else
			{
				#print "Warning: $rpt_file Archive $a\n";
			}							
		}
	}	
}

sub LoadPackerStats ( $$ )
{
	my $rpt_file = shift;
	my $label = shift;
	
	my $source = "UNKNOWN";
	open( IN, "< $rpt_file" ) or return 0;	
	my @data = <IN>;
	close IN;
	
	foreach my $entry ( @data )
	{
		if ( $entry =~ /Source,\s*(.*)\s*/i )
		{
			$source = lc($1);			 			
		}
		elsif ( $entry =~ m/(.*),\s*([0-9]{1,8})/i )
		{
			# Save sourcewise count
			my $t = "$label, $source, $1";
			my $count = $2;

			if ( exists ($KAV_PACKER_STAT{$t}) )
			{
				my $t1 = $KAV_PACKER_STAT{$t};
				$t1 = $t1 + $count;
				$KAV_PACKER_STAT{$t} = $t1;
			}
			else
			{
				$KAV_PACKER_STAT{$t} = $count;
			}					
			
			# Save Total count
			$t = "$label, $1";
			
			if ( exists ($TOTAL_KAV_PACKER_STAT{$t}) )
			{
				my $t1 = $TOTAL_KAV_PACKER_STAT{$t};
				$t1 = $t1 + $count;
				$TOTAL_KAV_PACKER_STAT{$t} = $t1;
			}
			else
			{
				$TOTAL_KAV_PACKER_STAT{$t} = $count;
			}					
		}
	}	
}

sub SaveReport( )
{	
	# save detailed Archive stats
	open( OUT, "> $detailed_archive_stat_file" );	
	my @names = sort keys ( %KAV_ARCHIVE_STAT );	
	
	my %DATES = ( );
	my %TYPES = ( );
	my %SOURCES = ( );
	
	for my $key ( @names )
	{		
		my @parts = split( /,/, $key );
		my $cnt = @parts;
		if($cnt >= 4)
		{
			$DATES{$parts[0]} = "";
			$parts[1] =~ s/\s*//;			
			$SOURCES{ $parts[1] } = "";				
			$TYPES{ "$parts[2],$parts[3]" } = "";
		}
		else
		{
			#print "Warning: Archive info [$key]\n";
		}
	}

	my @uniq_dates = sort keys ( %DATES );	
	my @uniq_types = sort keys ( %TYPES );	
	my @uniq_sources = sort keys ( %SOURCES );	
	
	for my $source ( @uniq_sources )
	{
		print OUT "Source: $source\n\n";			
		print OUT "Date, ";
		
		for my $type ( @uniq_types )
		{
			my $t = $type;
			$t =~ s/,\s*/-/;
			print OUT "$t,";
		}
		
		for my $date ( @uniq_dates )
		{
			print OUT "\n$date, ";
			for my $type ( @uniq_types )
			{
				my $key = "$date, $source,$type";						
				my $value = 0 ;
				if ( exists ( $KAV_ARCHIVE_STAT{ $key } ) )
				{
					$value = $KAV_ARCHIVE_STAT{ $key };
				}
				print OUT "$value, ";
			}
		}
		print OUT "\n\n";
	}
	
	close OUT;
	
	# save Archive stats	
	@names = sort keys ( %TOTAL_KAV_ARCHIVE_STAT );	
	
	%DATES = ( );
	%TYPES = ( );
		
	for my $key ( @names )
	{		
		my @parts = split( /,/, $key );
		my $cnt = @parts;
		if($cnt >= 3)
		{
			$DATES{$parts[0]} = "";			
			$TYPES{"$parts[1],$parts[2]"} = "";
		}
		else
		{
			#print "Warning: Archive info [$key]\n";
		}		
	}

	@uniq_dates = sort keys ( %DATES );	
	@uniq_types = sort keys ( %TYPES );	
		
	open( OUT, "> $archive_stat_file" );	
	print OUT "Date, ";
	
	for my $type ( @uniq_types )
	{
		my $t = $type;
		$t =~ s/,\s*/-/;
		print OUT "$t, ";
	}
	
	for my $date ( @uniq_dates )
	{
		print OUT "\n$date, ";
		for my $type ( @uniq_types )
		{
			my $key = "$date,$type";						
			my $value = 0 ;
			if ( exists ( $TOTAL_KAV_ARCHIVE_STAT{ $key } ) )
			{
				$value = $TOTAL_KAV_ARCHIVE_STAT{ $key };
			}
			print OUT "$value, ";
		}
	}
	
	close OUT;


	# Save detailed packer stats
	open( OUT, "> $detailed_packer_stat_file" );	
	@names = sort keys ( %KAV_PACKER_STAT );		
	
	%DATES = ( );
	%TYPES = ( );
	%SOURCES = ( );
	
	for my $key ( @names )
	{		
		my @parts = split( /,/, $key );
		my $cnt = @parts;
		if($cnt >= 3)
		{
			$DATES{ $parts[0] } = "";
			$parts[1] =~ s/\s*//;			
			$SOURCES{ $parts[1] } = "";		
			$TYPES{ $parts[2] } = "";
		}
		else
		{
			#print "Warning: Archive info [$key]\n";
		}
		
	}

	@uniq_dates = sort keys ( %DATES );	
	@uniq_types = sort keys ( %TYPES );	
	@uniq_sources = sort keys ( %SOURCES );	

	for my $source ( @uniq_sources )
	{	
		print OUT "Source: $source\n\n";		
		print OUT "Date, ";
		
		for my $type ( @uniq_types )
		{
			print OUT "$type,";
		}
		
		for my $date ( @uniq_dates )
		{
			print OUT "\n$date, ";
			for my $type ( @uniq_types )
			{
				my $key = "$date, $source,$type";						
				my $value = 0 ;
				if ( exists ( $KAV_PACKER_STAT{ $key } ) )
				{
					$value = $KAV_PACKER_STAT{ $key };
				}
				print OUT "$value, ";
			}
		}		
		print OUT "\n\n";
	}
	close OUT;	

	# Save packer stats	
	@names = sort keys ( %TOTAL_KAV_PACKER_STAT );		
	
	%DATES = ( );
	%TYPES = ( );
	
	for my $key ( @names )
	{		
		my @parts = split( /,/, $key );
		$DATES{ $parts[0] } = "";		
		$TYPES{ $parts[1] } = "";
	}

	@uniq_dates = sort keys ( %DATES );	
	@uniq_types = sort keys ( %TYPES );	
	
	open( OUT, "> $packer_stat_file" );					
	print OUT "Date, ";
	
	for my $type ( @uniq_types )
	{
		print OUT "$type, ";
	}
	
	for my $date ( @uniq_dates )
	{
		print OUT "\n$date, ";
		for my $type ( @uniq_types )
		{
			my $key = "$date,$type";						
			my $value = 0 ;
			if ( exists ( $TOTAL_KAV_PACKER_STAT{$key } ) )
			{
				$value = $TOTAL_KAV_PACKER_STAT{ $key };
			}
			print OUT "$value, ";
		}
	}

	close OUT;
	
	# Save detailed samples stats			
	@names = sort keys ( %SAMPLE_STATS );			
	%DATES = ( );
	%TYPES = ( );
	%SOURCES = ( );
	
	for my $key ( @names )
	{		
		my @parts = split( /,/, $key );
		$DATES{ $parts[0] } = "";		
		$parts[1] =~ s/\s*//;		
		$SOURCES{ $parts[1] } = "";		
	}

	@uniq_dates = sort keys ( %DATES );	
	#@uniq_types = ("Total Received", "Unique samples", "QH Detected", "Adware", "Backdoor", "Trojan", "Worm", "Virus", "Bulk-Add-2", "Non-pe", "Signed", "Version-MS", "Archive", "Skipped", "Undetected", "CLEAN");

	@uniq_types = ("Total Received", "Unique samples", "QH Detected", "Adware", "Backdoor", "Trojan", "Worm", "Virus", "For-Generic", "Symc-generic", "Bulk-Add-2", "Non-pe", "Signed", "Version-MS", "Archive", "Skipped", "Undetected", "CLEAN", "Undetected Total PE", "Undetected Total non-PE", "Undetected PE-EXE", "Undetected PE-DLL", "Undetected PE-DRIVER", "Undetected PE-VB", "Undetected PE64-EXE", "Undetected PE64-DLL", "Undetected PE64-DRIVER", "PDF", "SCRIPT", "ANDRIOD APK", "ANDRIOD DEX", "Mac", "Mac-Archive", "Corrupt");
	
	@uniq_sources = sort keys ( %SOURCES );	
	
	open( OUT, "> $detailed_samples_stat_file" );	
	
	for my $source ( @uniq_sources )
	{
		print OUT "Source: $source\n\n";				
		print OUT "Date, ";
		
		for my $type ( @uniq_types ) { print OUT "$type, ";	}
		
		for my $date ( @uniq_dates )
		{
			print OUT "\n$date, ";
			for my $type ( @uniq_types )
			{
				my $key = "$date, $source, $type";					
				my $value = 0;
				if ( exists ( $SAMPLE_STATS{ $key } ) )
				{
					$value = $SAMPLE_STATS{ $key };
				}
				print OUT "$value, ";
			}
		}		
		print OUT "\n\n";
	}
	
	close OUT;
	
	# Save combined samples stats
	open( OUT, "> $samples_stat_file" );	
  @names = sort keys ( %TOTAL_SAMPLE_STATS );		
	
	%DATES = ( );
	%TYPES = ( );	
	
	for my $key ( @names )
	{		
		my @parts = split( /,/, $key );
		$DATES{ $parts[0] } = "";		
	}

	@uniq_dates = sort keys ( %DATES );	
	##
	### @uniq_types = ("Total Received", "Unique samples", "QH Detected", "Adware", "Backdoor", "Trojan", "Worm", "Virus", "For-Generic", "Symc-generic", "Bulk-Add-2", "Non-pe", "Signed", "Version-MS", "Archive", "Skipped", "Undetected", "CLEAN", "Undetected Total PE", "Undetected Total non-PE", "Undetected PE-EXE", "Undetected PE-DLL", "Undetected PE-DRIVER", "Undetected PE-VB", "Undetected PE64-EXE", "Undetected PE64-DLL", "Undetected PE64-DRIVER", "PDF", "SCRIPT", "ANDRIOD APK", "ANDRIOD DEX", "Mac", "Mac-Archive", "Corrupt");
	##
	print OUT "Date, ";
	
	for my $type ( @uniq_types ) { print OUT "$type, ";	}
	
	for my $date ( @uniq_dates )
	{
		print OUT "\n$date, ";
		for my $type ( @uniq_types )
		{
			my $key = "$date, $type";					
			my $value = 0;
			if ( exists ( $TOTAL_SAMPLE_STATS{ $key } ) )
			{
				$value = $TOTAL_SAMPLE_STATS{ $key };
			}
			print OUT "$value, ";
		}
	}		
	print OUT "\n\n";
			
	close OUT;
}

sub ListStatFiles( $ );

sub ListStatFiles( $ )
{
	my $src_dir = shift;
		
	my $src_file = "";

	opendir( SRCDIR, $src_dir );
	my( @files ) = grep( !/^\./, readdir( SRCDIR ));
	closedir( SRCDIR );	
	my $md5;	
	
	my @RET;
	
	for my $filename ( @files )
	{
		$src_file = "$src_dir\\$filename";	    
		
		if($filename =~ /^ARCHIVE_[0-9]{2}-[0-9]{2}-[0-9]{4}_[0-9]{6}\.csv$/)
		{
			#print "\n $src_file";	
			@RET = (@RET, $src_file);
		}
		
		if($filename =~ /^PACKER_[0-9]{2}-[0-9]{2}-[0-9]{4}_[0-9]{6}\.csv$/)
		{
			#print "\n $src_file";	
			@RET = (@RET, $src_file);
		}
		
		if($filename =~ /^STATS_[0-9]{2}-[0-9]{2}-[0-9]{4}_[0-9]{6}\.csv$/)
		{
			#print "\n $src_file";	
			@RET = (@RET, $src_file);
		}

		my @r1 = ListStatFiles( $src_file ) if ( -d $src_file );
    @RET = (@RET, @r1); 	     
	}		
	
	return @RET;
}

sub LoadReports(  $$$ )
{
	my $stats_dir = shift;
	my $date = shift;
	my $label = shift;
	
	#$date =~ s/-/\\/g;
	$date =~ s/-//g;
	
	print " $stats_dir\\$date \n"; 
	
	if( ! (-d "$stats_dir\\$date") )
	{
		print "      Error: Directory $stats_dir\\$date not present ! \n";
		return;
	}
	
	my @files = ListStatFiles("$stats_dir\\$date");
	
 	for my $filename ( @files )
	{		
		# Stats
		if ( $filename =~ m/STATS_([0-9]{2})-([0-9]{2})-([0-9]{4})_([0-9]{6})/i )
		{				
			LoadSampleStats( $filename, $label );
		}

		# Archive
		if ( $filename =~ m/ARCHIVE_([0-9]{2})-([0-9]{2})-([0-9]{4})_([0-9]{6})/i )
		{			
			LoadArchiveStats( $filename, $label );
		}

		# PACKER
		if ( $filename =~ m/PACKER_([0-9]{2})-([0-9]{2})-([0-9]{4})_([0-9]{6})/i )
		{			
			LoadPackerStats( $filename, $label );
		}			
	} 			
}

sub GenerateReport( $$$$ )
{
	my $stats_dir = shift;
	my $start = shift;
	my $end = shift;
	my $diff = shift;
	my $start_date = "";
	my $end_date = "";	
	
	my $t1 = "";
	my $t2 = "";
	
	if( $start =~ m/([0-9]{4})\/([0-9]{1,2})\/([0-9]{1,2})/ )
	{	
		$start_date = DateTime->new(year=>$1, month=>$2, day=>$3);
		$t1 = "$1-$2-$3"; 
	}
	else
	{
		PrintUsage( );
	}
	
	if( $end =~ m/([0-9]{4})\/([0-9]{1,2})\/([0-9]{1,2})/ )
	{
		$end_date = DateTime->new(year=>$1, month=>$2, day=>$3);
		$t2 = "$1-$2-$3"; 
	}
	else
	{
		PrintUsage( );
	}
	
	$archive_stat_file = "$stats_dir\\archive_stats.csv";
	$packer_stat_file  = "$stats_dir\\packer_stats.csv";;
	$samples_stat_file = "$stats_dir\\samples_stats.csv";;

	$detailed_archive_stat_file = "$stats_dir\\archive_stats_detailed.csv";
	$detailed_packer_stat_file  = "$stats_dir\\packer_stats_detailed.csv";;
	$detailed_samples_stat_file = "$stats_dir\\samples_stats_detailed.csv";;
		
	if ($diff < 1 || $diff > 100)
	{
		PrintUsage( );
	}
	                 
	my @datelist = ( );

	my $dt = $start_date;	
	my $days = 0;
	
	print "\n Generating report : \n\n";
	my $label = $dt->ymd('-');	

	until ( DateTime->compare($dt,$end_date) == 1 ) 
	{	
		unshift(@datelist, $dt->ymd('-'));		
		$dt->add( days => 1 );
		$days = $days + 1;
		
		if ( $days >= $diff  )
		{
			@datelist = reverse ( @datelist );
			foreach my $t ( @datelist )
			{
				LoadReports ( $stats_dir, $t, $label );				
			}							
		
			# initilize data structures
			$days = 0;
			@datelist = ( );			
			$label = $dt->ymd('-');	
		}	
		# 
	}	
	
	# save report for last chunk of days
	if ( $diff  > 0 )
	{
		@datelist = reverse ( @datelist );
		foreach my $t ( @datelist )
		{
			LoadReports ( $stats_dir, $t, $label );				
		}				
	}

	SaveReport( );	
}

sub PrintUsage( )
{

 print <<EOF;

Quick Heal Tecnhologies Pvt. Ltd.

Generates Archive, Packer and processed samples statistics specified between date range. 


Usage: $APPNAME GENERATE_REPORT <stats folder> <start date> <end date> <span>
date format: yyyy/mm/dd

e.g. $APPNAME GENERATE_REPORT c:\\QH\\stats 2010/01/01 2010/01/31 7

Usage: $APPNAME COPY_STATS <root of source folder> <root of destination folder>

e.g.  $APPNAME COPY_STATS c:\\Processed c:\\stats

for comments or suggestions please contact Rajesh (at) QuickHeal (dot) com
EOF
	
	exit;
}

my $count = @ARGV;


if ( $count == 3 )
{	
	if  ( $ARGV[0] =~ /COPY_STATS/i )		
	{
		CopyStats( $ARGV[1], $ARGV[2] );
		exit;
	}	
}

if ( $count == 5 )
{	
	if  ( $ARGV[0] =~ /GENERATE_REPORT/i )		
	{		
		GenerateReport( $ARGV[1], $ARGV[2], $ARGV[3], $ARGV[4] );
		exit;
	}
}

PrintUsage( );