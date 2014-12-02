#!perl    
#  
#  Author: Sanjay Bhosale
# 
#  Quick Heal Technologies Pvt. Ltd.
#  Date: 17-02-2014
#   
###########################################################################

use strict;
use warnings;

use DBI;


##################################################
#
# Global variables
#
#####

my $APPNAME = "gen_bat_from_md5_list.pl";

my $db_name = "collection_db";
my $db_server = "192.168.50.203";
my $db_user = "mlab";
my $db_password = "helloworld";
# my $db_server = "127.0.0.1";
# my $db_user = "root";
# my $db_password = "";
my $debug_str;

my $database_handle;

sub die_handler 
{ 
	# 1st argument is signal name
	my($sig) = @_;
	$debug_str = "$sig Exiting !!!\n";
	print $debug_str;
	exit(0);
}

$SIG{__DIE__} = \&die_handler;

sub DBConnect( $$$$$ )
{
	my $DatabaseName = shift;
	my $ServerAddress = shift;
	my $user_name = shift;
	my $password = shift;
	my $error = shift;

	my $dsn = "DBI:mysql:database=$DatabaseName;host=$ServerAddress";

	if( $error == 1 )
	{
		$database_handle = DBI->connect( $dsn, $user_name, $password, { RaiseError => 1 } );
	}
	else
	{
		$database_handle = DBI->connect( $dsn, $user_name, $password, { RaiseError => 0 } );
	}

	if( !$database_handle )
	{
		$debug_str = "DBConnect: failed ! " . $database_handle->errstr;
		print $debug_str;
	}
	else
	{
		$debug_str = "DBConnect: Successful.\n";
		print $debug_str;
	}
}


sub DBDisconnect( )
{
	if( !( $database_handle->disconnect() ) )
	{
		$debug_str = "DBDisconnect: failed ! " . $database_handle->errstr;
		print $debug_str;
	}
	else
	{
		$debug_str = "DBDisconnect: Done.\n";
		print $debug_str;
	}
	
}

sub PrintUsage
{
	print "\n Usage : \n $APPNAME <File With MD5 List> <Batch File Name>\n";
}


sub GenerateBatFile( $$ )
{
	my $md5_list = shift;
	my $bat_file = shift;
	my $query = "SELECT `SHA2` FROM `collectiondb_file_hash_info` where `MD5` = ";
	
	open( BAT_FILE, " > $bat_file" ) or return -1;
	close BAT_FILE;
	
	open( MD5_FILE, "< $md5_list" ) or die( "Unable to open file $md5_list" );
	my @md5_list = <MD5_FILE>;
	close MD5_FILE;
	
	DBConnect($db_name, $db_server, $db_user, $db_password, 1);

	foreach my $md5 ( @md5_list )
	{
		$md5 =~ s/\s+//g;
		my $query1 = "$query '$md5'";

		my $statement_handle;

		if( !( $statement_handle = $database_handle->prepare($query1) ) )
		{
			$debug_str = " Error in prepare statement. \n<$database_handle->errstr> \n";
			print $debug_str;
		}
		else
		{
			if( !($statement_handle->execute() ) )
			{
				$debug_str = "  Error in execute statement. \n<$database_handle->errstr> \n[$query1]\n";
				$statement_handle->finish;
				print $debug_str;
			}
			else
			{
				my $resultrow;

				if( ( $statement_handle != -1 ) && ( $statement_handle != 0 ) && (0 != $statement_handle->rows ))
				{
					open(FD, ">> $bat_file") or die(" Unable to open file : $bat_file");
					while ( $resultrow = $statement_handle->fetchrow_hashref )
					{
						my $sha2 = $resultrow->{SHA2};
						if( $sha2 =~ /^([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{60})$/i)
						{
							print FD "copy \\\\192.168.30.200\\Public\\$1\\$2\\$sha2.bin\n";
						}
					}
					close FD;
				}
				else
				{
					print "\n No information found \n";
				}
				$statement_handle->finish;
			}
		}
	}
	DBDisconnect();
	return 1;
}


###########################################
#
# M A I N  S T A R T S  H E R E 
#

$| = 1;

my $argc = @ARGV;

if( $argc == 2)
{
	my $md5_file_name = $ARGV[0];
	my $batch_file_name = $ARGV[1];
	
	if( -f $md5_file_name )
	{
		my $return_value = GenerateBatFile( $md5_file_name, $batch_file_name );
		if( $return_value != 1)
		{
			print "\n Unable to open file $batch_file_name ";
			PrintUsage( );
		}
	}
	else
	{
		PrintUsage( );
	}
}
else
{
	PrintUsage();
}