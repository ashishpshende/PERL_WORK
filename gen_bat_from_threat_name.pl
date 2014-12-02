#!perl    
#  
#  Author: Sanjay Bhosale
# 
#  Quick Heal Technologies Pvt. Ltd.
#  Date: 12-02-2014
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

my $APPNAME = "get_sah2_from_threat_name.pl";

my $db_name = "collection_db";
my $db_server = "192.168.50.203";
my $db_user = "mlab";
my $db_password = "helloworld";
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
	print "\n Usage : \n\t $APPNAME <Threat Name> <Batch File Name>\n";
}


###########################################
#
# M A I N  S T A R T S  H E R E 
#

$| = 1;

my $argc = @ARGV;

if( $argc == 2)
{
	my $threat_name = $ARGV[0];
	my $batch_file_name = $ARGV[1];
	
	DBConnect($db_name, $db_server, $db_user, $db_password, 1);

	my $query = "SELECT `SHA2` FROM `collectiondb_detected_file_info` where `Detection_Name` LIKE '%$threat_name'";

	my $statement_handle;

	if( !( $statement_handle = $database_handle->prepare($query) ) )
	{
		$debug_str = " Error in prepare statement. \n<$database_handle->errstr> \n";
		print $debug_str;
	}
	else
	{
		if( !($statement_handle->execute() ) )
		{
			$debug_str = "  Error in execute statement. \n<$database_handle->errstr> \n[$query]\n";
			$statement_handle->finish;
			print $debug_str;
		}
		else
		{
			my $resultrow;

			if( ( $statement_handle != -1 ) && ( $statement_handle != 0 ) && (0 != $statement_handle->rows ))
			{
				open(FD, "> $batch_file_name") or die(" Unable to open file : $batch_file_name");
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
	DBDisconnect();
}
else
{
	PrintUsage();
}