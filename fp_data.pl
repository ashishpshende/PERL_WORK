
use File::Path;
use Digest::MD5;
use File::Copy;
use LWP::UserAgent;
require HTTP::Request;

use POSIX;

use strict;

my $tools_dir = "c:\\tools";
my $sample_server = "http://192.168.50.201/claddrec.php";

my $DST_DIR = "";
my $HDD = "";
my $log_file = "fp_data.log";
my $move_file_log = "movefile.log";
my $duplicate_log = "duplicate_log.csv";

my %FILE_TYPE;

sub WriteToLog( $$ )
{
	my $log_filename = shift;
	my $data = shift;
	
	open( LOG, ">> $log_filename" ) or return;	
	print LOG $data;
	close LOG;
}


sub IsDuplicate($$$$)
{
	my $md5 = shift;	
	my $src_file = shift;
	my $dst_file = shift;
	my $hdd = shift;
		
	my $ua = LWP::UserAgent->new;	
	my $url = "$sample_server?MD5=$md5&OFILEPATH=$src_file&NFILEPATH=$dst_file&SOURCE=$hdd";
	
	my $request = HTTP::Request->new(GET => $url);
	my $response = $ua->request($request);
	
	if ($response->is_success) 
	{
	    if ( $response->decoded_content =~ /RECORDED/) 
	    {
	    	return "NEW";
	    }
	    else
	    {
	    	return "DUPLICATE";
	    }
	}
	
	return "ERROR";
}

sub GetFileType( $ )
{
	my $src_file = shift;
	my $command = "$tools_dir\\fp_filetype.exe /f \"$src_file\"";					
	my $output = qx( $command );													
	
	#print "--$output\n";
	
	my @a = split( /,/, $output);
	my $len = @a;
	
	my $ft = "UNKNOWN";
	if( $len >= 2 )
	{
		$ft = $a[-1];
	}
	
	if( $ft =~ m/^$/ )
	{
		$ft = "UNKNOWN";
	}
	
	$ft =~ s/\s+//g;
	$ft =~ s/-/\\/;
	
	return $ft;
}

sub GetMD5( $ )
{	
	my $src_file = shift;
	my $md5 = "ERROR";
	
	eval 
	{
		open( FILE, $src_file );
		binmode( FILE );
		$md5 = uc( Digest::MD5->new->addfile( *FILE )->hexdigest );
		close( FILE );		
	};
	
	if ($@) 
  {
  	WriteToLog( $log_file, "$src_file, GetMD5 Failed !, $@->what" );
  }
	
	return $md5;
}

sub ListMD5( $ )
{
	my $src_dir = shift;		
	my $src_file = "";
	
	opendir( SRCDIR, $src_dir );
	my( @files ) = grep( !/^\./, readdir( SRCDIR ));
	closedir( SRCDIR );	
	my $md5;	
	
	for my $filename ( @files )
	{
		$src_file = "$src_dir\\$filename";	
    
    stat( $src_file );       
    
    if ( -d $src_file )
    {
    	ListMD5( $src_file );	
    }
    else
    {
    	$md5 = GetMD5( $src_file );    	   	
    	
    	#print "$md5 -";
    	
    	if( $md5 =~ /^ERROR/ )
    	{    		
    		next;
    	}
    	
    	my $ft = GetFileType( $src_file );
    	my $t1 = 1;    	
    	
    	#print "$ft -\n";
    	    	
			if ( exists ($FILE_TYPE{ $ft } ) )
			{
				$t1 = $FILE_TYPE{ $ft };
				$t1 = $t1 + 1;
				$FILE_TYPE{ $ft } = $t1;
			}
			else
			{
				$FILE_TYPE{ $ft } = 1;
				$t1 = 1;
			}					   	

		  #print ", $t1\n"; 
			my $folder_index = floor($t1 / 20000);    		
    	
    	my $parent_dir = "$DST_DIR\\$ft\\$folder_index";
    	my $dst_file = "$parent_dir\\$md5"; 
    	
    	#my $ret = IsDuplicate($md5, $src_file, $dst_file, $HDD);
	my $ret = "NEW";
    	#WriteToLog( $log_file, "$md5, $src_file, $HDD, $ft, $ret \n");
    	
    	eval 
			{
	    	if( $ret =~ m/^NEW/ )
	    	{
	    		mkpath( $parent_dir );
	    		copy ( $src_file, $dst_file );    		
	    		#print "$src_file ==>  [$dst_file]\n";
	    		print "$src_file \n";
	    		#WriteToLog( $move_file_log, "$src_file ==>  [$dst_file]\n");    
	    	}
				else
				{
					unlink($src_file);
					#WriteToLog( $duplicate_log, "$md5, $src_file, $ret\n");    
				}			
			};		
			if ($@) 
		  {
		  	WriteToLog( $log_file, "$src_file, $@->what" );
		  }				
		}		
	}		
}


if( $ARGV[0] && $ARGV[1] && $ARGV[2] )
{
	if ( -d $ARGV[0] )
	{
		print "\n Please wait Clean Data Collection is in progress ...\n";		

		if ( -d $ARGV[1]  )
		{
			$DST_DIR = $ARGV[1] ;	
			$HDD = $ARGV[2];
			ListMD5( $ARGV[0] );
			exit;
		}		
	}
}

print "\n Usage: fp_data.pl <source dir> <destination file> <HDD Tag>\n";
