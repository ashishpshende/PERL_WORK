use Digest::MD5;
use File::Copy;
use Cwd;
use File::Path;

use strict;

sub CopyFiles( $$ )
{
	my $file = shift;
	my $dst_dir = shift;
	
	open( IN, "< $file" ) or die "\n Error: $! $file !!! \n";				
	my @data = <IN>;
	close IN;
	
	my $folder_index = 0;
	my $sample_count = 0;
	
	foreach my $entry ( @data )
	{			
		my @t = split( /,\s*/, $entry );
		
		$t[1] =~ s/-/\\/g;
		my $src_file = $t[0];
		if( -e $src_file )
		{
	    open( FILE, $src_file ) or next;
	    binmode( FILE );
	    my $md5 = Digest::MD5->new->addfile( *FILE )->hexdigest;
			
			my $dst_file = "$dst_dir\\$t[1]\\$folder_index";
			if(!( -e "$dst_file\\$md5" ) )
			{
				mkpath(	$dst_file );
				print " $src_file ==> $dst_file \n";
				copy( $src_file, "$dst_file\\$md5" );   		
			
				$sample_count++;
				if( $sample_count > 10000 )		
				{
					$folder_index++;
				}
			}
		}
		else
		{
			print " file Not Found: $src_file \n";
		}
	}
}

if( $ARGV[0] && $ARGV[1] ) 
{
	CopyFiles( $ARGV[0], $ARGV[1] );
}
else
{
	print "\n Usage: <path to found.csv> <dst dir>\n"
}
