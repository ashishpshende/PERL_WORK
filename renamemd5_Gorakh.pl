use Digest::MD5;
use File::Copy;

use strict;


sub RenamewithMD5($)
{
	my $src_dir = shift;
	my $dst_dir = $src_dir;
		
	my $src_file = "";
	my $dst_file = "";
	my $temp = "_";

	opendir( SRCDIR, $src_dir );
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
        
    $dst_file = "$src_dir\\$md5";
    
   # print $md5, ", $src_file, $filename, ", -s $src_file, ", \n";    
    
    open FH, ">> sample-md5.csv";
		print FH $md5, ", $src_file, $filename, ", -s $src_file, ", \n";    
		close FH;
    
    #print "$src_file ==> $dst_file\n";
    
    move( "$src_file", "$dst_file" );
    print "\n\nRename=>$src_file, $dst_file\n\n";
   
	}		
}

sub PrintUsage( )
{

 print <<EOF;

Quick Heal Tecnhologies Pvt. Ltd.

Usage: renamemd5.pl sourcefolder
e\.g\. renamemd5\.pl d\:\\temp
This tool renames files with MD5 recursively.

for comments or suggestions please contact vishald\@quickheal\.com
EOF
	
	exit;
}

if ( $ARGV[0] )
{
	RenamewithMD5($ARGV[0]);
}
else 
{
	PrintUsage();
}


