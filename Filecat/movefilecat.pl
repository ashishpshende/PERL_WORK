use Digest::MD5;
use File::Copy;
use File::Path;

use strict;


sub RenamewithMD5($$)
{
	my $src_dir = shift;
	my $out = shift;
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
    
    open FH, ">> $out\\sample-md5.csv";
		print FH $md5, ", $src_file, $filename, ", -s $src_file, ", \n";    
		close FH;
    
    #print "$src_file ==> $dst_file\n";
    
    move( "$src_file", "$dst_file" );
    print "$dst_file\n";
   
	}		
}

sub PrintUsage( )
{

 print <<EOF;

Quick Heal Tecnhologies Pvt. Ltd.

Usage: copyfilecat.pl <srd> <dest>
This tool copies the file by filetype.

Make sure that mpa_filetype.exe is present in utils dir.

for comments or suggestions please contact vishald\@quickheal\.com
EOF
	
	exit;
}

if ( $ARGV[0] &&  $ARGV[1])
{
	RenamewithMD5($ARGV[0], $ARGV[1]);
	Filecat($ARGV[0] , $ARGV[1])	
}
else 
{
	PrintUsage();
}

sub Filecat($$)	
{
	my $src = shift;
	my $dest = shift;

	my $cmd = "mpa_filetype.exe /rd $ARGV[0] > $ARGV[1]\\filetype.csv";
	qx($cmd);
	open (IN, "<" , "$dest\\filetype.csv") or die "Unable to open the filetype.csv";
	my @data = <IN>;
	close IN;
	foreach my $line (@data)
	{
		my @kk = split(/,/,$line);
		my $sfile = $kk[0];
		$kk[1] =~ s/^ //;
		my $dfile = "$dest\\$kk[1]";
		mkpath($dfile);
		move ($sfile, $dfile);
		
	}
}


