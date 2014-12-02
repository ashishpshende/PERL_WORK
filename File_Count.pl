#!perl
#  
#  Author: Vishal Dodke
#    
#  Created on : 06-July-2010
# 
#  Created to find the file count
#
###########################################################################
use strict;
use warnings;

sub FileCount($$)
{
    my $log = shift;
	my $output_dir  = shift;
	my $out_file = "$output_dir\\TOP.csv";
	my %ALL;



	open (IN, "<" , "$log") or die "Unable to open the file";
	my @lines = <IN>;
	close IN;

	open (OUT, ">" , "$out_file") or die "Unable to open the file";


	foreach my $line(@lines)
	{
		chomp($line);
		if (exists $ALL{$line})
		{
			$ALL{$line} = $ALL{$line} + 1;
			next;
		}
		$ALL{$line}=1;
		
		
	}

	my $key;

	foreach $key(keys %ALL)
	{
		print"$key ==> $ALL{$key}\n";
		print OUT "$key,$ALL{$key}\n";
	}
}

sub Print_Usage( )
{
	print <<EOF;
	
Quick Heal Tecnhologies Pvt. Ltd.

Usage: FileCount.pl <log.txt> <Output_dir>.

for comments or suggestions please contact vishald\@quickheal\.com	
EOF
	exit;

}

if ($ARGV[0] && $ARGV[1] )
{
	FileCount($ARGV[0] , $ARGV[1] );
}
	
else
{
	Print_Usage ( );
}