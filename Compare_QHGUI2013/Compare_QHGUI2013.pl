use strict;
use warnings;

my %ORG;
my %NEW;

my $chk = "File is skipped";

sub parseQH_GUI($)
{
	my $file = shift;
	my %CURRENT = "";

	open(IN,  "<" , "$file") or die "unable to open $file\n";
#  open( IN, "<:encoding(UTF-16)", $file ) or die "\n\n Error:  $file !!! \n\n";			
	my @lines;
	while ( <IN> ) 
	{
		chomp;
		push ( @lines, $_ );
	}
	my @super =  join(" ", @lines);
	close IN;
	my @Data = split(/$chk/,$super[0]);	

	foreach my $line (@Data) 
	{
		if ($line =~/-------------------------------------------------------  (.*) Detected: \"(.*)\"\s+/)
		{
			$CURRENT{$1} = $2;
			next;
		}	
		if ($line =~/  (.*) Detected: \"(.*)\"\s+/) 
		{
			$CURRENT{$1} = $2;
		}	
	}	
	close OUT;
	return (%CURRENT);
}

sub compare()
{
	open (OUT, ">" , "Difference.csv") or die "dies\n";
	print OUT "File-Path,Org-Name,New-Name\n";
	foreach my $key (keys %ORG)
	{
		if (exists $NEW{$key})
		{
			if ($ORG{$key} eq $NEW{$key}) 
			{
				next; # fine
			}
			else
			{
				print OUT "$key,$ORG{$key},$NEW{$key}\n";
			}
		}
	}
}

if ($ARGV[0] && $ARGV[1])
{
	%ORG = parseQH_GUI($ARGV[0]);
	%NEW = parseQH_GUI($ARGV[1]);
	compare();
}

else
{
	print "Usage:Compare_QHGUI2013.pl <ScanReport1> <ScanReport2>\n";
}