use strict;
use warnings;

sub check_type($)
{
	my $src = shift;
	
	my $filetype = "$src\\filetype.csv";
	my $cmd = "mpa_filetype.exe /rd $src > $filetype";
	qx($cmd);

	open(IN, "<" , "$filetype") or die "Unable to open the required file\n";
	my @lines  = <IN>;
	close IN;

	foreach my $line (@lines)
	{
		chomp($line);
		my @Data = split(/,/,$line);
		my $file = $Data[0];
		my $type = $Data[1];

		if ($file =~/files/) 
		{
			next;
		}
		
		if ($file =~ /filetype.csv/)
		{
			next;
		}	
		if ($type =~/PE/i)
		{
			next;
		}

		if ($type =~/DOS/i)
		{
			next;
		}

		else
		{
			unlink($file);
		}
	}
}

if ($ARGV[0] )
{
	check_type($ARGV[0]);
}

else 
{
	print "Usage: delNonPE.pl <SRC_DIR>";
}