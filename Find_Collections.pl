use strict;
use warnings;

sub find($)
{

	my $base_folder = shift;
	my $A = "\\shift_A";
	my $B = "\\shift_B";
	my $C = "\\shift_C";

	my $shift_A_folder="$base_folder$A";
	my $shift_B_folder="$base_folder$B";
	my $shift_C_folder="$base_folder$C";

	if (-d $shift_A_folder)
	{
		opendir( SRCDIR, $shift_A_folder );
		my( @files ) = grep( !/^\./, readdir( SRCDIR ));
		closedir( SRCDIR );
		foreach my $filename (@files) 
		{
			print "$shift_A_folder\\$filename\n";
		}
	}


	if (-d $shift_B_folder)
	{
		opendir( SRCDIR, $shift_B_folder );
		my( @files ) = grep( !/^\./, readdir( SRCDIR ));
		closedir( SRCDIR );
		foreach my $filename (@files) 
		{
			print "$shift_B_folder\\$filename\n";
		}
	}


	if (-d $shift_C_folder)
	{
		opendir( SRCDIR, $shift_C_folder );
		my( @files ) = grep( !/^\./, readdir( SRCDIR ));
		closedir( SRCDIR );
		foreach my $filename (@files) 
		{
			print "$shift_C_folder\\$filename\n";
		}
	}
}

sub month($)
{
	my $base_folder = shift;
	opendir( SRCDIR, $base_folder );
	my( @files ) = grep( !/^\./, readdir( SRCDIR ));
	closedir( SRCDIR );

	foreach my $filename (@files) 
	{
		my $src_folder = "$base_folder\\$filename";
		if (-d $src_folder)
		{
			print "\n\n$src_folder\n";
			find($src_folder);
		}
	}
}


if ($ARGV[0])
{
	month($ARGV[0]);
	

}

else
{
	print "Usage: Find_Collections <\\\\192.168.30.8\\August-2013>\n";
}