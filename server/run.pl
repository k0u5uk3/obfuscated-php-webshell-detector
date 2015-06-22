#!/usr/bin/perl
use strict;
use warnings;
use Data::Dumper;
use YAML;
use Text::Template;
use File::Basename qw/basename/;

our $YAML = YAML::LoadFile("./observ.yaml");

#-----------#
# SUB ROUTN #
#-----------#
sub generate_from_template($$){
	my $tmpl_file = shift;
	my $data = shift;

	my $template = Text::Template->new(SOURCE => "$tmpl_file");
	my $text = $template->fill_in(HASH => $data) or die "Faild fill in $tmpl_file\n";
	my $gen_file = basename $tmpl_file;

	open my $fh, '>', $gen_file or die "Faild write $gen_file : $!\n";
	print $fh $text;
	close($fh);
}

#-------------#
# MAIN ROUTIN #
#-------------#
sub main(){
	generate_from_template("./template/prepend.php", {TRACELOG_DIR => "$YAML->{TRACELOG_DIR}"});
	generate_from_template("./template/append.php", {});
}

main ();

