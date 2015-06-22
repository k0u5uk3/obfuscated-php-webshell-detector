#!/usr/bin/env perl
use strict;
use warnings;
use Digest::MD5;
use HTTP::Request::Common;
use LWP::UserAgent;
use Getopt::Long qw(:config posix_default no_ignore_case gnu_compat);
use File::Spec;
use Data::Dumper;

our $DEBUG=0;

sub usage{
   printf("Usage : %s -f [filename] [-m detect|deobfusucate|trace]\n", $0); 
   exit(0);
}

my %opts;
GetOptions(\%opts, qw ( 
   filename|f=s
   mode|m=s
   vervbose|v
));

if(! exists $opts{filename}){
   #filenameオプションが渡っていないならusageを表示して終了
   usage();
}

if(! exists $opts{mode}){
   #modeオプションが渡っていないならdetectに設定する
   $opts{mode} = 'detect';
}

if(exists $opts{verbose}){
   #verboseオプションが渡っているな$DEBUGを真にする。
   $DEBUG=1;
}

sub debug($){
   my $msg = shift;
   printf("[*] $msg\n") if $DEBUG;
}

#------------#
# SUB ROUTIN #
#------------#

sub get_md5($){
   my $filename = shift;
   open my $fh, '<', $filename or die "Failed open $filename : $!\n";
   my $md5 = Digest::MD5->new->addfile($fh)->hexdigest;
   close($fh);
   return $md5;
}

#-------------#
# MAIN ROUTIN #
#-------------#

my $target_file = $opts{filename};
my $target_md5  = get_md5($target_file);
my $analyze_url = "http://192.168.74.57:5000";

my $req = POST(
   $analyze_url,
   Content_Type => 'form-data',
   Content => {
      md5  => "$target_md5",
      mode => "$opts{mode}",
      data => [ $target_file ],
   },
);

my $abs_filename = File::Spec->rel2abs("$opts{filename}");

my $ua = LWP::UserAgent->new;
my $res = $ua->request( $req );
if($res->is_success){
   print "$abs_filename:";
   print $res->content;
   print "\n";
}else{
   print "$abs_filename:";
   print $res->content;
   print "\n";
}


