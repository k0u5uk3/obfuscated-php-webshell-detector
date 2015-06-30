#!/usr/bin/env perl
use strict;
use warnings;
use YAML;
use Digest::MD5;
use HTTP::Request::Common;
use LWP::UserAgent;
use Getopt::Long qw(:config posix_default no_ignore_case gnu_compat);
use File::Spec;
use JSON qw(encode_json decode_json);
use FindBin qw($Bin);
use Data::Dumper;

our $YAML = YAML::LoadFile("$Bin/../settings.yaml");

#------------#
# SUB ROUTIN #
#------------#
sub usage{
   printf("Usage : %s -f filename -m detect-obfuscate|detect-webshell|deobfuscate|tracelog|viewfunc\n", $0); 
   exit(0);
}

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

# オプション解析
my %opts;
GetOptions(\%opts, qw ( 
   filename|f=s
   mode|m=s
));

if(! exists $opts{filename}){
   #filenameオプションが渡っていないならusageを表示して終了
   usage();
}

if(! exists $opts{mode}){
   #modeオプションが渡っていないならdetectに設定する
   $opts{mode} = 'detect-webshell';
}

# オプションから必要な変数を作成する。
my $target_file = $opts{filename};
my $abs_filename = File::Spec->rel2abs("$opts{filename}");
my $target_md5  = get_md5($target_file);
my $sandbox_uri;

# ブラウザの作成
my $ua = LWP::UserAgent->new;
$ua->timeout(5);

# SSLを使用するか、しないかでURIを切り分ける。
if($YAML->{USE_SSL}){
   $sandbox_uri = "https://".$YAML->{SANDBOX_HOST}.":".$YAML->{SANDBOX_PORT};
   $ua->ssl_opts( verify_hostname => 0 );
}else{
   $sandbox_uri = "http://".$YAML->{SANDBOX_HOST}.":".$YAML->{SANDBOX_PORT};
}

# POSTリクエストを作成する
my $request = POST(
   $sandbox_uri,
   Content_Type => 'form-data',
   Content => {
      md5  => get_md5($target_file),
      mode => "$opts{mode}",
      data => [ $target_file ],
   },
);

# POSTリクエストを作成し、レスポンスを得る。
my $response = $ua->request( $request );

# ERROR処理
unless($response->is_success){
   my $code = $response->code;
   die "$abs_filename: [$code] ".$response->content."\n";
}

# 以降はSANDBOXから正常なレスポンスを受け取ったとみなす。
my $result = decode_json($response->content);
# debug mode output 
if($result->{mode} eq 'viewfunc'){
   print "TARGET FILE [ $abs_filename ]\n";
   foreach my $key (sort {$b cmp $a} keys %{$result->{body}}){
      print "$key".'['.$result->{body}->{$key}.']'."\n";
   }
}
# trace mode output
if($result->{mode} eq 'tracelog'){
   print "TARGET FILE [ $abs_filename ]\n";
   print $result->{body};
}
# detect mode output 
if($result->{mode} eq 'detect-obfuscate'){
   print "TARGET FILE [ $abs_filename ] : $result->{body}\n";
}

# malware-detect mode output 
if($result->{mode} eq 'detect-webshell'){
   print "TARGET FILE [ $abs_filename ] : $result->{body}\n";
}

# deobfusucate mode output
if($result->{mode} eq 'deobfuscate'){
   my @deobfusucate = @{$result->{body}};
   my $i=0;
   foreach my $deob (@deobfusucate){
      next unless defined $deob;
      print "/*** Obfusucated-PHP-Detector STEP $i ***/\n";
      print $deob . "\n";
      $i++;
   }
}
