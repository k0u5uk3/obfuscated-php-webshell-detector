#!/usr/bin/env perl
use strict;
use warnings;
use YAML;
use Digest::MD5;
use HTTP::Request::Common;
use LWP::UserAgent;
use Getopt::Long qw(:config posix_default no_ignore_case gnu_compat);
use File::Spec;
use Data::Dumper;
use JSON qw(encode_json decode_json);
use FindBin qw($Bin);

our $YAML = YAML::LoadFile("$Bin/../settings.yaml");
our $VERBOSE=0;

sub usage{
   printf("Usage : %s -f filename -m obfuscated-detect|webshell-detect|deobfuscated|tracelog|internal [-v]\n", $0); 
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
   $opts{mode} = 'webshell-detect';
}

if(exists $opts{verbose}){
   #verboseオプションが渡っているな$VERBOSEを真にする。
   $VERBOSE=1;
}

#------------#
# SUB ROUTIN #
#------------#
sub verbose($){
   my $msg = shift;
   printf("[*] $msg\n") if $VERBOSE;
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
my $target_file = $opts{filename};
my $sandbox_uri; 

if($YAML->{USE_SSL}){
   $sandbox_uri = "http://".$YAML->{SANDBOX_HOST}.":".$YAML->{SANDBOX_PORT},
}else{
   $sandbox_uri = "https://".$YAML->{SANDBOX_HOST}.":".$YAML->{SANDBOX_PORT},
}

# SANDBOX送信用のPOSTリクエストを生成する
my $req = POST(
   $sandbox_uri,
   Content_Type => 'form-data',
   Content => {
      md5  => get_md5($target_file),
      mode => "$opts{mode}",
      data => [ $target_file ],
   },
);

# 対象のファイルの絶対パスを取得する 
my $abs_filename = File::Spec->rel2abs("$target_file");

# LWPインスタンスの作成
my $ua = LWP::UserAgent->new;
# SSLを使用する場合は自己証明書を許可する
$ua->ssl_opts( verify_hostname => 0 ) if $YAML->{USE_SSL};
$ua->timeout($YAML->{TIMEOUT});

# リクエストをsandboxに発行して、レスポンスを取得する 
my $response = $ua->request( $req );

# ERRORハンドリング
unless($response->is_success){
   # レスポンスコードが200以外ならエラーの原因を通知し、適切な処理を行う。
   if($ersponse->code == 500){
      die "abs_filename: ".$response->content."\n";
   }else{
      die "unexpect error!!\n";
   }
}

# 移行は正常処理とみなす。正常なHTTP RESPONSEであればJSONが返ってくる。
my $json = decode_json($response->content);
# debug mode output 
if($json->{mode} eq 'internal'){
   print "TARGET FILE [ $abs_filename ]\n";
   foreach my $key (sort {$b cmp $a} keys %{$json->{body}}){
      print "$key".'['.$json->{body}->{$key}.']'."\n";
   }
}
# trace mode output
if($json->{mode} eq 'tracelog'){
   print "TARGET FILE [ $abs_filename ]\n";
   print $json->{body};
}
# detect mode output 
if($json->{mode} eq 'obfuscated-detect'){
   print "TARGET FILE [ $abs_filename ] : $json->{body}\n";
}

# malware-detect mode output 
if($json->{mode} eq 'webshell-detect'){
   print "TARGET FILE [ $abs_filename ] : $json->{body}\n";
}

# deobfusucate mode output
if($json->{mode} eq 'deobfuscate'){
   my @deobfusucate = @{$json->{body}};
   my $i=0;
   foreach my $deob (@deobfusucate){
      next unless defined $deob;
      print "/*** [Obfuscated-PHP-WebShell-Detector STEP $i ] ***/\n";
      print $deob . "\n";
      $i++;
   }
}


