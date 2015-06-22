#!/usr/bin/env perl
use strict;
use warnings;
use YAML;
use Plack::Request;
use File::Copy;
use Digest::MD5;
use HTTP::Request::Common;
use LWP::UserAgent;
use File::Path 'mkpath';
use Data::Dumper;

our $VERSION = "0.0.2";
our $YAML = YAML::LoadFile("./observ.yaml");

#------------#
# SUB ROUTIN # 
#------------#
sub essential_dir($){
   my $dir = shift;
   unless(-d $dir){
      mkpath($dir) or die "Failed make $dir directory : $!\n";
   }
}

sub decide_file_location($$){
   my $file_path = shift;
   my $file_name = shift;
   my $ana_path = $YAML->{WEBROOT} . $file_name;

   # $file_pathが存在することを確認
   if(! -f $file_path){
      die "Not exists $file_path";
   }

   # 対象ファイルの解析場所に移す
   move $file_path, $ana_path or die "Faild move $file_path to $ana_path : $!\n";

   # 解析場所に移したphpファイルを実行可能にする
   chmod 0444, $ana_path or die "Failed change permission $ana_path\n";

   return $ana_path;
}

sub get_md5($){
   my $filename = shift;
   open my $fh, '<', $filename or die "Failed open $filename : $!\n";
   my $md5 = Digest::MD5->new->addfile($fh)->hexdigest;
   close($fh);
   return $md5;
}

sub get_rand_string($){
   my $length = shift;
   my @char_tmp=();
   push @char_tmp, ('a'..'z');
   push @char_tmp, ('A'..'Z');
   push @char_tmp, (0..9);

   my $str;
   for(my $i=1; $i<=$length; $i++){
      $str .= $char_tmp[int(rand($#char_tmp+1))];
   }
   return $str;
}

sub get_tracelog($){
   my $file_name = shift;

   # TRACELOGディレクトリのすべてのファイルを削除する。
   my @tracelogs;
   {
      opendir my $dh, $YAML->{TRACELOG_DIR} or die "Failed open $YAML->{TRACELOG_DIR} : $!\n"; 
      @tracelogs = grep { m/trace\..+?\.xt/} readdir $dh;
      close($dh);

      map{ unlink "$YAML->{TRACELOG_DIR}/$_" or die "Failed unlink $_ : $!\n" } @tracelogs;
      @tracelogs = ();
   }

   # ブラウザの作成
   my $ua = LWP::UserAgent->new;
   $ua->agent("Obfusucation Detection Browser $VERSION");
   # 解析PHPをApache経由で実行し、Xdebugにtracelogを吐かせる
   my $response = $ua->get("127.0.0.1/$file_name");
   die "Failed execute 127.0.0.1/$file_name" unless $response->is_success;

   # 現在残っているTRACELOGのみを取得する 
   {
      opendir my $dh, $YAML->{TRACELOG_DIR} or die "Failed open $YAML->{TRACELOG_DIR} : $!\n"; 
      @tracelogs = grep { m/trace\..+?\.xt/} readdir $dh;
      close($dh);
   }
   
   return [map{ "$YAML->{TRACELOG_DIR}".$_ } @tracelogs];
}

sub parse_tracelog($){
   my $tracelogs = shift;
   my %hash;

   foreach my $tracelog (@$tracelogs){
      my ($START_FLAG, $END_FLAG);
      open my $fh, '<', $tracelog or die "Failed open $tracelog : $!\n";
      while(<$fh>){
         if($_ =~ /^TRACE\sSTART/){ $START_FLAG=1};
         if($_ =~ /^TRACE\sEND/){   $END_FLAG=1  };

         if($START_FLAG && !$END_FLAG){
            # 解析対象
            my @col = split(/\s+/,$_);
            # 関数名を保存
            if($col[3] eq '->' && defined $col[4]){
               # 関数名だけを切り出し
               $col[4] =~ s/(.+?)\(.*/$1/;
               # 関数名を出現回数を保存
               $hash{$col[4]}++;
            }
         }
      }
      close($fh);
   }

   return \%hash;
}

sub analyze($){
   my $info = shift;
   my $score = 0;
   my $threshold = 50;
   my @msg;
   
   # コード再評価のための関数
   # この関数を使用する毎に+50p
   my @eval_func = qw(
      eval
      assert
      preg_replace
      create_function
   );

   # コード難読化のための関数
   # この関数を使用する毎に+10p
   my @obfuscate_func = qw(
      base64_encode
      gzdeflate
      str_rot13
      gzcompress
      strrev
      rawurlencode
   );

   # コード再評価関数の使用に基づきスコアリング
   map{ 
      my $key = $_;
      if(grep { $key eq $_ } @eval_func){
         my $point = 50 * $info->{$key};
         push(@msg, "$key($point)");
         $score += $point;
      }
   } keys %$info;

   # コード再評価関数の使用に基づきスコアリング
   map{ 
      my $key = $_;
      if(grep { $key eq $_ } @obfuscate_func){
         my $point = 10 * $info->{$key};
         push(@msg, "$key($point)");
         $score += $point;
      }
   } keys %$info;

   if($score >= $threshold){
      # malware判定
      return [
         200,
         [ 'Content-Type' => 'text/plain' ],
         [ "Detect($score):" . join(",", @msg) ],
      ];
   }else{
      # malwareではない 
      return [
         200,
         [ 'Content-Type' => 'text/plain' ],
         [ "None($score):" . join(",", @msg) ],
      ];
   }
}

#-------------#
# MAIN ROUTIN #
#-------------#
sub main(){

   # 作業上必要なディレクトリを作成する
   essential_dir($YAML->{WEBROOT});
   essential_dir($YAML->{TRACELOG_DIR});

   my $app = sub {
      # obscan.plからのパラメータ取得
      my $req = Plack::Request->new(shift);
      my $uploads = $req->uploads;
      my $file_name = $uploads->{data}->{filename};    # 対象ファイル名
      my $file_path = $uploads->{data}->{tempname};    # 対象ファイルの一時保存先
      my $client_md5 = $req->parameters->{md5};        # 対象ファイルのCLIENT側で取得したmd5
      my $mode = $req->parameters->{mode};

      my $ana_path;
      my $server_md5;
      my $tracelogs;

      # eval内の関数はdieする可能性があるのでtrapする。
      eval{
         # 解析対象ファイルを解析場所に配置してファイルパスを取得
         $ana_path = decide_file_location($file_path, $file_name);
         # MD5を取得
         $server_md5 = get_md5($ana_path);
         # tracelogの取得
         $tracelogs = get_tracelog($file_name);
      };

      # MD5エラー 
      if($client_md5 ne $server_md5){
         return [ 500, [ 'Content-Type' => 'text/plain' ], [ "upload file is corrupted." ], ];
      }

      # 例外のハンドリング 
      if($@){
         return [ 500, [ 'Content-Type' => 'text/plain' ], [ $@ ], ];
      }

      # tracelogの解析 
      # $func_infoは関数名と出現回数を記録したハッシュリファレンス
      my $func_info = parse_tracelog($tracelogs);

      if($mode eq 'dump'){
         return [ 200, [ 'Content-Type' => 'text/plain' ], [ sprintf Dumper ($func_info) ], ];
      }

      return analyze($func_info); 
   };

   return $app;
}

main();

