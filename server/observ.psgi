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

   # ブラウザの作成
   my $ua = LWP::UserAgent->new;
   $ua->agent("Obfusucation Detection Browser $VERSION");
   # 解析PHPをApache経由で実行し、Xdebugにtracelogを吐かせる
   my $response = $ua->get("http://$YAML->{PHP_BUILD_SERVER_HOST}:$YAML->{PHP_BUILD_SERVER_PORT}/$file_name");
   die "Failed execute http://$YAML->{PHP_BUILD_SERVER_HOST}:$YAML->{PHP_BUILD_SERVER_PORT}/$file_name" unless $response->is_success;

   return "$YAML->{TRACELOG_DIR}".$file_name.".xt";
}

#---------------------------------------------------------------------
# parse_tracelogはハッシュリファレンスとリストリファレンスを返す。
# ハッシュリファレンスは関数名と呼び出し回数を保持しており
# リストリファレンスは関数を呼び出し順に関数名とパラメータを保持する
#---------------------------------------------------------------------
sub parse_tracelog($){
   my $tracelog = shift;
   my %func_count;
   my @stack_trace;
   my ($START_FLAG, $END_FLAG);

   open my $fh, '<', $tracelog or die "Failed open $tracelog : $!\n";
   while(<$fh>){
      if($_ =~ /^TRACE\sSTART/){ $START_FLAG=1};
      if($_ =~ /^TRACE\sEND/){   $END_FLAG=1  };
      if($START_FLAG && !$END_FLAG){
         my @col = split("\t", $_);
         if(defined $col[2] && $col[2] eq '0'){
            #関数呼び出しのみを解析対象とする。
            my $func_name = $col[5];
            # 関数呼び出し回数集計
            $func_count{$func_name}++;
            # stack_trace作成
            my @param;
            if($func_name eq 'eval'){
               #evalの場合は7番にパラメータが入る
               push(@param,$col[7]);               
            }else{
               @param = @col[11..$#col];
            }
            push(@stack_trace, [$func_name, @param]);
         }
      }
   }
   close($fh);

   return (\%func_count, \@stack_trace);
}

sub detect($){
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

sub read_file($){
   my $file = shift;
   my $text;
   open my $fh, '<', $file or die "Failed read $file : $!\n";
   local $/ = undef;
   $text = <$fh>;
   close($fh);
   return $text;
}

sub deobfusucate($){
   my $stack_trace = shift;

   # stack traceを逆順に見て行き、上記の関数で呼ばれるパラメータが
   # 難読化済みのコードだと仮定する

   my $ret;
   foreach my $tmp (reverse @$stack_trace){
      if($tmp->[0] eq 'eval'){
         return sprintf("%s", $tmp->[1]);        
      }
      if($tmp->[0] eq 'create_function'){
         return sprintf("%s", $tmp->[2]);        
      }
       if($tmp->[0] eq 'assert'){
         return sprintf("%s", $tmp->[1]);        
      }
   }
}

#-------------#
# MAIN ROUTIN #
#-------------#
sub main(){
   my $app = sub {
      # obscan.plからのパラメータ取得
      my $req = Plack::Request->new(shift);
      my $uploads = $req->uploads;
      my $file_name = $uploads->{data}->{filename};    # 対象ファイル名
      my $file_path = $uploads->{data}->{tempname};    # 対象ファイルの一時保存先
      my $client_md5 = $req->parameters->{md5};        # 対象ファイルのCLIENT側で取得したmd5
      my $mode = $req->parameters->{mode};

      # mode値のチェック
      my @allow_mode = qw(detect deobfusucate trace debug);

      unless(grep {$mode eq $_} @allow_mode){
         return [ 500, [ 'Content-Type' => 'text/plain' ], [ "unexcepted mode paramaeter" ], ];
      }

      my $ana_path;
      my $server_md5;
      my $tracelog;

      # eval内の関数はdieする可能性があるのでtrapする。
      eval{
         # 解析対象ファイルを解析場所に配置してファイルパスを取得
         $ana_path = decide_file_location($file_path, $file_name);
         # MD5を取得
         $server_md5 = get_md5($ana_path);
         # tracelogの取得
         $tracelog = get_tracelog($file_name);
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
      my ($func_info,$stack_trace) = parse_tracelog($tracelog);
      # tracelogの生テキスト
      my $trace_text = read_file($tracelog);

      # tracelogが必要な処理が終わったらtracelogを削除する
      unlink($tracelog) or die "Failed unlink $tracelog : $!\n" if -f $tracelog;
      # 解析対象ファイルも削除する
      unlink($ana_path) or die "Failed unlink $ana_path : $!\n" if -f $ana_path;

      if($mode eq 'debug'){
         return [ 200, [ 'Content-Type' => 'text/plain' ], [ sprintf Dumper ($func_info) ], ];
      }
   
      if($mode eq 'trace'){
         return [ 200, [ 'Content-Type' => 'text/plain' ], [ $trace_text ], ];
      }     

      if($mode eq 'detect'){
         # detectは関数内でHTTPヘッダを考慮した返り値を返す
         return detect($func_info); 
      }

      if($mode eq 'deobfusucate'){
         my $deobfusucate = deobfusucate($stack_trace);
         # 先頭と行末のシングルクォーテションを削除
         $deobfusucate =~ s/^\'//;
         $deobfusucate =~ s/\'$//;
         return [ 200, [ 'Content-Type' => 'text/plain' ], [ $deobfusucate ], ];
      }
   };

   return $app;
}

main();

