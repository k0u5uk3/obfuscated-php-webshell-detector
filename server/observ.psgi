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
use JSON qw(encode_json decode_json);
use File::Temp qw/ tempfile tempdir /; 

our $VERSION = "0.0.2";
our $YAML = YAML::LoadFile("./observ.yaml");
our $THRESHOLD = 50;

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
   my @msg;
   
   # コード再評価のための関数
   # この関数を使用する毎に+50p
   my @eval_func = qw(
      eval
      assert
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

   return ($score, \@msg);

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

sub escape2control($){
   my $string = shift;
   # 先頭と行末のシングルクォーテションを削除
   $string =~ s/^\'//;
   $string =~ s/\'$//;

   # エスケープシーケンスを制御文字に変換
   $string =~ s/\\r\\n/\x{0a}/g;
   $string =~ s/\\n/\x{0a}/g;
   $string =~ s/\\t/\x{09}/g; 

   $string =~ s/\\//g;
   return $string;
}

sub deobfusucate($){
   my $stack_trace = shift;
   my @ret;

   foreach my $tmp (@$stack_trace){
      my $deobfusucate;
      if($tmp->[0] eq 'eval'){
         $deobfusucate = escape2control($tmp->[1]);
      }
      if($tmp->[0] eq 'create_function'){
         $deobfusucate = escape2control($tmp->[2]);
      }
      if($tmp->[0] eq 'assert'){
         $deobfusucate = escape2control($tmp->[1]);
      }
      push(@ret, $deobfusucate);
   }
   return \@ret;
}

sub cleanup($){
   my $file = shift;
   unlink($file) or die "Failed unlink $file : $!\n" if -f $file;
}

sub strip_php_code($){
   my $code = shift;
   my $fh = new File::Temp();
   my $file = $fh->filename;
   print $fh $code;
   my $strip = qx{ /usr/bin/php -w $file } ;
   return $strip;
}

sub malware_detect($){
   my $codes = shift;
   my $score=0;
   my @mal_codes = qw(
      system exec passthru shell_exec popen proc_open pcntl_exec eval assert create_function
   );

   my %ret;

   foreach my $code (@$codes){
      next unless defined $code;
      my $strip = strip_php_code($code);            
      foreach my $mal_code (@mal_codes){
         $ret{$mal_code} = scalar( () = $strip =~ /$mal_code\(.+\)/g);
         $score += $ret{$mal_code};
      }      
   }

   return ($score,\%ret);
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
      my @allow_mode = qw(detect malware-detect deobfusucate trace debug);

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
         cleanup($ana_path);
         cleanup($tracelog);
         return [ 500, [ 'Content-Type' => 'text/plain' ], [ "upload file is corrupted." ], ];
      }

      # 例外のハンドリング 
      if($@){
         cleanup($ana_path);
         cleanup($tracelog);
         return [ 500, [ 'Content-Type' => 'text/plain' ], [ $@ ], ];
      }

      # tracelogの解析 
      # $func_infoは関数名と出現回数を記録したハッシュリファレンス
      my ($func_info,$stack_trace) = parse_tracelog($tracelog);
      # tracelogの生テキスト
      my $trace_text = read_file($tracelog);

      cleanup($ana_path);
      cleanup($tracelog);

      my %ret;
      if($mode eq 'debug'){
         %ret = (
               'mode' => 'debug',
               'body' => $func_info,
               ); 
         return [ 200, [ 'Content-Type' => 'text/plain' ], [ encode_json( \%ret ) ], ];
      }

      if($mode eq 'trace'){
         %ret = (
               'mode' => 'trace',
               'body' => $trace_text,
               );
         return [ 200, [ 'Content-Type' => 'text/plain' ], [ encode_json( \%ret ) ], ];
      }     

      if($mode eq 'detect'){
         my ($score, $msg) =  detect($func_info); 
         if($score >= $THRESHOLD){
            # 難読化判定
            %ret = (
                  'mode' => 'detect',
                  'body' => "Detect!!($score) : " . join(", ", @$msg),
                  );
         }else{
            # 難読化されていない
            %ret = (
                  'mode' => 'detect',
                  'body' => "None($score) : " . join(", ", @$msg),
                  );
         }
         return [ 200, [ 'Content-Type' => 'text/plain' ], [ encode_json( \%ret ) ], ];
      }

      if($mode eq 'malware-detect'){
         my ($score, $obmsg) =  detect($func_info); 
         if($score >= $THRESHOLD){
            # 難読化判定
            # 難読化を解読して危険なコードが含まれているかを確認
            my ($mal_score, $mal_code) = malware_detect(deobfusucate($stack_trace)); 
            if($mal_score){
               my @malmsg;
               while(my ($key, $value) = each %{$mal_code}){
                  push(@malmsg, "$key".'['."$value".']');
               }
                %ret = (
                     'mode' => 'malware-detect',
                     'body' => "Malware Detect!! : " . join(", ", (@$obmsg, @malmsg)),
                     );
            }else{
               %ret = (
                     'mode' => 'malware-detect',
                     'body' => "Not Malware($score) : " . join(", ", @$obmsg),
                     );
            }
            return [ 200, [ 'Content-Type' => 'text/plain' ], [ encode_json( \%ret ) ], ];
      }else{
            # 難読化されていない
            %ret = (
                  'mode' => 'malware-detect',
                  'body' => "None($score) : " . join(", ", @$obmsg),
                  );
         }
         return [ 200, [ 'Content-Type' => 'text/plain' ], [ encode_json( \%ret ) ], ];
      }

      if($mode eq 'deobfusucate'){
         %ret = (
               'mode' => 'deobfusucate',
               'body' => deobfusucate($stack_trace),
               );
         return [ 200, [ 'Content-Type' => 'text/plain' ], [ encode_json( \%ret ) ], ];
      }
   };

   return $app;
}

main();

