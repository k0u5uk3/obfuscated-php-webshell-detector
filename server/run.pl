#!/usr/bin/perl
use strict;
use warnings;
use Data::Dumper;
use YAML;
use Text::Template;
use File::Basename qw/basename/;
use File::Path 'mkpath';
use Cwd 'getcwd';
use FindBin qw($Bin);
use lib "$Bin/../lib";
use K0U5UK3::Error qw($DEBUG $WARNING debug warning critical);
use K0U5UK3::Util qw(init_dir);

our $YAML = YAML::LoadFile("$Bin/../settings.yaml");

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

sub msg($){
   my $msg = shift;
   print "[*] $msg\n";
}

#-------------#
# MAIN ROUTIN #
#-------------#
sub main(){
    # 解析対象PHPスクリプトを配置するディレクトリを作成する
	init_dir($YAML->{WEBROOT_DIR});
    # TRACELOG出力先ディレクトリを作成する
	init_dir($YAML->{TRACELOG_DIR});

	# Templateからphp実行前処理と実行後処理を作成
	generate_from_template("./template/prepend.php", {TRACELOG_DIR => "$YAML->{TRACELOG_DIR}"});
	generate_from_template("./template/append.php", {});

	# Templateからphp.iniを作成
	generate_from_template("./template/custom-php.ini", {CWD => getcwd()});

	# Templateからiptables.ruleを作成
	generate_from_template("./template/iptables.rule", { SANDBOX_HTTPD_PORT  => "$YAML->{SANDBOX_HTTPD_PORT}" });

    # iptables設定の指示
	msg("以下のコマンドでSANDBOX_HTTPDとSSH以外の通信を遮断します。");
	msg("sudo iptables-restore ./iptables.rule");
    msg("iptables設定をデフォルトに戻すには以下のコマンドを入力してください");
    msg("sudo /sbin/iptables -X");
    msg("sudo /sbin/iptables -P INPUT ACCEPT");
    msg("sudo /sbin/iptables -P OUTPUT ACCEPT");
    msg("sudo /sbin/iptables -P FORWARD ACCEPT");
    msg("sudo /sbin/iptables -F");

    if($YAML->{USE_SSL}){
      msg("HTTPSを使用するために秘密鍵、公開鍵、証明書を作成します。");
 	  system("openssl genrsa 2048 > server.key");
   	  system("openssl req -new -key server.key -out server.csr -subj '/C=JP/ST=Tokyo/L=Tokyo/O=Example Ltd./OU=Web/CN=example.com'");
   	  system("openssl x509 -in server.csr -days 365 -req -signkey server.key > server.crt");
    } 

    if($YAML->{SANDBOX_HTTPD_ENGINE} eq 'APACHE'){

    }elsif($YAML->{SANDBOX_HTTPD_ENGINE} eq 'PLACK'){
      # HTTPD_ENGINEにPLACKを使用する
      if($YAML->{USE_SSL}){
         # PLACKをHTTPSプロトコルで立ち上げる
         system("/usr/bin/plackup -s HTTP::Server::PSGI --ssl-key-file server.key " . 
                "--ssl-cert-file server.crt --ssl 1 observ.psgi " . 
                "--host $YAML->{SANDBOX_HTTPD_HOST} --port $YAML->{SANDBOX_HTTPD_PORT} >> $YAML->{SANDBOX_HTTPD_LOG} 2>&1 &"); 
      }else{
         # PLACKをHTTPプロトコルで立ち上げる
         system("/usr/bin/plackup observ.psgi --host $YAML->{SANDBOX_HTTPD_HOST} " . 
                "--port $YAML->{SANDBOX_HTTPD_PORT} >> $YAML->{SANDBOX_HTTPD_LOG} 2>&1 &");
      }
    }elsif($YAML->{SANDBOX_HTTPD_ENGINE} eq 'STARMAN'){
      # HTTPD_ENGINEにSTARMANを使用する
      if($YAML->{USE_SSL}){
   	     system("/usr/bin/plackup -s Starman -a observ.psgi --ssl-key-file server.key " . 
                "--ssl-cert-file server.crt --ssl 1 " . 
                "--host $YAML->{SANDBOX_HTTPD_HOST} --port $YAML->{SANDBOX_HTTPD_PORT} >> $YAML->{SANDBOX_HTTPD_LOG} 2>&1 &");
      }else{
	     system("/usr/bin/plackup -s Starman -a observ.psgi " . 
                "--host $YAML->{SANDBOX_HTTPD_HOST} --port $YAML->{SANDBOX_HTTPD_PORT} >> $YAML->{SANDBOX_HTTPD_LOG} 2>&1 &");
      }
    }

	# plackとphp builid in serverの起動
	system("/usr/bin/php -t $YAML->{WEBROOT} -S $YAML->{PHP_BUILTIN_SERVER_HOST}:$YAML->{PHP_BUILTIN_SERVER_PORT} " . 
           "-c ./custom-php.ini >> $YAML->{PHP_BUILTIN_SERVER_LOG} 2>&1 &");
}

main ();

