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

our $YAML = YAML::LoadFile("$Bin/../settings.yaml");

#-----------#
# SUB ROUTN #
#-----------#
sub essential_dir($){
   my $dir = shift;
   unless(-d $dir){
      mkpath($dir) or die "Failed make $dir directory : $!\n";
   }
}

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
	# 作業上必要なディレクトリを作成する
	essential_dir($YAML->{WEBROOT});
	essential_dir($YAML->{TRACELOG_DIR});

	# Templateからphp実行前処理と実行後処理を作成
	generate_from_template("./template/prepend.php", {TRACELOG_DIR => "$YAML->{TRACELOG_DIR}"});
	generate_from_template("./template/append.php", {});
	# Templateからphp.iniを作成
	generate_from_template("./template/custom-php.ini", {CWD => getcwd()});
	# Templateからiptables.ruleを作成
	generate_from_template("./template/iptables.rule", { PLACK_SERVER_PORT  => "$YAML->{PLACK_SERVER_PORT}" });
	print "以下のコマンドでsshとPLACK SERVERT以外の通信を遮断します。\n";
	print "sudo iptables-restore ./iptables.rule\n";
    print "元に戻す時は以下の処理をコマンドを使用してください。\n";
    print "sudo /sbin/iptables -X\n";
    print "sudo /sbin/iptables -P INPUT ACCEPT\n";
    print "sudo /sbin/iptables -P OUTPUT ACCEPT\n";
    print "sudo /sbin/iptables -P FORWARD ACCEPT\n";
    print "sudo /sbin/iptables -F\n";

	if($YAML->{USING_HTTPS}){
	# HTTPS対応
	print "HTTPS対応のために秘密鍵、公開鍵、証明書を作成します。\n";
	system("openssl genrsa 2048 > server.key");
	system("openssl req -new -key server.key -out server.csr -subj '/C=JP/ST=Tokyo/L=Tokyo/O=Example Ltd./OU=Web/CN=example.com'");
	system("openssl x509 -in server.csr -days 365 -req -signkey server.key > server.crt");
	system("/usr/bin/plackup -s Starman -a observ.psgi --ssl-key-file server.key --ssl-cert-file server.crt --ssl 1 --host $YAML->{PLACK_SERVER_HOST} --port $YAML->{PLACK_SERVER_PORT} >> $YAML->{PLACK_SERVER_LOG} 2>&1 &");
	}else{
	system("/usr/bin/plackup -s Starman -a observ.psgi --host $YAML->{PLACK_SERVER_HOST} --port $YAML->{PLACK_SERVER_PORT} >> $YAML->{PLACK_SERVER_LOG} 2>&1 &");
	}

	# plackとphp builid in serverの起動
	system("/usr/bin/php -t $YAML->{WEBROOT} -S $YAML->{PHP_BUILD_SERVER_HOST}:$YAML->{PHP_BUILD_SERVER_PORT} -c ./custom-php.ini >> $YAML->{PHP_BUILD_SERVER_LOG} 2>&1 &");
}

main ();
