package K0U5UK3::Util;
require Exporter;
use Exporter;
use File::Path;
use Digest::MD5;
use K0U5UK3::Error qw(debug warning critical);

@ISA = qw(Exporter);
@EXPORT_OK = qw(get_md5 concat_path init_dir);

sub get_md5($){
   my $filename = shift;
   open my $fh, '<', $filename or critical "Failed open $filename : $!\n";
   my $md5 = Digest::MD5->new->addfile($fh)->hexdigest;
   close($fh);
   return $md5;
}

sub concat_path{
   my $concat;
   my @paths = @_;

   foreach my $path (@paths){
      if($path !~ /^\//){
         $path = '/' . $path;
      }
      $concat .= $path;
   }

   return $concat;
}

#ディレクトリがなければ作成する
#再起的に作成することもできる
sub init_dir($){
   my $dir = shift;

   if (!-d $dir){
      mkpath $dir or critical "Failed make $dir : $!";
   }
}

1;
