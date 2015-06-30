package MyUtil;
require Exporter;
use Exporter;
use File::Path;
use MyError qw(debug warning critical);
@ISA = qw(Exporter);
@EXPORT_OK = qw(concat_path init_dir);

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
