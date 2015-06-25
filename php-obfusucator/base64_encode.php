<?php
$a = 'eval("echo \'Hello, World!\';");';
echo base64_encode($a);
echo "\n";
?>
