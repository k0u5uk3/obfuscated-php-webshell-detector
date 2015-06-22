<?php
$POD_TRACELOG_DIR = "/tmp/tracelog/";

if(!file_exists($POD_TRACELOG_DIR)){
	// tracelog格納ディレクトリが存在しないなら作成する
	mkdir($POD_TRACELOGDIR, 0700);
}

$POD_EXEC_FILENAME = basename($_SERVER['PHP_SELF']);
$POD_EXEC_FILENAME .= "_" . time();
xdebug_start_trace( "$POD_TRACELOG_DIR/$POD_EXEC_FILENAME" );
$POD_TRACELOG_FILENAME = "$POD_TRACELOG_DIR/$POD_EXEC_FILENAME".".xt";
?>
