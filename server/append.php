<?php
xdebug_stop_trace();

//tracelogが存在することを確認して削除する。
if(file_exists($POD_TRACELOG_FILENAME)){
        // tracelog格納ディレクトリが存在しないなら作成する
	// unlink($POD_TRACELOG_FILENAME);
}
?>

