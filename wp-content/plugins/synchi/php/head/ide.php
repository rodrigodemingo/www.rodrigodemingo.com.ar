<?php 
    
// =============================================================================
// File: ide.php
// Version: 2.6
// 
// Indcludes head files for synchi IDE
// =============================================================================

// check access
if(!defined('SYNCHI')) exit('Direct access is not allowed...'); 

$css_includes = array(
    // CodeMirror core
    'lib/codemirror/codemirror',
    // CodeMirror util
    'lib/codemirror/util/dialog',
    'lib/codemirror/util/simple-hint',
    // FileTree
    'lib/jqueryFileTree/jqueryFileTree',
    // Tooltip
    'lib/jquery-tooltip/jquery.tooltip',
    // Synchi
    'css/synchi',
    'css/synchi_ide',
);

$js_includes = array(
    // JQuery UI
    'lib/jquery/jquery-ui-1.8.21.custom.min',
    // CodeMirror core
    'lib/codemirror/codemirror',
    // CodeMirror modess
    'lib/codemirror/mode/clike',
    'lib/codemirror/mode/css',
    'lib/codemirror/mode/htmlmixed',
    'lib/codemirror/mode/javascript',
    'lib/codemirror/mode/mysql',
    'lib/codemirror/mode/php',
    'lib/codemirror/mode/xml',
    // CodeMirror utils
    'lib/codemirror/util/dialog',
    'lib/codemirror/util/formatting',
    'lib/codemirror/util/searchcursor',
        'lib/codemirror/util/search',
        'lib/codemirror/util/match-highlighter',
    'lib/codemirror/util/simple-hint',
    'lib/codemirror/util/javascript-hint',
    'lib/codemirror/util/php-hint',
    // FileTree
    'lib/jqueryFileTree/jqueryFileTree',
    // Keyboard Shortcuts
    'lib/shortcut/shortcut',
    // Context Menu
    'lib/contextmenu/jquery.contextmenu.r2.packed',
    // Tooltip
    'lib/jquery-tooltip/jquery.tooltip',
    // Synchi
    'js/jquery.synchi',
    'js/synchi_ide',
);

?>

<script type="text/javascript">
    $ = jQuery;
    var synchi_settings = <?php echo json_encode($synchi_settings); ?>;
    var synchi_editor_root = '<?php echo $editor_root; ?>/';
    var synchi_editor_mode = '<?php echo $editor_mode; ?>/';
    var synchi_path = '<?php echo WP_PLUGIN_URL; ?>/synchi/';
    var synchi_serialized_tabs = <?php echo json_encode($serialized_tabs) ?>;
    var synchi_labels = [];
    <?php  // echo labels
        echo "synchi_labels['Directory copied'] = '".__('Directory copied','synchi')."';"; 
        echo "synchi_labels['File copied'] = '".__('File copied','synchi')."';"; 
        echo "synchi_labels['Directory cut'] = '".__('Directory cut','synchi')."';"; 
        echo "synchi_labels['File cut'] = '".__('File cut','synchi')."';"; 
        echo "synchi_labels['Copying'] = '".__('Copying','synchi')."';"; 
        echo "synchi_labels['Done'] = '".__('Done','synchi')."';"; 
        echo "synchi_labels['Deleting'] = '".__('Deleting','synchi')."';"; 
        echo "synchi_labels['Delete folder'] = '".__('Delete folder','synchi')."';"; 
        echo "synchi_labels['Delete file'] = '".__('Delete file','synchi')."';"; 
        echo "synchi_labels['File deleted'] = '".__('File deleted','synchi')."';"; 
        echo "synchi_labels['Folder deleted'] = '".__('Folder deleted','synchi')."';"; 
        echo "synchi_labels['Select a file/dir to cut'] = '".__('Select a file/dir to cut','synchi')."';"; 
        echo "synchi_labels['Select a file/dir to copy'] = '".__('Select a file/dir to copy','synchi')."';"; 
        echo "synchi_labels['You must select where to paste'] = '".__('You must select where to paste','synchi')."';"; 
        echo "synchi_labels['You must select where to upload'] = '".__('You must select where to upload','synchi')."';"; 
        echo "synchi_labels['Select a file/dir to download'] = '".__('Select a file/dir to download','synchi')."';"; 
        echo "synchi_labels['Unknown control'] = '".__('Unknown control','synchi')."';"; 
        echo "synchi_labels['Not yet implemented'] = '".__('Not yet implemented','synchi')."';"; 
        echo "synchi_labels['Exit without saving'] = '".__('Exit without saving','synchi')."';"; 
        echo "synchi_labels['Initializing Synchi IDE'] = '".__('Initializing Synchi IDE','synchi')."';"; 
        echo "synchi_labels['Unable to load Synchi IDE'] = '".__('Unable to load Synchi IDE','synchi')."';"; 
        echo "synchi_labels['folder with all files and subfolders'] = '".__('folder with all files and subfolders','synchi')."';"; 
        echo "synchi_labels['Select a file/dir to delete'] = '".__('Select a file/dir to delete','synchi')."';"; 
        echo "synchi_labels['Creating folder'] = '".__('Creating folder','synchi')."';"; 
        echo "synchi_labels['Enter folder name'] = '".__('Enter folder name','synchi')."';"; 
        echo "synchi_labels['You must select a directory'] = '".__('You must select a directory','synchi')."';"; 
        echo "synchi_labels['File created'] = '".__('File created','synchi')."';"; 
        echo "synchi_labels['Creating file'] = '".__('Creating file','synchi')."';"; 
        echo "synchi_labels['Enter filename'] = '".__('Enter filename','synchi')."';"; 
        echo "synchi_labels['You must select a directory'] = '".__('You must select a directory','synchi')."';"; 
        echo "synchi_labels['Error: file not saved'] = '".__('Error: file not saved','synchi')."';"; 
        echo "synchi_labels['File saved'] = '".__('File saved','synchi')."';"; 
        echo "synchi_labels['Saving'] = '".__('Saving','synchi')."';"; 
        echo "synchi_labels['Saved in total'] = '".__('Saved in total','synchi')."';"; 
        echo "synchi_labels['Saving all files'] = '".__('Saving all files','synchi')."';"; 
        echo "synchi_labels['Error: file not saved'] = '".__('Error: file not saved','synchi')."';"; 
        echo "synchi_labels['File saved'] = '".__('File saved','synchi')."';"; 
        echo "synchi_labels['Saving'] = '".__('Saving','synchi')."';"; 
        echo "synchi_labels['Save changes to'] = '".__('Save changes to','synchi')."';"; 
        echo "synchi_labels['File size'] = '".__('File size','synchi')."';"; 
    ?>  
</script>

<style type="text/css">
    .CodeMirror-scroll {
        font-size : <?php echo $synchi_settings['fontSize']; ?>px;
        <?php if($theme == 'default') { ?>background-color: #FAFAFA;<?php } ?>
    }
</style>

<?php

foreach($css_includes as $css) synchi_echoCSSinclude($css);
foreach($js_includes as $js) synchi_echoJSinclude($js);
if($synchi_settings['theme'] != 'default') synchi_echoCSSinclude("lib/codemirror/theme/{$synchi_settings['theme']}");

?>