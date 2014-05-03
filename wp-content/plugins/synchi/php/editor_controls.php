<?php 
    
// =============================================================================
// File: editor_controls.php
// Version: 1.0
// 
// Renders controls for article editor
// =============================================================================

// check access
if(!defined('SYNCHI')) exit('Direct access is not allowed...'); 

// define editor controls
$editor_controls = array(
    'find_prev','search','find_next','search_replace','spacer',
    'indent_left','format','indent_right','spacer',
    'undo','redo','spacer',
    'goto','fullscreen'
);

?>

<div id="ed_toolbar" class="synchi_editor_controls">
    <?php
    foreach ($editor_controls as $control) {
        $src = WP_PLUGIN_URL . "/synchi/img/ide/$control.png";
        switch($control) {
            case 'search' :$title = __('Search','synchi').' (Ctrl-F)';break;
            case 'find_prev' :$title = __('Find Previous','synchi').' (Ctrl-left)';break;
            case 'find_next' :$title = __('Find Next','synchi').' (Ctrl-Right)';break;
            case 'search_replace' :$title = __('Replace','synchi').' (Ctrl-R)';break;
            case 'format' :$title = __('Format','synchi').' (Alt-Shift-F)';break;
            case 'indent_left' :$title = __('Indent left','synchi').' (Alt-Shift-Left)';break;
            case 'indent_right' :$title = __('Indent right','synchi').' (Alt-Shift-Right)';break;
            case 'goto' :$title = __('Go to line','synchi').' (Ctrl-G)';break;
            case 'fullscreen' :$title = __('Toggle Fullscreen','synchi').' (Alt-Enter)';break;
            default :$title = 'action';
        }
        ?>
    <?php if ($control == "spacer") { ?>
            <a href="#" onclick="return false;" class="synchi_spacer"><img src="<?php echo $src; ?>" border="0" /></a>
    <?php } else { ?>
            <a href="#" onclick="synchi_Control('<?php echo $control; ?>'); return false;" title="<?php echo $title; ?>"><img src="<?php echo $src; ?>" border="0" /></a>
    <?php }
} ?>
</div>