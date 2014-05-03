<?php 
    
// =============================================================================
// File: ide.php
// Version: 1.0
// 
// Renders editor HTML.
// =============================================================================

// check access
if(!defined('SYNCHI')) exit('Direct access is not allowed...'); 

// define editor controls
$editor_controls = array(
    'save','save_all','spacer',
    'comment','uncomment','spacer',
    'find_prev','search','find_next','search_replace','spacer',
    'indent_left','format','indent_right','spacer',
    'undo','redo','spacer',
    'goto','fullscreen'
);

// define sidebar controls
$sidebar_controls = array(
    'new_file' => __('New File','synchi'),
    'new_folder' => __('New Folder','synchi'),
    'delete' => __('Delete','synchi'),
    'cut' => __('Cut','synchi'),
    'copy' => __('Copy','synchi'),
    'paste' => __('Paste','synchi'),
    //'upload' => __('Upload','synchi'),
    //'download' => __('Download','synchi'),
);

// define tab controls
$tab_controls = array(
    'save' => __('Save','synchi'),
    'close' => __('Close','synchi'),
    'close_other' => __('Close Other','synchi'),
    'close_all' => __('Close All','synchi'),
);

// determine sidebar label
switch($editor_mode) {
    case 'themes': $translated_editor_mode = __('themes','synchi'); break;
    case 'plugins': $translated_editor_mode = __('plugins','synchi'); break;
    default: $translated_editor_mode = __('files','synchi');
}

?>

<div id="synchi_ide">
    <table width="100%" height="500" cellpadding="0" cellspacing="0">
        <tr style="height: 30px; vertical-align: bottom">
            <td style="width: 5px;"></td>
            <td style="border-bottom: 1px solid #DFDFDF;">
                <table width="100%" height="100%" cellpadding="0" cellspacing="0">
                    <tr style="vertical-align: bottom">
                        <td width="5"></td>
                        <td><div id="synchi_ide_tabs"></div></td>
                        <td width="5"></td>
                    </tr>
                </table>
            </td>
            <td style="width: 10px;"></td>
            <td style="width: 300px; border-bottom: 1px solid #DFDFDF; text-align: center; font-size: 10px; font-weight: bold">
                - <?php echo $translated_editor_mode; ?> -
            </td>
            <td style="width: 5px;"></td>
        </tr>
        <tr style="vertical-align: top">
            <td style="width: 5px;"></td>
            <td style="border-left: 1px solid #DFDFDF; ">
                <div style="margin-right: 6px;">
                    <div id="synchi_ide_editor"></div>
                </div>
            </td>
            <td style="width: 10px; border-left: 1px solid #DFDFDF;"></td>
            <td style="width: 300px; border-left: 1px solid #DFDFDF; border-right: 1px solid #DFDFDF;">
                <div id="synchi_ide_sidebar" tabindex="0"></div>
            </td>
            <td style="width: 5px;"></td>
        </tr>
        <tr style="height: 30px">
            <td style="width: 5px;"></td>
            <td style="border-top: 1px solid #DFDFDF; text-align: right">
                <div id="synchi_ide_editor_controls">
                    <?php
                    foreach($editor_controls as $control) {
                        $src = WP_PLUGIN_URL . "/synchi/img/ide/$control.png";
                        switch($control) {
                            case 'save' :$title = __('Save','synchi').' (Ctrl-S)';break;
                            case 'save_all' :$title = __('Save All','synchi').' (Ctrl-Shift-S)'; break;
                            case 'comment' :$title = __('Comment','synchi').' (Ctrl-Q)';break;
                            case 'uncomment' :$title = __('Uncomment','synchi').' (Ctrl-Shift-Q)';break;
                            case 'search' :$title = __('Search','synchi').' (Ctrl-F)';break;
                            case 'find_prev' :$title = __('Find Previous','synchi').' (Ctrl-left)';break;
                            case 'find_next' :$title = __('Find Next','synchi').' (Ctrl-Right)';break;
                            case 'search_replace' :$title = __('Replace','synchi').' (Ctrl-R)';break;
                            case 'format' :$title = __('Format','synchi').' (Alt-Shift-F)';break;
                            case 'indent_left' :$title = __('Indent left','synchi').' (Alt-Shift-Left)';break;
                            case 'indent_right' :$title = __('Indent right','synchi').' (Alt-Shift-Right)';break;
                            case 'undo' :$title = __('Undo','synchi').' (Ctrl-Z)';break;
                            case 'redo' :$title = __('Redo','synchi').' (Ctrl-Y)';break;
                            case 'goto' :$title = __('Go to line','synchi').' (Ctrl-G)';break;
                            case 'fullscreen' :$title = __('Toggle Fullscreen','synchi').' (Alt-Enter)';break;
                            //case 'comment' :$title = __('Comment Selection','synchi').' (Alt+Shift+/)';break;
                            default :$title = 'action';
                        }
                    ?>
                    <?php if($control == "spacer") { ?>
                    <a href="#" onclick="return false;" class="synchi_spacer"><img src="<?php echo $src; ?>" border="0" /></a>
                    <?php } else { ?>
                    <a href="#" onclick="synchiIDE_editor_action('<?php echo $control; ?>'); return false;" title="<?php echo $title; ?>"><img src="<?php echo $src; ?>" border="0" /></a>
                    <?php }} ?>
                </div>
            </td>
            <td style="width: 10px;"></td>
            <td style="width: 300px; border-top: 1px solid #DFDFDF; text-align: right">
                <span id="synchi_ide_sidebar_filesize"></span>
            </td>
            <td style="width: 5px;"></td>
        </tr>
    </table>
    <br style="clear: both" />
</div>

<div class="contextMenu" id="synchi_ide_sidebar_menu" style="display: none">
    <ul>
        <?php foreach($sidebar_controls as $control => $title) { ?>
        <li id="synchi_sidebar_<?php echo $control; ?>"><img src="<?php echo WP_PLUGIN_URL . "/synchi/img/ide/menu/$control.png"; ?>" /> <?php echo $title; ?></li>
        <?php } ?>
    </ul>
</div>

<div class="contextMenu" id="synchi_ide_tabs_menu" style="display: none">
    <ul>
        <?php foreach($tab_controls as $control => $title) { ?>
        <li id="synchi_tabs_<?php echo $control; ?>"><?php echo $title; ?></li>
        <?php } ?>
    </ul>
</div>