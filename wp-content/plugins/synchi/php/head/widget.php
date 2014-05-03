<?php

// =============================================================================
// File: widget.php
// Version: 1.0
//
// Indcludes head files for synchi in text/HTML widgets
// =============================================================================

// check access
if(!defined('SYNCHI')) exit('Direct access is not allowed...');

$css_includes = array(
    // CodeMirror core
    'lib/codemirror/codemirror',
    // Synchi
    'css/synchi',
);

$js_includes = array(
    // CodeMirror core
    'lib/codemirror/codemirror',
    // CodeMirror modes
    'lib/codemirror/mode/clike',
    'lib/codemirror/mode/css',
    'lib/codemirror/mode/htmlmixed',
    'lib/codemirror/mode/javascript',
    'lib/codemirror/mode/mysql',
    'lib/codemirror/mode/php',
    'lib/codemirror/mode/xml',
    // Synchi
    'js/jquery.synchi',
    'js/synchi_widget',
);

?>

<script type="text/javascript">
    $ = jQuery;
    var synchi_settings = <?php echo json_encode($synchi_settings); ?>;
    var synchi_path = '<?php echo WP_PLUGIN_URL; ?>/synchi/';
    var synchi_labels = [];
    <?php  // echo labels
    echo "synchi_labels['Initializing Synchi IDE'] = '".__('Initializing Synchi IDE','synchi')."';";
    echo "synchi_labels['Toggle Fullscreen'] = '".__('Toggle Fullscreen','synchi')."';";
    ?>
</script>

<style type="text/css">
    .CodeMirror-wrap {
        border: 1px solid #CCC;
        margin-bottom: 10px;
        background-color: #ffffff;
    }

    .synchi_widget_controls {
        width: 100%;
        text-align: right;
    }

    .synchi_fullscreen {
        position:fixed !important;
        top: 28px !important;
        left: 0px !important;
        right: 0px !important;
        bottom: 0px !important;
        z-index:1000 !important;
        margin: 0 !important;
        background-color: whiteSmoke;
        padding: 10px;
    }

    .synchi_fullscreen .CodeMirror {
        /*height: 100% !important;*/
    }
</style>

<?php

foreach($css_includes as $css) synchi_echoCSSinclude($css);
foreach($js_includes as $js) synchi_echoJSinclude($js);
if($synchi_settings['theme'] != 'default') synchi_echoCSSinclude("lib/codemirror/theme/{$synchi_settings['theme']}");

?>