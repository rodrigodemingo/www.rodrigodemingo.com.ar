<?php 
    
// =============================================================================
// File: settings.php
// Version: 3.0
// 
// Renders synchi settings.
// =============================================================================

// check access
if(!defined('SYNCHI')) exit('Direct access is not allowed...'); 
    
?>

<script type="text/javascript">
    
    $ = jQuery;
    
    $(function(){
        $('input[type="checkbox"]').change(function(){
            var checkbox = $(this);
            checkbox.prev('select').val((checkbox.is(':checked')) ? 1 : 0);
        });
        $("#synchi_theme").change(function(){
            $("#synchi_theme_preview").attr('src','<?php echo WP_PLUGIN_URL; ?>/synchi/img/theme-previews/' + $(this).val() + '.png');
        });
        $("#synchi_theme").change();
    });
    
</script>

<div class="wrap">
    
    <div id="icon-options-general" class="icon32"><br></div>
    <h2><?php echo __('Synchi Settings','synchi'); ?></h2>
    
    <form method="post" action="<?php echo WP_ADMIN_URL; ?>/index.php">
        
        <h3><?php echo __('Global Settings','synchi'); ?></h3>
        <hr />
        <table class='form-table'>
            <tr valign='top'>
                <th scope='row'><?php echo __('Plugins Editor','synchi'); ?></th>
                <td>
                    <select name="synchi_option_flag_plugins" style="display: none">
                        <option value="0" <?php if($synchi_settings['flag_plugins'] == 0) echo 'selected="selected"'; ?>>off</option>
                        <option value="1" <?php if($synchi_settings['flag_plugins'] == 1) echo 'selected="selected"'; ?>>on</option>
                    </select>
                    <input type="checkbox" <?php if($synchi_settings['flag_plugins'] == 1) echo 'checked="true"'; ?>/>
                </td>
            </tr>
            <tr valign='top'>
                <th scope='row'><?php echo __('Themes Editor','synchi'); ?></th>
                <td>
                    <select name="synchi_option_flag_themes" style="display: none">
                        <option value="0" <?php if($synchi_settings['flag_themes'] == 0) echo 'selected="selected"'; ?>>off</option>
                        <option value="1" <?php if($synchi_settings['flag_themes'] == 1) echo 'selected="selected"'; ?>>on</option>
                    </select>
                    <input type="checkbox" <?php if($synchi_settings['flag_themes'] == 1) echo 'checked="true"'; ?>/>
                </td>
            </tr>
            <tr valign='top'>
                <th scope='row'><?php echo __('Articles Editor','synchi'); ?></th>
                <td>
                    <select name="synchi_option_flag_articles" style="display: none">
                        <option value="0" <?php if($synchi_settings['flag_articles'] == 0) echo 'selected="selected"'; ?>>off</option>
                        <option value="1" <?php if($synchi_settings['flag_articles'] == 1) echo 'selected="selected"'; ?>>on</option>
                    </select>
                    <input type="checkbox" <?php if($synchi_settings['flag_articles'] == 1) echo 'checked="true"'; ?>/>
                </td>
            </tr>
            <tr valign='top'>
                <th scope='row'><?php echo __('Text Widgets Editor','synchi'); ?></th>
                <td>
                    <select name="synchi_option_flag_widgets" style="display: none">
                        <option value="0" <?php if($synchi_settings['flag_widgets'] == 0) echo 'selected="selected"'; ?>>off</option>
                        <option value="1" <?php if($synchi_settings['flag_widgets'] == 1) echo 'selected="selected"'; ?>>on</option>
                    </select>
                    <input type="checkbox" <?php if($synchi_settings['flag_widgets'] == 1) echo 'checked="true"'; ?>/>
                </td>
            </tr>
        </table>
        
        <h3><?php echo __('Editing Settings','synchi'); ?></h3>
        <hr />
        <table class='form-table'>
            <tr valign='top'>
                <th scope='row'><?php echo __('Line Numbers','synchi'); ?></th>
                <td>
                    <select name="synchi_option_lineNumbers" style="display: none">
                        <option value="0" <?php if($synchi_settings['lineNumbers'] == 0) echo 'selected="selected"'; ?>>no</option>
                        <option value="1" <?php if($synchi_settings['lineNumbers'] == 1) echo 'selected="selected"'; ?>>yes</option>
                    </select>
                    <input type="checkbox" <?php if($synchi_settings['lineNumbers'] == 1) echo 'checked="true"'; ?>/>
                </td>
            </tr>
            <tr valign='top'>
                <th scope='row'><?php echo __('Match Brackets','synchi'); ?></th>
                <td>
                    <select name="synchi_option_matchBrackets" style="display: none">
                        <option value="0" <?php if($synchi_settings['matchBrackets'] == 0) echo 'selected="selected"'; ?>>no</option>
                        <option value="1" <?php if($synchi_settings['matchBrackets'] == 1) echo 'selected="selected"'; ?>>yes</option>
                    </select>
                    <input type="checkbox" <?php if($synchi_settings['matchBrackets'] == 1) echo 'checked="true"'; ?>/>
                </td>
            </tr>
            <tr valign='top'>
                <th scope='row'><?php echo __('Indent With Tabs','synchi'); ?></th>
                <td>
                    <select name="synchi_option_indentWithTabs" style="display: none">
                        <option value="0" <?php if($synchi_settings['indentWithTabs'] == 0) echo 'selected="selected"'; ?>>no</option>
                        <option value="1" <?php if($synchi_settings['indentWithTabs'] == 1) echo 'selected="selected"'; ?>>yes</option>
                    </select>
                    <input type="checkbox" <?php if($synchi_settings['indentWithTabs'] == 1) echo 'checked="true"'; ?>/>
                </td>
            </tr>
            <tr valign='top'>
                <th scope='row'><?php echo __('Tab Size','synchi'); ?></th>
                <td>
                    <select name="synchi_option_tabSize">
                        <option value="2" <?php if($synchi_settings['tabSize'] == 2) echo 'selected="selected"'; ?>>2</option>
                        <option value="3" <?php if($synchi_settings['tabSize'] == 3) echo 'selected="selected"'; ?>>3</option>
                        <option value="4" <?php if($synchi_settings['tabSize'] == 4) echo 'selected="selected"'; ?>>4</option>
                        <option value="5" <?php if($synchi_settings['tabSize'] == 5) echo 'selected="selected"'; ?>>5</option>
                        <option value="6" <?php if($synchi_settings['tabSize'] == 6) echo 'selected="selected"'; ?>>6</option>
                    </select>
                </td>
            </tr>
            <tr valign='top'>
                <th scope='row'><?php echo __('Font Size','synchi'); ?> (px)</th>
                <td>
                    <select name="synchi_option_fontSize">
                        <?php for($i=10; $i<=16; $i++) { ?>
                        <option value="<?php echo $i; ?>" <?php if($synchi_settings['fontSize'] == $i) echo 'selected="selected"'; ?>><?php echo $i; ?> px</option>
                        <?php } ?>
                    </select>
                </td>
            </tr>
        </table>
        
        <h3><?php echo __('Other Settings','synchi'); ?></h3>
        <hr />
        <table class='form-table'>
            <tr valign='top'>
                <th scope='row'><?php echo __('Theme','synchi'); ?></th>
                <td>
                    <select id="synchi_theme" name="synchi_option_theme">
                        <?php foreach($synchi_themes as $theme_option) { ?>
                        <option 
                            value="<?php echo $theme_option; ?>" 
                            <?php if($theme_option == $theme) echo 'selected="selected"'; ?>>
                            <?php echo $theme_option; ?>
                        </option>
                        <?php } ?>
                    </select>
                </td>
            </tr>
            <tr>
                <th scope='row'></th>
                <td>
                    <?php echo __('theme preview','synchi'); ?>:<br />
                    <img id="synchi_theme_preview" src="" style="width: 590px; height: 300px; border: 1px solid black;" />
                </td>
            </tr>
        </table>
        
        
        <?php submit_button(); ?>
        <input type="hidden" name="synchi_action" value="update_settings" />
    </form>

</div>