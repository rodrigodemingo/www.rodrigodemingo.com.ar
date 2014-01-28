<?php
/**
 * Theme Update Checker
 *
 * @package Smartbox
 * @subpackage Admin
 * @since 1.4
 *
 * @copyright (c) 2013 Oxygenna.com
 * @license **LICENSE**
 * @version 1.5
 */

class OxyThemeUpdate {
    /**
     * Stores array of theme setuop options
     *
     * @since 1.0
     * @access private
     * @var array
     */
    private $_theme;

    /**
     * Constructior, sets up all the update events
     *
     * @since 1.4
     */
    function __construct( $theme ) {
        $this->_theme = $theme;

        add_action( 'admin_menu', array( &$this, 'create_update_option_menu' ) );

        add_action( 'admin_init', array( &$this, 'admin_init' ) );
        add_action( 'switch_theme', array( &$this, 'switch_theme' ) );
        add_action( THEME_SHORT . '_check_theme_update', array( &$this, 'check_theme_update' ) );

        add_action( 'oxy-options-updated-' . THEME_SHORT . '-update', array( &$this, 'update_check_from_options' ) );
    }

    function create_update_option_menu() {
        // first find out the themes main menu
        $pages = $this->_theme->theme['option-pages'];
        foreach( $pages as $option_page_file ) {
            $page_data = include OPTIONS_DIR . 'option-pages/' . $option_page_file . '.php';
            if( $page_data['main_menu'] == true ) {
                $main_menu_slug = $page_data['slug'];
            }
        }

        // if we have a main menu add the update page
        if( null !== $main_menu_slug ) {
            add_submenu_page( $main_menu_slug, __('Update Theme From ThemeForest', THEME_ADMIN_TD), __('Update', THEME_ADMIN_TD), 'manage_options', THEME_SHORT.'-update', array( &$this , 'update_page_html' ) );
        }

    }

    function save_options() {
        if( ! isset( $_POST[ 'theme-options-nonce' ] ) || ! wp_verify_nonce( $_POST[ 'theme-options-nonce' ], THEME_SHORT . '-update-options' ) ) {
            return false;
        }

        if( isset( $_POST['submit'] ) ) {
            update_option( 'oxy_theme_update_username', $_POST['oxy_theme_update_username'] );
            update_option( 'oxy_theme_update_api', $_POST['oxy_theme_update_api'] );
            echo '<div id="message" class="updated"><p><strong>' . __('Settings Saved', THEME_ADMIN_TD) . '</strong></p></div>';
        }

        if( isset( $_POST['check_theme_update'] ) ) {
            $result = $this->check_theme_update();
            if( $result->updated_themes_count === 0 ) {
                echo '<div id="message" class="error"><p><strong>' . __('No Update Available', THEME_ADMIN_TD) . '</strong></p></div>';
            }
        }

        if( isset( $_POST['theme_update'] ) ) {
            $result = $this->update_theme();

            foreach( $result->errors as $error ) {
                echo '<div id="message" class="error"><p><strong>' . $error . '</strong></p></div>';
            }
        }

        return true;

    }

    function update_page_html() {
        // save options
        $this->save_options();
        // get status of update check
        $update_status = get_option( THEME_SHORT . '_theme_update_status' );

        // get other options
        $username = get_option( 'oxy_theme_update_username' );
        $api_key = get_option( 'oxy_theme_update_api' );

        ?>
        <div class="wrap">
            <div class="icon32">
                <img src="<?php echo ADMIN_ASSETS_URI . 'images/oxygenna.png' ?>" alt="Oxygenna logo">
            </div>
            <h2><?php echo get_admin_page_title(); ?></h2>
            <div id="ajax-errors-here"></div>
            <form method="post" action="">
                <table class="form-table">
                    <tbody>
                        <tr valign="top">
                            <th scope="row">
                                ThemeForest Username
                            </th>
                            <td>
                                <input name="oxy_theme_update_username" type="text" value="<?php echo $username; ?>">
                                <span class="description">Enter your theme forest username here</span>
                            </td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">
                                ThemeForest API Key
                            </th>
                            <td>
                                <input name="oxy_theme_update_api" type="text" value="<?php echo $api_key; ?>"/>
                                <span class="description">Enter your ThemeForest API Key here <a href="http://themeforest.net/help/api">Instuctions Here</a></span>
                            </td>
                        </tr>
                        <?php if( !empty( $username) && !empty( $api_key ) ) : ?>
                            <tr valign="top">
                                <th scope="row">
                                    Check for update
                                </th>
                                <td>
                                    <input type="submit" name="check_theme_update" class="btn btn-primary" value="Check again"/>
                                    <span class="description">Click to check for an update on ThemeForest</span>
                                </td>
                            </tr>
                            <?php if( isset( $update_status->updated_themes_count ) && $update_status->updated_themes_count > 0 ) : ?>
                                <tr valign="top" class="update-available">
                                    <th scope="row">
                                        Update available to download
                                    </th>
                                    <td>
                                        <strong style="color:red;">Warning untested - use at your own risk, backup your installation before use</strong>
                                        <br/>
                                        <input type="submit" name="theme_update" class="btn btn-primary" value="Update theme"/>
                                        <span class="description">Click to update to the latest version of the theme</span>
                                    </td>
                                </tr>
                            <?php endif; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
                <?php wp_nonce_field( THEME_SHORT . '-update-options', 'theme-options-nonce' ); ?>
                <div class="submit-footer">
                    <?php submit_button(); ?>
                </div>
            </form>
        </div>
    <?php
    }

    /**
     * Called on admin_init, sets up update Checker
     *
     * @return void
     * @since 1.4
     **/
    function admin_init() {
        // no event scheduled?
        if( !wp_next_scheduled( THEME_SHORT . '_check_theme_update' ) ) {
            // add new event
            wp_schedule_event( time(), 'hourly', THEME_SHORT . '_check_theme_update' );
        }
    }

    /**
     * Called when the theme is deactivated
     *
     * @return void
     * since 1.4
     **/
    function switch_theme() {
        // make sure we remove the scheduled event & option
        wp_clear_scheduled_hook( THEME_SHORT . '_check_theme_update' );
    }

    /**
     * Updates the theme from themeforest
     *
     * @return void
     * @since 1.4
     **/
    function update_theme() {
        $username = get_option( 'oxy_theme_update_username' );
        $api_key = get_option( 'oxy_theme_update_api' );

        if( isset( $username) && isset( $api_key ) ) {
            include MODULES_DIR  . 'envato-wordpress-toolkit-library/class-envato-wordpress-theme-upgrader.php';

            // create api upgrade checker
            $upgrader = new Envato_WordPress_Theme_Upgrader( 'oxygenna', '2ngkgj6p45u935sflddbhv8mtca8rdw3' );

            // update theme
            $result = $upgrader->upgrade_theme();

            // reset the update status
            update_option( THEME_SHORT . '_theme_update_status', false );

            return $result;
        }
    }

    /**
     * Runs twice a day to check for theme updates
     *
     * @return void
     * @author
     **/
    function check_theme_update() {
        $username = get_option( 'oxy_theme_update_username' );
        $api_key = get_option( 'oxy_theme_update_api' );

        if( isset( $username) && isset( $api_key ) ) {
            include MODULES_DIR  . 'envato-wordpress-toolkit-library/class-envato-wordpress-theme-upgrader.php';

            // create api upgrade checker
            $upgrader = new Envato_WordPress_Theme_Upgrader( 'oxygenna', '2ngkgj6p45u935sflddbhv8mtca8rdw3' );

            // check for update
            $result = $upgrader->check_for_theme_update();

            update_option( THEME_SHORT . '_theme_update_status', $result );

            return $result;
        }
    }

    /**
     * Checks theme is updatable from the options
     *
     * @return void
     * @since 1.4
     **/
    function update_check_from_options() {
        //add_action( 'init', array( &$this, 'show_update_available' ) );
    }

    function show_update_available() {
        //echo 'update available';
    }
}