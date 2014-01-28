<?php
/**
 * Displays a single post
 *
 * @package Smartbox
 * @subpackage Frontend
 * @since 0.1
 *
 * @copyright (c) 2013 Oxygenna.com
 * @license http://wiki.envato.com/support/legal-terms/licensing-terms/
 * @version 1.5
 */

get_header();
?>
<?php oxy_create_hero_section( null, null ); ?>
<section class="section section-padded">
    <div class="container-fluid">
        <div class="row-fluid">
            <?php get_template_part( 'partials/loop' ); ?>
        </div>
    </div>
</section>
<?php get_footer();