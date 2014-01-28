<?php
/**
 * Template Name: Full Width - Padded
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
oxy_page_header();
$allow_comments = oxy_get_option( 'site_comments' );
?>
<section class="section section-padded">
    <div class="container-fluid">
        <div class="row-fluid">
            <?php while ( have_posts() ) : the_post(); ?>

            <?php get_template_part('partials/content', 'page'); ?>

            <?php if( $allow_comments == 'pages' || $allow_comments == 'all' ) comments_template( '', true ); ?>

            <?php endwhile; ?>
        </div>
    </div>
</section>
<?php get_footer();