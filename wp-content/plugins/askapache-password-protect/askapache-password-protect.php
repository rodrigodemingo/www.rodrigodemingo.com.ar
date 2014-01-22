<?php
/**
 * Plugin Name: AskApache Password Protect
 * Short Name: AA PassPro
 * Description:  Advanced Security: Password Protection, Anti-Spam, Anti-Exploits, more to come...
 * Author: askapache
 * Contributors: askapache
 * Version: 4.6.8
 * Requires at least: 2.7
 * Tested up to: 3.5.2
 * Tags: password, secure, wp-admin, hacked, virus, apache, server, hacker, cracker, protect, spammer, security, admin, username, access, authorization, authentication, spam, hack, login, askapache, htaccess, rewrite, redirect, mod_security, htpasswd
 * WordPress URI: http://wordpress.org/extend/plugins/askapache-debug-viewer/
 * Author URI: http://www.askapache.com/
 * Donate URI: http://www.askapache.com/donate/
 * Plugin URI:http://www.askapache.com/htaccess/htaccess-security-block-spam-hackers.html
 *
 *
 * AskApache Password Protect - AskApache Password Protect WordPress Plugin for .htaccess Files
 * Copyright (C) 2010	AskApache.com
 *
 * This program is free software - you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.	If not, see <http://www.gnu.org/licenses/>.
 */


// exit if add_action or plugins_url functions do not exist
!defined('ABSPATH') || !function_exists('add_action') || !function_exists('plugins_url') || !function_exists('add_management_page') || !function_exists('wp_die') && exit;


/********************************************************************************************************************************************************************************************************
 COMPAT FUNCTIONS
 ********************************************************************************************************************************************************************************************************/
if (!function_exists('wp_die')) : function wp_die ($message = 'wp_die') { die($message); } endif;
if (!function_exists('absint')): function absint( $maybeint ) { return abs( intval( $maybeint ) ); } endif;
if (!function_exists('is_a')) : function is_a($o, $c) { return (!is_object($o)) ? false : ((strtolower(get_class($o)) == strtolower($c)) ? true : is_subclass_of($o, $c)); } endif;
if (!function_exists('stripos')) : function stripos($haystack, $needle, $offset = 0) { return strpos(strtolower($haystack), strtolower($needle), $offset); } endif;


/********************************************************************************************************************************************************************************************************
 DEFINES
 ********************************************************************************************************************************************************************************************************/
!defined('NET_SOCKET_READ') && define('NET_SOCKET_READ',  1);
!defined('NET_SOCKET_WRITE') && define('NET_SOCKET_WRITE', 2);
!defined('NET_SOCKET_ERROR') && define('NET_SOCKET_ERROR', 4);
!defined('STREAM_CRYPTO_METHOD_TLS_CLIENT') && define('STREAM_CRYPTO_METHOD_TLS_CLIENT', 3);
!defined('STREAM_CRYPTO_METHOD_SSLv3_CLIENT') && define('STREAM_CRYPTO_METHOD_SSLv3_CLIENT', 1);
!defined('STREAM_CRYPTO_METHOD_SSLv23_CLIENT') && define('STREAM_CRYPTO_METHOD_SSLv23_CLIENT', 2);
!defined('STREAM_CRYPTO_METHOD_SSLv2_CLIENT') && define('STREAM_CRYPTO_METHOD_SSLv2_CLIENT', 0);



// WORDPRESS BUILTINS
!defined('WP_CONTENT_DIR') && define( 'WP_CONTENT_DIR', ABSPATH . 'wp-content' );
!defined('WP_CONTENT_URL') && define( 'WP_CONTENT_URL', WP_SITEURL . '/wp-content');
!defined('WP_PLUGIN_DIR') && define( 'WP_PLUGIN_DIR', WP_CONTENT_DIR . '/plugins' );
!defined('WP_PLUGIN_URL') && define( 'WP_PLUGIN_URL', WP_CONTENT_URL . '/plugins' );
!defined('COOKIEPATH') && define('COOKIEPATH', preg_replace('|https?://[^/]+|i', '', get_option('home') . '/'));
!defined('SITECOOKIEPATH') && define('SITECOOKIEPATH', preg_replace('|https?://[^/]+|i', '', get_option('siteurl') . '/'));
!defined('ADMIN_COOKIE_PATH') && define('ADMIN_COOKIE_PATH', SITECOOKIEPATH . 'wp-admin');
!defined('PLUGINS_COOKIE_PATH') && define('PLUGINS_COOKIE_PATH', preg_replace('|https?://[^/]+|i', '', WP_PLUGIN_URL));

// AA_PP DEFINES
!defined('AA_PP_DIR') && define('AA_PP_DIR', dirname(__FILE__));
!defined('AA_PP_URL') && define('AA_PP_URL', WP_PLUGIN_URL . '/' . basename(dirname(__FILE__)));

define( 'AA_PP_DEBUG', 0 ); // set this to 1 for verbose debugging
define( 'AA_PP_NET_DEBUG', 0 ); // set this to 1 for verbose network debugging


/** aa_pp_deactivate
* aa_pp_deactivate()
 *
 * @return
 */
function aa_pp_deactivate()
{
	global $aa_PP,$aa_SIDS;
	$aa_PP=get_option("askapache_password_protect");
	$aa_SIDS=get_option("askapache_password_protect_sids");
	
	aa_pp_deactivate_sid("PASSPRO","ASKAPACHE ",$aa_PP["root_htaccess"]);
	aa_pp_deactivate_sid("PASSPRO","ASKAPACHE ",$aa_PP["admin_htaccess"]);
	
	delete_option("askapache_password_protect");
	delete_option("askapache_password_protect_plugin");
	delete_option("askapache_password_protect_sids");
}


/** aa_pp_activate
* aa_pp_activate()
 *
 * @return
 */
function aa_pp_activate()
{
	global $wpdb, $aa_PP, $aa_SIDS, $aa_PLUGIN;
	$aa_PP = $s = $aa_SIDS = array();
	
	$aa_PLUGIN=aa_pp_get_plugin_data();

	foreach ( array( 'home_folder', 'wpadmin_folder', 'htpasswd_file', 'htaccess_file', 'original_htpasswd', 'original_htaccess', 'plugin_message', 'plugin_version', 'home', 'wpadmin', 'htpasswd_f', 'htaccess_f', 'user', 'plugin_message', 'home_folder', 'wpadmin_folder', 'htpasswd_file', 'htaccess_file', 'original_htpasswd', 'original_htaccess', 'plugin_message', 'plugin_version', 'pp_docroot_htaccess', 'pp_wp_includes_htaccess', 'pp_wp_content_htaccess', 'pp_wp_includes_htaccess', 'pp_main_base64', 'pp_ok' ) as $option )	delete_option( 'aa_'.$option );


	$scheme = ( isset($_SERVER['HTTPS']) && ( 'on' == strtolower($_SERVER['HTTPS']) ||  '1' == $_SERVER['HTTPS'] )  || ( isset($_SERVER['SERVER_PORT']) && ( '443' == $_SERVER['SERVER_PORT'] ) )) ? 'https' : 'http';
	$home = get_option( 'home' );
	$siteurl=get_option('siteurl');
	if($scheme=='https' && strpos($siteurl.$home,'https://')!==FALSE)$scheme='http';

	$su = parse_url( $home );

	!defined('WP_CONTENT_DIR') && define( 'WP_CONTENT_DIR', ABSPATH . 'wp-content' );
	!defined('WP_CONTENT_URL') && define( 'WP_CONTENT_URL', $siteurl . '/wp-content');
	!defined('WP_PLUGIN_DIR') && define( 'WP_PLUGIN_DIR', WP_CONTENT_DIR . '/plugins' );
	!defined('WP_PLUGIN_URL') && define( 'WP_PLUGIN_URL', WP_CONTENT_URL . '/plugins' );

	$home = get_option( 'siteurl' );
	
	$su = parse_url( $home );
	$path = ( !isset( $su['path'] ) || empty( $su['path'] ) ) ? '/' : rtrim( $su['path'], '/' ) . '/';
	aa_pp_notify(__FUNCTION__ . ":" . __LINE__ . ' ' . "path: $path" );
	$home_path = rtrim( get_home_path(), '/' ) . '/';
	$hu = str_replace( $scheme . '://', '', $home );
	aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "hu: $hu" );
	$url = $scheme . '://' . rtrim( str_replace( rtrim( $path, '/' ), '', $hu ), '/' );
	aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "url: $url" );
	$authdomain = "/wp-admin/";

	update_option( 'askapache_password_protect', array( 
			'step' => 'welcome',
			'setup_complete' => 0,
			'scheme' => $scheme,
			'host' => $su['host'],
			'root_path' => $path,
			'home_path' => $home_path,
			'test_dir' => WP_CONTENT_DIR.'/askapache',
			'root_htaccess' => $home_path . '.htaccess',
			'admin_htaccess' => $home_path . 'wp-admin/.htaccess',
			'admin_mail' => get_option( 'admin_email' ),
			'authdomain' => $authdomain,
			'authname' => 'Protected By AskApache',
			'authuserfile' => $home_path . '.htpasswda3',
			'authuserdigest' => 'AuthUserFile',
			'algorithm' => 'md5',
			'key' => wp_hash_password( wp_generate_password() ),
			'htaccess_support' => 0,
			'mod_alias_support' => 0,
			'mod_rewrite_support' => 0,
			'mod_security_support' => 0,
			'mod_auth_digest_support' => 0,
			'basic_support' => 0,
			'digest_support' => 0,
			'crypt_support' => 0,
			'sha1_support' => 0,
			'md5_support' => 0,
			'revision_support' => 0,
			'apache_version' => '',
			'revisions' => array(),
			'plugin_data' => get_plugin_data( __FILE__ ),
			) );
			
	update_option( 'askapache_password_protect_sids', array( 
			60000001 => array( 'Version' => '1.3',
				'Name' => 'Directory Protection',
				'Description' => 'Enable the DirectoryIndex Protection, preventing directory index listings and defaulting.',
				'Rules' =>
				'Options -Indexes%n%' . 
				'DirectoryIndex index.html index.php %relative_root%index.php'
				),

			60000002 => array( 'Version' => '1.0',
				'Name' => 'Loop Stopping Code',
				'Description' => 'Stops Internal Redirect Loops',
				'Rules' =>
				'RewriteCond %{ENV:REDIRECT_STATUS} 200%n%' . 
				'RewriteRule .* - [L]%n%'
				),

			10140001 => array( 'Version' => '1.1',
				'Name' => 'Stop Hotlinking',
				'Description' => 'Denies any request for static files (images, css, etc) if referrer is not local site or empty.',
				'Rules' =>
				'RewriteCond %{HTTP_REFERER} !^$%n%' . 
				'RewriteCond %{REQUEST_URI} !^%relative_root%(wp-login.php|wp-admin/|wp-content/plugins/|wp-includes/).* [NC]%n%' . 
				'RewriteCond %{HTTP_REFERER} !^%scheme%://%host%.*$ [NC]%n%' . 
				'RewriteRule \.(ico|pdf|flv|jpg|jpeg|mp3|mpg|mp4|mov|wav|wmv|png|gif|swf|css|js)$ - [F,NS,L]'
				),

			20030001 => array( 'Version' => '1.4',
				'Name' => 'Password Protect wp-login.php',
				'Description' => 'Requires a valid user/pass to access the login page..',
				'Rules' =>
				'<Files wp-login.php>%n%' . 
				'Satisfy Any%n%' . 
				'%generate_auth%%n%' . 
				'</Files>%n%'.
				'<FilesMatch "\.([hH][tT][aApP].*)$">%n%' .
				'Deny from all%n%'.
				'</FilesMatch>%n%'
				),

			21030002 => array( 'Version' => '1.3',
				'Name' => 'Password Protect wp-admin',
				'Description' => 'Requires a valid user/pass to access any non-static (css, js, images) file in this directory...',
				'Rules' =>
				'%generate_auth%%n%' . 
				'<FilesMatch "\.(ico|pdf|flv|jpg|jpeg|mp3|mpg|mp4|mov|wav|wmv|png|gif|swf|css|js)$">%n%' . 
				'Allow from All%n%' . 
				'</FilesMatch>%n%' . 
				'<FilesMatch "(async-upload|admin-ajax)\.php$">%n%' . 
				'<IfModule mod_security.c>%n%' . 
				'SecFilterEngine Off%n%' . 
				'</IfModule>%n%' . 
				'Allow from All%n%' . 
				'</FilesMatch>'
				),

			30140003 => array( 'Version' => '1.1',
				'Name' => 'Forbid Proxies',
				'Description' => 'Denies POST Request using a Proxy Server. Can access site, but not comment. See <a href="http://perishablepress.com/press/2008/04/20/how-to-block-proxy-servers-via-htaccess/">Perishable Press</a>',
				'Rules' =>
				'RewriteCond %{HTTP:VIA}%{HTTP:FORWARDED}%{HTTP:USERAGENT_VIA}%{HTTP:X_FORWARDED_FOR}%{HTTP:PROXY_CONNECTION} !^$ [OR]%n%' . 
				'RewriteCond %{HTTP:XPROXY_CONNECTION}%{HTTP:HTTP_PC_REMOTE_ADDR}%{HTTP:HTTP_CLIENT_IP} !^$%n%' . 
				'RewriteCond %{REQUEST_URI} !^%relative_root%(wp-login.php|wp-admin/|wp-content/plugins/|wp-includes/).* [NC]%n%' . 
				'RewriteCond %{REQUEST_METHOD} =POST%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			30140004 => array( 'Version' => '1.1',
				'Name' => 'Real wp-comments-post.php',
				'Description' => 'Denies any POST attempt made to a non-existing wp-comments-post.php..',
				'Rules' =>
				'RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ %relative_root%.*/wp-comments-post\.php.*\ HTTP/ [NC]%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			30140005 => array( 'Version' => '1.1',
				'Name' => 'BAD Content Length',
				'Description' => 'Denies any POST request that doesnt have a Content-Length Header..',
				'Rules' =>
				'RewriteCond %{REQUEST_METHOD} =POST%n%' . 
				'RewriteCond %{REQUEST_URI} !^%relative_root%(wp-admin/|wp-content/plugins/|wp-includes/).* [NC]%n%' . 
				'RewriteCond %{HTTP:Content-Length} ^$%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			30140006 => array( 'Version' => '1.1',
				'Name' => 'BAD Content Type',
				'Description' => 'Denies any POST request with a content type other than application/x-www-form-urlencoded|multipart/form-data..',
				'Rules' =>
				'RewriteCond %{REQUEST_METHOD} =POST%n%' . 
				'RewriteCond %{REQUEST_URI} !^%relative_root%(wp-login.php|wp-admin/|wp-content/plugins/|wp-includes/).* [NC]%n%' . 
				'RewriteCond %{HTTP:Content-Type} !^(application/x-www-form-urlencoded|multipart/form-data.*(boundary.*)?)$ [NC]%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			30140007 => array( 'Version' => '1.1',
				'Name' => 'NO HOST:',
				'Description' => 'Denies requests that dont contain a HTTP HOST Header...',
				'Rules' =>
				'RewriteCond %{REQUEST_URI} !^%relative_root%(wp-login.php|wp-admin/|wp-content/plugins/|wp-includes/).* [NC]%n%' . 
				'RewriteCond %{HTTP_HOST} ^$%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			30140008 => array( 'Version' => '1.1',
				'Name' => 'No UserAgent, No Post',
				'Description' => 'Denies POST requests by blank user-agents. May prevent a small number of visitors from POSTING.',
				'Rules' =>
				'RewriteCond %{REQUEST_METHOD} =POST%n%' . 
				'RewriteCond %{REQUEST_URI} !^%relative_root%(wp-login.php|wp-admin/|wp-content/plugins/|wp-includes/).* [NC]%n%' . 
				'RewriteCond %{HTTP_USER_AGENT} ^-?$%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			30140009 => array( 'Version' => '1.1',
				'Name' => 'No Referer, No Comment',
				'Description' => 'Denies any comment attempt with a blank HTTP_REFERER field, highly indicative of spam. May prevent some visitors from POSTING.',
				'Rules' =>
				'RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /.*/wp-comments-post\.php.*\ HTTP/ [NC]%n%' . 
				'RewriteCond %{HTTP_REFERER} ^-?$%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			30140010 => array( 'Version' => '1.1',
				'Name' => 'Trackback Spam',
				'Description' => 'Denies obvious trackback spam.  See <a href="http://ocaoimh.ie/2008/07/03/more-ways-to-stop-spammers-and-unwanted-traffic/">Holy Shmoly!</a>',
				'Rules' =>
				'RewriteCond %{HTTP_USER_AGENT} ^.*(opera|mozilla|firefox|msie|safari).*$ [NC,OR]%n%' . 
				'RewriteCond %{HTTP_USER_AGENT} ^-?$%n%' . 
				'RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /.+/trackback/?\ HTTP/ [NC]%n%' . 
				'RewriteCond %{REQUEST_METHOD} =POST%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			40140011 => array( 'Version' => '1.2',
				'Name' => 'Protect wp-content',
				'Description' => 'Denies any Direct request for files ending in .php with a 403 Forbidden.. May break plugins/themes',
				'Rules' =>
				'RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ %relative_root%wp-content/.*$ [NC]%n%' . 
				'RewriteCond %{REQUEST_FILENAME} !^.+(flexible-upload-wp25js|media)\.php$%n%' . 
				'RewriteCond %{REQUEST_FILENAME} ^.+\.(php|html|htm|txt)$%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			40140012 => array( 'Version' => '1.2',
				'Name' => 'Protect wp-includes',
				'Description' => 'Denies any Direct request for files ending in .php with a 403 Forbidden.. May break plugins/themes',
				'Rules' =>
				'RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ %relative_root%wp-includes/.*$ [NC]%n%' . 
				'RewriteCond %{THE_REQUEST} !^[A-Z]{3,9}\ %relative_root%wp-includes/js/.+/.+\ HTTP/ [NC]%n%' . 
				'RewriteCond %{REQUEST_FILENAME} ^.+\.php$%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			40140013 => array( 'Version' => '1.1',
				'Name' => 'Common Exploit',
				'Description' => 'Block common exploit requests with 403 Forbidden. These can help alot, may break some plugins.',
				'Rules' =>
				'RewriteCond %{REQUEST_URI} !^%relative_root%(wp-login.php|wp-admin/|wp-content/plugins/|wp-includes/).* [NC]%n%' . 
				'RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ ///.*\ HTTP/ [NC,OR]%n%' . 
				'RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /.+\?\=?(http|ftp|ssl|https):/.*\ HTTP/ [NC,OR]%n%' . 
				'RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /.*\?\?.*\ HTTP/ [NC,OR]%n%' . 
				'RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /.*\.(asp|ini|dll).*\ HTTP/ [NC,OR]%n%' . 
				'RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /.*\.(htpasswd|htaccess|aahtpasswd).*\ HTTP/ [NC]%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			50140001 => array( 'Version' => '1.1',
				'Name' => 'Safe Request Methods',
				'Description' => 'Denies any request not using <a href="/online-tools/request-method-scanner/">GET,PROPFIND,POST,OPTIONS,PUT,HEAD</a>..',
				'Rules' =>
				'RewriteCond %{REQUEST_METHOD} !^(GET|HEAD|POST|PROPFIND|OPTIONS|PUT)$ [NC]%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			50140002 => array( 'Version' => '1.1',
				'Name' => 'HTTP PROTOCOL',
				'Description' => 'Denies any badly formed HTTP PROTOCOL in the request, 0.9, 1.0, and 1.1 only..',
				'Rules' =>
				'RewriteCond %{THE_REQUEST} !^[A-Z]{3,9}\ .+\ HTTP/(0\.9|1\.0|1\.1) [NC]%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			50140003 => array( 'Version' => '1.1',
				'Name' => 'SPECIFIC CHARACTERS',
				'Description' => 'Denies any request for a url containing characters other than "a-zA-Z0-9.+/-?=&" - REALLY helps but may break your site depending on your links.',
				'Rules' =>
				'RewriteCond %{REQUEST_URI} !^%relative_root%(wp-login.php|wp-admin/|wp-content/plugins/|wp-includes/).* [NC]%n%' . 
				'RewriteCond %{THE_REQUEST} !^[A-Z]{3,9}\ [A-Z0-9\.\+_/\-\?\=\&\%\#]+\ HTTP/ [NC]%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			50140004 => array( 'Version' => '1.1',
				'Name' => 'Directory Traversal',
				'Description' => 'Denies Requests containing ../ or ./. which is a directory traversal exploit attempt..',
				'Rules' =>
				'RewriteCond %{THE_REQUEST} !^[A-Z]{3,9}\ .*([\.]+[\.]+).*\ HTTP/ [NC]%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			50140005 => array( 'Version' => '1.1',
				'Name' => 'PHPSESSID Cookie',
				'Description' => 'Only blocks when a PHPSESSID cookie is sent by the user and it contains characters other than 0-9a-z..',
				'Rules' =>
				'RewriteCond %{HTTP_COOKIE} ^.*PHPSESS?ID.*$%n%' . 
				'RewriteCond %{HTTP_COOKIE} !^.*PHPSESS?ID=([0-9a-z]+);.*$%n%' . 
				'RewriteRule .* - [F,NS,L]'
				),

			50140006 => array( 'Version' => '1.1',
				'Name' => 'Bogus Graphics Exploit',
				'Description' => 'Denies obvious exploit using bogus graphics..',
				'Rules' =>
				'RewriteCond %{HTTP:Content-Disposition} \.php [NC]%n%' . 
				'RewriteCond %{HTTP:Content-Type} image/.+ [NC]%n%' . 
				'RewriteRule .* - [F,NS,L]'
			),
			
			50140007 => array( 'Version' => '5',
				'Name' => '5G Blacklist 2013',
				'Description' => '<a href="http://perishablepress.com/5g-blacklist-2013/">Perishable Press</a>.. The 5G protects against malicious QUERY STRINGS, User Agents, and Requests',
				'Rules' =>
					'# 5G BLACKLIST/FIREWALL (2013)%n%' .
					'# @ http://perishablepress.com/5g-blacklist-2013/%n%' .
					'# 5G:[QUERY STRINGS]%n%' .
					'<IfModule mod_rewrite.c>%n%' .
					'RewriteEngine On%n%' .
					'RewriteBase /%n%' .
					'RewriteCond %{QUERY_STRING} (\"|%22).*(<|>|%3) [NC,OR]%n%' .
					'RewriteCond %{QUERY_STRING} (javascript:).*(\;) [NC,OR]%n%' .
					'RewriteCond %{QUERY_STRING} (<|%3C).*script.*(>|%3) [NC,OR]%n%' .
					'RewriteCond %{QUERY_STRING} (\\|\.\./|`|='."\'".'$|=%27$) [NC,OR]%n%' .
					'RewriteCond %{QUERY_STRING} (\;|'."\'".'|\"|%22).*(union|select|insert|drop|update|md5|benchmark|or|and|if) [NC,OR]%n%' .
					'RewriteCond %{QUERY_STRING} (base64_encode|localhost|mosconfig) [NC,OR]%n%' .
					'RewriteCond %{QUERY_STRING} (boot\.ini|echo.*kae|etc/passwd) [NC,OR]%n%' .
					'RewriteCond %{QUERY_STRING} (GLOBALS|REQUEST)(=|\[|%) [NC]%n%' .
					'RewriteRule .* - [F]%n%' .
					'</IfModule>%n%' .
					'# 5G:[USER AGENTS]%n%' .
					'<IfModule mod_setenvif.c>%n%' .
					'# SetEnvIfNoCase User-Agent ^$ keep_out%n%' .
					'SetEnvIfNoCase User-Agent (binlar|casper|cmsworldmap|comodo|diavol|dotbot|feedfinder|flicky|ia_archiver|jakarta|kmccrew|nutch|planetwork|purebot|pycurl|skygrid|sucker|turnit|vikspider|zmeu) keep_out%n%' .
					'<limit GET POST PUT>%n%' .
					'Order Allow,Deny%n%' .
					'Allow from all%n%' .
					'Deny from env=keep_out%n%' .
					'</limit>%n%' .
					'</IfModule>%n%' .
					'# 5G:[REQUEST STRINGS]%n%' .
					'<IfModule mod_alias.c>%n%' .
					'RedirectMatch 403 (https?|ftp|php)\://%n%' .
					'RedirectMatch 403 /(https?|ima|ucp)/%n%' .
					'RedirectMatch 403 /(Permanent|Better)$%n%' .
					'RedirectMatch 403 (\=\\'."\'".'|\=\\%27|/\\'."\'".'/?|\)\.css\()$%n%' .
					'RedirectMatch 403 (\,|\)\+|/\,/|\{0\}|\(/\(|\.\.\.|\+\+\+|\||\\\"\\\")%n%' .
					'RedirectMatch 403 \.(cgi|asp|aspx|cfg|dll|exe|jsp|mdb|sql|ini|rar)$%n%' .
					'RedirectMatch 403 /(contac|fpw|install|pingserver|register)\.php$%n%' .
					'RedirectMatch 403 (base64|crossdomain|localhost|wwwroot|e107\_)%n%' .
					'RedirectMatch 403 (eval\(|\_vti\_|\(null\)|echo.*kae|config\.xml)%n%' .
					'RedirectMatch 403 \.well\-known/host\-meta%n%' .
					'RedirectMatch 403 /function\.array\-rand%n%' .
					'RedirectMatch 403 \)\;\$\(this\)\.html\(%n%' .
					'RedirectMatch 403 proc/self/environ%n%' .
					'RedirectMatch 403 msnbot\.htm\)\.\_%n%' .
					'RedirectMatch 403 /ref\.outcontrol%n%' .
					'RedirectMatch 403 com\_cropimage%n%' .
					'RedirectMatch 403 indonesia\.htm%n%' .
					'RedirectMatch 403 \{\$itemURL\}%n%' .
					'RedirectMatch 403 function\(\)%n%' .
					'RedirectMatch 403 labels\.rdf%n%' .
					'RedirectMatch 403 /playing.php%n%' .
					'RedirectMatch 403 muieblackcat%n%' .
					'</IfModule>%n%'
				)
			)
		);

	$aa_SIDS = get_option( 'askapache_password_protect_sids' );
	$sids = array_keys( $aa_SIDS );
	foreach ( $sids as $sid )
	{
		$newinfo = aa_pp_sid_info( $sid );
		$aa_SIDS[$sid] = array_merge( $aa_SIDS[$sid], $newinfo );
	}

	update_option( 'askapache_password_protect_sids', $aa_SIDS );
}






/** aa_pp_get_post_values
* aa_pp_get_post_values()
 *
 * @param mixed $v
 * @return
 */
function aa_pp_get_post_values( $v )
{
	global $aa_PP, $aa_SIDS;
	$errors = new WP_Error;

	$action = 'none';
	foreach( array( 'a_htaccess_support', 'a_mod_alias_support', 'a_mod_rewrite_support', 'a_mod_security_support', 'a_mod_auth_digest_support', 'a_digest_support', 'a_basic_support' ) as $k )
	{
		if ( isset( $_POST[$k] ) && $v[$k] != 1 )
		{
			check_admin_referer( 'askapache-passpro-form' );
			$v[substr( $k, 2 )] = 1;
		}
	}

	foreach( array( 'a_user', 'a_authdomain', 'a_authtype', 'a_algorithm', 'a_authname', 'a_authuserfile', 'a_step', 'a_admin_email', 'a_root_htaccess', ) as $k )
	{
		if ( isset( $_POST[$k] ) && !empty( $_POST[$k] ) && $_POST[$k] != $v[$k] )
		{
			check_admin_referer( 'askapache-passpro-form' );
			$v[substr( $k, 2 )] = $_POST[$k];
		}
	}

	foreach ( array( 'activate-selected', 'deactivate-selected', 'delete-selected', 'm_move' ) as $action_key )
	{
		if ( isset( $_POST[$action_key] ) )
		{
			aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "Setting action to {$action_key}" );
			$action = $action_key;
			break;
		}
	}

	if ( $action == 'm_move' )
	{
		check_admin_referer( 'askapache-move-area' );
		foreach( array( 'm_read', 'm_reset', 'm_sid', 'm_setup', 'm_test', 'm_welcome', 'm_contact' ) as $where )
		{
			if ( isset( $_POST[$where] ) )
			{
				$aa_PP['step'] = substr( $where, 2 );
				aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "Setting step to {$aa_PP['step']}" );
				break;
			}
		}
		return true;
	}

	foreach ( array( 'deactivate-sid', 'activate-sid', 'view-revision', 'activate-revision', 'delete-revision' ) as $ak )
	{
		if ( isset( $_GET[$ak] ) )
		{
			$action = $ak;
			break;
		}
	}

	if ( isset( $_POST['a_pass1'] ) && isset( $_POST['a_pass2'] ) )
	{
		if ( empty( $_POST['a_pass1'] ) || empty( $_POST['a_pass2'] ) )$errors->add( 'password-required', __( '<strong>ERROR</strong>: A password is required' ) );
		if ( $_POST['a_pass1'] != $_POST['a_pass2'] )$errors->add( 'passwords-notsame', __( '<strong>ERROR</strong>: The passwords do not match.' ) );
		else $pass = $_POST['a_pass1'];
	}

	if ( isset( $_POST['a_user'] ) && isset( $_POST['a_admin_email'] ) )
	{
		if ( empty( $_POST['a_user'] ) )$errors->add( 'username-required', __( '<strong>ERROR</strong>: A username is required.' ) );
		if ( empty( $_POST['a_admin_email'] ) )$errors->add( 'adminemail-required', __( '<strong>ERROR</strong>: An admin email is required.' ) );
		if ( !is_email( $_POST['a_admin_email'] ) )$errors->add( 'adminemail-bad', __( '<strong>ERROR</strong>: A valid admin email is required.' ) );
	}

	if ( isset( $v['authtype'] ) && !in_array( $v['authtype'], array( 'Digest', 'Basic' ) ) ) $errors->add( 'bad-authtype', __( '<strong>ERROR</strong>: Incorrect authtype' ) );

	if ( isset( $v['algorithm'] ) && !in_array( $v['algorithm'], array( 'crypt', 'md5', 'sha1' ) ) ) $errors->add( 'bad-algorithm', __( '<strong>ERROR</strong>: Incorrect algorithm' ) );

	if ( isset($v['user']) && strpos( $v['user'], ':' ) !== false ) $errors->add( 'bad-username', __( '<strong>ERROR</strong>: Username cannot contain the : character' ) );

	if ( isset($v['authname']) && strlen( $v['authname'] ) > 65 ) $errors->add( 'bad-authname', __( '<strong>ERROR</strong>: Authname cannot exceed 65 characters, yours was ' . strlen( $v['authname'] ) . ' characters' ) );

	if ( isset($v['authtype']) && $v['authtype'] == 'Digest' && $v['algorithm'] != 'md5' ) $errors->add( 'algorithm-authtype-mismatch', __( '<strong>ERROR</strong>: Digest Authentication can only use the md5 algorithm' ) );

	foreach( array( $v['authuserfile'], $v['admin_htaccess'], $v['root_htaccess'] ) as $f )
	{
		if ( strpos( basename( $f ), '.ht' ) === false ) $errors->add( 'bad-authuserfilename', __( '<strong>ERROR</strong>: File names must start with .ht like .htaccess or .htpasswd-new3' ) );
		if ( (int)$v['setup_complete'] != 0 )
		{
			if ( aa_pp_htaccess_file_init() && !@touch($f) || !@is_writable( $f ) ) $errors->add( 'unwritable-file', __( '<strong>ERROR</strong>: Please make ' . $f . ' writable and readable' ) );
		}
	}

	if ( count( $errors->errors ) == 0 )
	{
		$aa_PP = $v;

		switch ( $action )
		{
			case 'activate-revision':
				$file = $_GET['activate-revision'];
				check_admin_referer( 'activate-revision_' . $file );
				break;
			case 'view-revision':
				$file = $_GET['view-revision'];
				check_admin_referer( 'view-revision_' . $file );
				break;
			case 'delete-revision':
				$file = $_GET['delete-revision'];
				check_admin_referer( 'delete-revision_' . $file );
				$g = array();
				foreach( $aa_PP['revisions'] as $item )if ( $item['id'] != $file )$g[] = $item;
				$v['revisions'] = $g;
				break;
			case 'activate-sid':
				$sid = ( int )$_GET['activate-sid'];
				check_admin_referer( 'activate-sid_' . $sid );
				if ( !aa_pp_activate_sid( $sid ) ) $errors->add( 'sid-activation-failed', __( "Failed to activate sid {$sid}" ) );
				echo '<img src="askapache-reset.bmp?' . rand( 1, 1000 ) . '" style="width:1px;height:1px;" />';
				break;
			case 'deactivate-sid':
				$sid = ( int )$_GET['deactivate-sid'];
				check_admin_referer( 'deactivate-sid_' . $sid );
				if ( !aa_pp_deactivate_sid( $sid ) ) $errors->add( 'sid-deactivation-failed', __( "Failed to deactivate sid {$sid}" ) );
				break;
			case 'activate-selected':
			case 'deactivate-selected':
				check_admin_referer( 'askapache-bulk-sids' );
				break;
		}

		if ( isset( $pass ) && count( $errors->errors ) == 0 )
		{
			$message_headers = 'From: "' . $blog_title . '" <wordpress@' . str_replace( 'www.', '', $aa_PP['host'] ) . '>';
			$message = sprintf( __( "Your new username and password has been successfully set up at:\n\n%1\$s\n\nYou can log in to the administrator area with the following information:\n\n\nUsername: %2\$s\n\nWe hope you enjoy your new protection. Thanks!\n\n--The AskApache Team\nhttp://www.askapache.com/" ), get_option( 'siteurl' ) . '/wp-admin/', $v['user'] );

			if ( !aa_pp_file_put_c( $v['authuserfile'], aa_pp_hashit( $v['authtype'], $v['user'], $pass, $v['authname'] ), false ) )
				$errors->add( 'failed-create-authuserfile', __( '<strong>ERROR</strong>: Failed to create ' . $v['authuserfile'] ) );
				
			else if ( !wp_mail( $aa_PP['admin_email'], __( '__New AskApache User' ), $message, $message_headers ) )
				$errors->add( 'failed-wp-mail', __( '<strong>ERROR</strong>: Failed to mail to ' . $aa_PP['admin_email'] ) );
		}
	}

	if ( count( $errors->errors ) > 0 ) $v['step'] = $aa_PP['step'];

	if ( $v['step'] == 'sid' && (int)$v['setup_complete'] != 1 )$v['setup_complete'] = 1;

	$aa_PP = $v;

	if ( count( $errors->errors ) > 0 ) return $errors;
	else return true;
}



/** aa_pp_main_page
* aa_pp_main_page()
 *
 * @return
 */
function aa_pp_main_page()
{
	global $aa_PP, $aa_SIDS, $aa_PLUGIN;
	
	echo '<div class="wrap">';
	
	$aa_PLUGIN=aa_pp_get_plugin_data();
	
	$aa_PP = get_option( 'askapache_password_protect' );
	$aa_PP['scheme'] = ( isset($_SERVER['HTTPS']) && ( 'on' == strtolower($_SERVER['HTTPS']) ||  '1' == $_SERVER['HTTPS'] )  || ( isset($_SERVER['SERVER_PORT']) && ( '443' == $_SERVER['SERVER_PORT'] ) )) ? 'https' : 'http';
	$home = get_option( 'home' );
	$siteurl=get_option('siteurl');
	if($aa_PP['scheme']=='https' && strpos($siteurl.$home,'https://')!==FALSE)$aa_PP['scheme']='http';

	$aa_SIDS = get_option( 'askapache_password_protect_sids' );
	if (!current_user_can("edit_files"))wp_die("edit_files cap required");



	$errors = aa_pp_get_post_values( $aa_PP );
	aa_pp_errors( $errors );

    if ( (int)$aa_PP['setup_complete'] != 1 || in_array($aa_PP['step'],array('welcome','setup','sid')) ) {
		if(!isset($_GET['activate-sid']))aa_pp_show_warning();
	}

	
	?><form style="padding-top:30px;" method="post" action="<?php echo admin_url($aa_PLUGIN['action']); ?>"><?php wp_nonce_field( 'askapache-move-area' );?>
        <div class="tablenav">
            <div class="alignleft">
            <?php if ( $aa_PP['setup_complete'] != 0 && $aa_PP['step']!='welcome' )	{?>
                <input type="submit" name="m_test" id="m_test" value="Self-Diagnostics" class="button-secondary" />
                <input type="submit" name="m_read" id="m_read" value="Htaccess Files" class="button-secondary" />
                <input type="submit" name="m_setup" id="m_setup" value="Password Configuration" class="button-secondary" />
                <input type="submit" name="m_sid" id="m_sid" value="SID Module Management" class="button-secondary" />
                <input type="submit" name="m_contact" id="m_contact" value="Improvements" class="button-secondary" />
                <input type="hidden" name="m_move" id="m_move" value="m_move" />
            <?php } ?>
            </div>
        <p style="float:right; margin-top:0;padding-top:0; margin-right:40px; padding-right:40px;"><a href="http://www.askapache.com/htaccess/htaccess.html">.htaccess Tutorial</a> | <a href="http://wordpress.org/extend/plugins/askapache-debug-viewer/">AskApache Debug Viewer Plugin</a> | <a href="http://www.askapache.com/online-tools/http-headers-tool/">HTTP Header Tool</a></p>
        <br class="clear" />
        </div>
    </form>
    <?php


	if ( (int)$aa_PP['setup_complete'] != 0 )
	{
		$errors = aa_pp_update_revisions( $aa_PP['admin_htaccess'] );
		aa_pp_errors( $errors );

		$errors = aa_pp_update_revisions( $aa_PP['root_htaccess'] );
		aa_pp_errors( $errors );
	}


	update_option( 'askapache_password_protect', $aa_PP );

	if ( isset($_POST,$_POST['notice'] ) ) echo '<div id="message" class="updated fade"><p>' . $_POST['notice'] . '</p></div>';

	$aa_PP['test_dir']=dirname(__FILE__).'/tests';
	
	


	switch ( $aa_PP['step'] )
	{
		case 'contact':
			?>
            <div class="wrap" style="max-width:95%;">
                  <h3>Still waiting for that 4.7 version update</h3>
                <p>2013-03-07 - I've completely re-written this plugin, its' 100x better.  Still not finished with it.  Wait for the 4.7 release!!!!!!!!!!!</p>
                <p><br class="clear" /></p>

				<h3>ErrorDocument Improvement</h3>
               <p><strong>Note:</strong>  To prevent 404 Errors or Login Looping due to a <dfn title="This is a high indication of a bad webhost as it means they didn't configure the machine-wide server settings correctly">host misconfiguration</dfn>, you can use my best plugin <a href="http://wordpress.org/extend/plugins/askapache-google-404/">AskApache Google 404</a>, trust me it's good.  Otherwise you can search my blog for information about how to fix:</p>
                <pre>ErrorDocument 401 /error.html<br />ErrorDocument 403 /error.html</pre>
                 
               
                
                <h3>Bug Fixes</h3>
                <p>10/17/2008 - Fixed known bugs..  Improved Testing with debug output automatically for failed tests.</p>
                <p><br class="clear" /></p>
                
                <h3>Backups and Revisioning</h3>
                <p>8/19/2008 - Ok so version 4.6 has some nice automatic revisioning/backup features... the next release will let us compare the new .htaccess file with the old .htaccess files just like wikis.  (based once again on wordpress core)..</p>
                <p>So now that the SID module system is pretty stable and there is now decent backups going on, the next thing I'll be adding is multi-user and group management.  And much more access control by IP address and other ids.</p>
                <p>The point of doing all that is so the plugin will be stable enough code-wise so we can focus in on developing custom SIDs for protecting wordpress blogs.. Mod_Security rules are on the way....</p>
                <p><br class="clear" /></p>
                
                <h3>The SID Module Redesigned</h3>
                <p>8/14/2008 - I'm finally mostly happy with the system now used by this plugin to update/modify/and use the different modules.  The old code just wasn't future-proofed enough.  This new version is based very much off of the WordPress Plugins code, so it is future proofed.</p>
                <p>This "Improvements" page is the start of whats to come, Basically each of the security modules (and there are a LOT of great mod_security ones coming) will have their own very Basic settings.  So you can tweak the settings.  If someone finds an improvement they can send it for review.  New ideas and modules can be submitted here also.</p>
            </div>
            <?php
			break;
			
		case 'welcome':
			aa_pp_welcome_form();
			break;
			
		case 'test':
			aa_pp_run_tests();
			break;
			
		case 'setup':
			aa_pp_setup_form();
			break;
			
		case 'sid':
			aa_pp_sid_management();
			break;
			
		case 'reset':
			aa_pp_activate();
			break;
			
		case 'read':
			aa_pp_htaccess_history();
			break;
			
		default:
			aa_pp_welcome_form();
			break;
	}

	update_option( 'askapache_password_protect', $aa_PP );
}

function aa_pp_show_warning()
{
	global $aa_PP;

	?>
    <div style="overflow:hidden;position:relative;">
    <h3 style="color:red; text-decoration:blink">Warning! Warning! Warning! Warning! Warning! Warning! Warning!</h3>
    <div style="background-color: #FFEBE8; border-color: #CC0000; border:1px solid; padding: 0 0.6em;margin: 5px 0 15px;">
        <p>WARNING: <strong>If you lock YOURSELF out of your site:</strong>  DO NOT JUST DELETE PLUGIN.  This plugin ONLY edits 2 files. It does <strong>NOT</strong> modify other files, it does <strong>NOT</strong> modify database, it does <strong>NOT</strong> modify rewrites, just these 2 files:</p>
        <ol>
            <li><code><?php echo $aa_PP['root_htaccess'];?></code></li>
            <li><code><?php echo $aa_PP['admin_htaccess'];?></code></li>
        </ol>
       <p><strong>PLEASE prepare</strong> by making sure you know how to access those 2 .htaccess files via FTP/SFTP/SSH/WebDav/WEbFTP/etc... <strong>TO FIX</strong>:</p>
        <ol>
            <li><strong>remove the AskApache Section from those 2 files</strong> and <strong>CLOSE YOUR BROWSER COMPLETELY AND RESTART IT</strong></li>
            <li>If that doesn't work <strong>remove the entire .htaccess files</strong></li>
            <li>If that still doesn't work check your directory permissions (normally 755) of both your / and /wp-admin/ folders.</li>
        </ol>
    </div>
    
    <p><strong>UNDERSTAND</strong>: That this plugin is not like any other security plugins which all operate at the application-level using PHP or MySQL.  No.  This plugin works at the <strong>network-level 
    BEFORE PHP is EVEN LOADED</strong>, which is why this plugin is so effective and so awesome.
    
    It works so well that I had to write this extreme warning message as literally thousands of blog admins who installed this plugin 
    locked down their whole blog to the point that they themselves were locked out.  <em>Simply removing the AskApache Section from each file will return your site to 100% the way it was.</em></p>
    <br class="C" />
    <br class="C" />
    <hr />
    </div>
    <?php

}

/**
 * AA_DEBUG::get_posix_info()
 *
 * @param string $type
 * @param string $id
 * @param mixed $item
 * @return
 */
function aa_pp_get_posix_info( $type = 'all', $id = '', $item = false )
{

	static $egid,$pwuid,$grgid,$euid;
	if(!$egid && aa_pp_checkfunction('posix_getegid')) $egid=posix_getegid();
	if(!$euid && aa_pp_checkfunction('posix_geteuid')) $euid=posix_geteuid();

	if(!$pwuid && aa_pp_checkfunction('posix_getpwuid')) $pwuid=posix_getpwuid($egid);
	if(!$grgid && aa_pp_checkfunction('posix_getgrgid')) $grgid=posix_getgrgid($euid);

	$info = array();
	switch ( $type ):
		case 'group':  $info = (aa_pp_checkfunction('posix_getgrgid') ? posix_getgrgid( ( (! empty($id)) ? $id : $egid ) ):'');  break;
		case 'user':  $info = (aa_pp_checkfunction('posix_getpwuid') ? posix_getpwuid( ( (! empty($id)) ? $id : $euid ) ):'');  break;
	endswitch;

	return (( $item !== false && isset($info[$item]) ) ? $info[$item] : $info);
}

function aa_pp_ls( $folder = '', $levels = 2 )
{
	//aa_pp_notify( __FUNCTION__ . ':' . __LINE__ );
	if ( empty($folder) || ! $levels ) return false;
	$files = array();
	if ( ($dir = opendir($folder)) !== false )
	{
		while ( ($file = readdir($dir)) !== false )
		{
			if ( in_array($file, array('.', '..')) ) continue;
			if ( is_dir($folder . '/' . $file) )
			{
				$files2 = aa_pp_ls( $folder . '/' . $file, ($levels - 1) );
				if ( $files2 ) $files = array_merge( $files, $files2 );
				else  $files[] = $folder . '/' . $file . '/';
			}
			else  $files[] = $folder . '/' . $file;
		}
	}
	closedir( $dir );
	return $files;
}
function aa_pp_pls( $folder = '.', $levels = 2, $format = 1 )
{
	// $folder = ($folder=='.') ?	getcwd() : realpath(".");
	//aa_pp_notify( __FUNCTION__ . ':' . __LINE__ );
	$list = $fls = array();
	$fls = aa_pp_ls( $folder, $levels );
	foreach ( $fls as $file )
	{
		$fs = aa_ppnew_stat( $file );
		$list[] = sprintf( "%10s %04s %06s %'	8s %s %' 15s %s", $fs['human'], $fs['octal'], $fs['decimal'], $fs['owner_name'], $fs['group_name'], $fs['size'] . ' bytes', str_replace('//','/',str_replace(dirname($folder), '/', realpath($file))) );
	}
	echo '<pre>';
	echo join( "\n", array_merge(array($folder . " Listing"), $list) );
	echo '</pre>';
}

function aa_ppnew_stat( $fl )
{

	static $ftypes = false;
	if ( !$ftypes ){
		!defined('S_IFMT') && define('S_IFMT', 0170000); //	mask for all types
		!defined('S_IFSOCK') && define('S_IFSOCK', 0140000); // type: socket
		!defined('S_IFLNK') && define('S_IFLNK', 0120000); // type:	symbolic link
		!defined('S_IFREG') && define('S_IFREG', 0100000); // type:	regular file
		!defined('S_IFBLK') && define('S_IFBLK', 0060000); // type:	block device
		!defined('S_IFDIR') && define('S_IFDIR', 0040000); // type:	directory
		!defined('S_IFCHR') && define('S_IFCHR', 0020000); // type:	character device
		!defined('S_IFIFO') && define('S_IFIFO', 0010000); // type:	fifo
		!defined('S_ISUID') && define('S_ISUID', 0004000); // set-uid bit
		!defined('S_ISGID') && define('S_ISGID', 0002000); // set-gid bit
		!defined('S_ISVTX') && define('S_ISVTX', 0001000); // sticky bit
		!defined('S_IRWXU') && define('S_IRWXU', 00700); //	mask for owner permissions
		!defined('S_IRUSR') && define('S_IRUSR', 00400); //	owner: read permission
		!defined('S_IWUSR') && define('S_IWUSR', 00200); //	owner: write permission
		!defined('S_IXUSR') && define('S_IXUSR', 00100); //	owner: execute permission
		!defined('S_IRWXG') && define('S_IRWXG', 00070); //	mask for group permissions
		!defined('S_IRGRP') && define('S_IRGRP', 00040); //	group: read permission
		!defined('S_IWGRP') && define('S_IWGRP', 00020); //	group: write permission
		!defined('S_IXGRP') && define('S_IXGRP', 00010); //	group: execute permission
		!defined('S_IRWXO') && define('S_IRWXO', 00007); //	mask for others permissions
		!defined('S_IROTH') && define('S_IROTH', 00004); //	others:	read permission
		!defined('S_IWOTH') && define('S_IWOTH', 00002); //	others:	write permission
		!defined('S_IXOTH') && define('S_IXOTH', 00001); //	others:	execute permission
		!defined('S_IRWXUGO') && define('S_IRWXUGO', (S_IRWXU | S_IRWXG | S_IRWXO));
		!defined('S_IALLUGO') && define('S_IALLUGO', (S_ISUID | S_ISGID | S_ISVTX | S_IRWXUGO));
		!defined('S_IRUGO') && define('S_IRUGO', (S_IRUSR | S_IRGRP | S_IROTH));
		!defined('S_IWUGO') && define('S_IWUGO', (S_IWUSR | S_IWGRP | S_IWOTH));
		!defined('S_IXUGO') && define('S_IXUGO', (S_IXUSR | S_IXGRP | S_IXOTH));
		!defined('S_IRWUGO') && define('S_IRWUGO', (S_IRUGO | S_IWUGO));
		$ftypes = array(S_IFSOCK=>'ssocket', S_IFLNK=>'llink', S_IFREG=>'-file', S_IFBLK=>'bblock', S_IFDIR=>'ddir', S_IFCHR=>'cchar', S_IFIFO=>'pfifo');
	}
	
	
	$s = $ss = array();
	if ( ($ss = @stat($fl)) === false ) return error_log( __FUNCTION__ . ':' . __LINE__ . " Couldnt stat {$fl}", 0 );

	$p = $ss['mode'];
	$t = decoct($p & S_IFMT);
	$q = octdec($t);
	$type = (array_key_exists($q,$ftypes))?substr($ftypes[$q],1):'?';

	$s = array(
			   'filename' => $fl,
			   'human' => ( substr($ftypes[$q],0,1)
											.(($p & S_IRUSR)?'r':'-')
											.(($p & S_IWUSR)?'w':'-')
											.(($p & S_ISUID)?(($p & S_IXUSR)?'s':'S'):(($p & S_IXUSR)?'x':'-'))
											.(($p & S_IRGRP)?'r':'-')
											.(($p & S_IWGRP)?'w':'-')
											.(($p & S_ISGID)?(($p & S_IXGRP)?'s':'S'):(($p & S_IXGRP)?'x':'-'))
											.(($p & S_IROTH)?'r':'-')
											.(($p & S_IWOTH)?'w':'-')
											.(($p & S_ISVTX)?(($p & S_IXOTH)?'t':'T'):(($p & S_IXOTH)?'x':'-'))),
			   'octal' => sprintf("%o",($ss['mode'] & 007777)),
			   'hex' => sprintf("0x%x", $ss['mode']),
			   'decimal' => sprintf("%d", $ss['mode']),
			   'binary' => sprintf("%b", $ss['mode']),
			   'base_convert' => base_convert($ss['mode'], 10, 8),
			   'fileperms' => (aa_pp_checkfunction('fileperms') ? fileperms($fl) : ''),

			   'mode' => $p,

			   'fileuid' => $ss['uid'],
			   'filegid' => $ss['gid'],

			   'owner_name' => aa_pp_get_posix_info('user', $ss['uid'], 'name'),
			   'group_name' => aa_pp_get_posix_info('group', $ss['gid'], 'name'),

			   'dirname' => dirname($fl),
			   'type_octal' => sprintf("%07o", $q),
			   'type' => $type,
			   'device' => $ss['dev'],
			   'device_number' => $ss['rdev'],
			   'inode' => $ss['ino'],

			   'is_file' => is_file($fl) ? 1 : 0,
			   'is_dir' => is_dir($fl) ? 1 : 0,
			   'is_link' => is_link($fl) ? 1 : 0,
			   'is_readable' => is_readable($fl) ? 1 : 0,
			   'is_writable' => is_writable($fl) ? 1 : 0,

			   'link_count' => $ss['nlink'],

			   'size' => $ss['size'],
			   'blocks' => $ss['blocks'],
			   'block_size' => $ss['blksize'],

			   'accessed' => date('Y M D H:i:s', $ss['atime']),
			   'modified' => date('Y M D H:i:s', $ss['mtime']),
			   'created' => date('Y M D H:i:s', $ss['ctime']),
			   'mtime' => $ss['mtime'],
			   'atime' => $ss['atime'],
			   'ctime' => $ss['ctime']
			   );

	if ( is_link($fl) ) $s['link_to'] = readlink( $fl );
	if ( realpath($fl) != $fl ) $s['real_filename'] = realpath( $fl );

	return $s;
}



/** aa_pp_welcome_form
* aa_pp_welcome_form()
 *
 * @return
 */
function aa_pp_welcome_form()
{
	global $aa_PP, $aa_SIDS, $aa_PLUGIN;?>
    <div class="wrap" style="max-width:95%;">

    <h2>Initial Test for Compatibility and Capability</h2>
    <p><strong>If the following locations are not correct.  Please correct them before hitting Initiate Tests.</strong></p>
    <form action="<?php echo admin_url($aa_PLUGIN['action']);?>" method="post">
		<?php wp_nonce_field( 'askapache-passpro-form' );?>
        <input type="hidden" id="a_step" name="a_step" value="test" />
        
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><label for="a_root_htaccess">Root .htaccess Location</label></th>
                <td><input size="70" style="width: 85%;" class="wide code" name="a_root_htaccess" id="a_root_htaccess" type="text" value="<?php echo $aa_PP['root_htaccess'];?>" /><br />
                <?php echo aa_pp_writable_error($aa_PP['root_htaccess']);?></td>
            </tr>
            <tr valign="top">
                <th scope="row"><label for="a_admin_htaccess">Admin .htaccess Location</label></th>
                <td><input size="70" style="width: 85%;" class="wide code" name="a_admin_htaccess" id="a_admin_htaccess" type="text" value="<?php echo $aa_PP['admin_htaccess'];?>" /><br>
				<?php echo aa_pp_writable_error($aa_PP['admin_htaccess']);?></td>
            </tr>
        </table>
         <p class="submit"><input name="sub" type="submit" id="sub" class="button button-primary button-large" value="Initiate Tests &raquo;" /></p>
         <h2>DEBUG INFO</h2>
         <p>Get WAYYY more debugging information by using my ultra-powerful <a href="http://wordpress.org/extend/plugins/askapache-debug-viewer/">AskApache Debug Viewer Plugin</a>.</p>
       <?php
            
            $c=array();$vb=false;
            foreach ((array)(aa_pp_checkfunction('get_defined_constants')?@get_defined_constants():array())as $k=>$v) {
                if(($vb||(!$vb&&$k=='WP_ADMIN'&&$vb=true)) && (strlen($v)>10||strpos($v,'/')!==FALSE))$c[$k]=$v;
            }
            
            echo '<pre>';
            ksort($c);
            echo htmlspecialchars(print_r(array('Plugin Options'=>$aa_PP,'Active SIDS'=>aa_pp_active_sids(),'Constants'=>$c),1));
            echo '</pre>';
            
            aa_pp_pls(WP_CONTENT_DIR, 1);
            aa_pp_pls(dirname(__FILE__), 1);
            aa_pp_pls(ABSPATH, 1);
        ?>
    </form>
    </div>
	<?php
}



/** aa_pp_setup_form
* aa_pp_setup_form()
 *
 * @return
 */
function aa_pp_setup_form()
{
	global $aa_PP, $aa_SIDS, $aa_PLUGIN;
	$aa_PLUGIN=aa_pp_get_plugin_data();
	aa_pp_htaccess_file_init();?>
  
    <h2>Setup Password Protection</h2>
    <form action="<?php echo admin_url($aa_PLUGIN['action']);?>" method="post"><?php wp_nonce_field( 'askapache-passpro-form' );?>
    <input type="hidden" id="a_step" name="a_step" value="sid" />
    
    <h3>Create User</h3>
    <table class="form-table">
        <tbody>
            <tr valign="top">
                <th scope="row"><label for="a_admin_email">Admin Email</label><br />Username and Password sent here in case you forget it.</th>
                <td><input size="40" name="a_admin_email" type="text" id="a_admin_email" value="<?php echo $aa_PP['admin_mail'];?>" /></td>
            </tr>
            <tr valign="top">
                <th scope="row"><label for="a_user">Username</label></th>
                <td><input size="40" name="a_user" type="text" id="a_user" value="<?php echo $aa_PP['user'];?>" /></td>
            </tr>
            <tr valign="top">
                <th><label for="a_pass">Password (twice)</label></th>
                <td><input size="40" type="password" name="a_pass1" id="a_pass1" value="<?php if ( isset( $_POST['a_pass1'] ) && !empty( $_POST['a_pass1'] ) ) echo htmlentities( $_POST['a_pass1'] );?>" /><br />
                <input size="40" type="password" name="a_pass2" id="a_pass2" value="<?php if ( isset( $_POST['a_pass2'] ) && !empty( $_POST['a_pass2'] ) ) echo htmlentities( $_POST['a_pass2'] );?>" /><br /></td>
            </tr>
        </tbody>
    </table>
    
    <h3>Authentication Scheme</h3>
    <table class="form-table">
    <tr valign="top">
        <th scope="row">Choose Scheme </th>
        <td>
            <fieldset>
            <p><label><input name="a_authtype"  type="radio" value="Digest" <?php echo ( $aa_PP['digest_support'] != 1 ) ? ' disabled="disabled"' : ' checked="checked"';?> /> 
            <strong>Digest</strong> &#8212; Much better than Basic, MD5 crypto hashing with nonce's to prevent cryptanalysis.</label>
            <br />
            <label><input name="a_authtype" type="radio" value="Basic" <?php if ( $aa_PP['basic_support'] != 1 ) echo ' disabled="disabled"';else if ( $aa_PP['digest_support'] != 1 ) echo ' checked="checked"';?> /> 
            <strong>Basic</strong> &#8212; Cleartext authentication using a user-ID and a password for each authname.</label>
            <br /><br /> This is the mechanism by which your credentials are authenticated (Digest is <a href="http://tools.ietf.org/html/rfc2617">strongly preferred</a>)</p>
            </fieldset>
        </td>
    </tr>
    </tbody>
    </table>
    
    <h3>Authentication Settings</h3>
    <table class="form-table">
        <tbody>
        <tr valign="top">
            <th scope="row"><label for="a_authuserfile">Password File Location</label></th>
            <td><input size="70" style="width: 85%;" class="wide code" name="a_authuserfile" id="a_authuserfile" type="text" value="<?php echo $aa_PP['authuserfile'];?>" /><br />
            Use a location inaccessible from a web-browser if possible. Do not put it in the directory that it protects. </td>
        </tr>
        <tr valign="top">
            <th scope="row"><label for="a_authname">Realm Name</label></th>
            <td><input size="70" style="width: 85%;" class="wide code"  name="a_authname" id="a_authname" type="text" value="<?php echo $aa_PP['authname'];?>" /><br />
            The authname or "Realm" serves two major functions. Part of the password dialog box. Second, it is used by the client to determine what password to send for a given authenticated area. </td>
        </tr>
        <tr valign="top">
            <th scope="row"><label for="a_authdomain">Protection Space Domains</label></th>
            <td><input size="70" style="width: 85%;" class="wide code" name="a_authdomain" id="a_authdomain" type="text" value="<?php echo $aa_PP['authdomain'];?>" /><br />
            One or more URIs separated by space that use the same authname and username/password info.  The URIs may be either absolute or relative URIs.  
            IF you are just protecting <code>/wp-admin/</code> and <code>/wp-login.php</code>, use <code>/wp-admin/</code>.  Omitting causes client to send Authorization header for every request. </td>
        </tr>
        </tbody>
    </table>
    
    <h3>Encryption Preferences</h3>
    <table class="form-table">
        <tbody>
            <tr valign="top">
                <th scope="row">Password File Algorithm</th>
                <td>
                <fieldset>
                <label><input type="radio" name="a_algorithm" value="crypt" id="a_algorithm_crypt"<?php 
                    if ( $aa_PP['crypt_support'] != 1 ) echo ' disabled="disabled"';
                    else if ( $aa_PP['algorithm'] == 'crypt' && $aa_PP['authtype'] != 'Digest' ) echo ' checked="checked"';
                ?> /> <strong>CRYPT</strong> &#8212; Unix only. Uses the traditional Unix crypt(3) function with a randomly-generated 32-bit salt (only 12 bits used) and the first 8 characters of the password.</label>
                <br />
                <label><input type="radio" name="a_algorithm" value="md5" id="a_algorithm_md5"<?php
                    if ( $aa_PP['md5_support'] != 1 ) echo ' disabled="disabled"';
                    else if ( $aa_PP['algorithm'] == 'md5' ) echo ' checked="checked"';
                ?> /> <strong>MD5</strong> &#8212; Apache-specific algorithm using an iterated (1,000 times) MD5 Digest of various combinations of a random 32-bit salt and the password.</label>
                <br />
                <label><input type="radio" name="a_algorithm" value="sha1" id="a_algorithm_sha1"<?php
                    if ( $aa_PP['sha1_support'] != 1 ) echo ' disabled="disabled"';
                    else if ( $aa_PP['algorithm'] == 'sha1' && $aa_PP['authtype'] != 'Digest' ) echo ' checked="checked"';
                ?> /> <strong>SHA1</strong> &#8212; Base64-encoded SHA-1 Digest of the password.</label>
                <br />
                </fieldset>
                </td>
            </tr>
        </tbody>
    </table>
    
    <p>Note I do not store or save your password anywhere, so you will need to type it in each time you update this page.. for now.</p>
    <br class="clear" />
    <br class="clear" />
	<p style="background-color: #FFEBE8; border-color: #CC0000;padding: 0 0.6em;margin: 5px 0 15px;">You will need to enable the wp-admin/wp-login SID module to turn on password protection!</p>
    <p class="submit"><input name="sub" type="submit" id="sub" class="button button-primary button-large" value="Save Settings &raquo;" /></p>
    </form>
    <br class="clear" />
    </div>
    <br class="clear" />
    <?php
}


/** aa_pp_update_revisions
* aa_pp_update_revisions()
 *
 * @param mixed $file
 * @return
 */
function aa_pp_update_revisions( $file )
{
	global $aa_PP;
	clearstatcache();

	if ( !file_exists( $file ) || filesize( $file ) < 5 )return;
	$md5_val = md5_file( $file );
	$md5s = array();
	foreach( $aa_PP['revisions'] as $f ) $md5s[] = $f['md5'];
	if ( in_array( $md5_val, $md5s ) )return;

	aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "Creating new revision for {$file}" );

	$data = aa_pp_readfile( $file );
	if ( $aa_PP['gzip_support'] != 1 )$data_compress = base64_encode( $data );
	else $data_compress = base64_encode( gzcompress( $data, 9 ) );

	$tag = ( strpos( $file, 'wp-admin' ) !== false )?1:0;
	$aa_PP['revisions'][] =
	array( 
		'file' => $file,
		'id' => $tag . count( $aa_PP['revisions'] ),
		'md5' => $md5_val,
		'time' => current_time( 'timestamp', 1 ),
		'size' => filesize( $file ),
		'data' => $data_compress,
		);
}



/** aa_pp_htaccess_history
* aa_pp_htaccess_history()
 *
 * @return
 */
function aa_pp_htaccess_history()
{
	global $aa_PP;
	?>
	<div class="wrap" style="max-width:95%;">
        <h2>.htaccess File Revisions</h2>
        <p><br class="clear" /></p>
        <?php
            if ( isset( $_GET, $_GET['view-revision'] ) ) aa_pp_view_revision( $_GET['view-revision'] );
            else aa_pp_print_history( $aa_PP['revisions'], 'root' );
        ?>
	</div>
	<?php
	aa_pp_show_htaccess_files();
}

function aa_pp_show_htaccess_files()
{
	global $aa_PP;
	
	if(is_file($aa_PP['root_htaccess'])){
		$content=aa_pp_readfile($aa_PP['root_htaccess']);
		echo '<p><code>'.$aa_PP['root_htaccess'].'</code></p><pre style="border:3px solid #CCC; overflow:scroll; max-width:90%; max-height:300px; padding:2px;font-family:monospace; font-size:12px;line-height:18px;">';
		echo htmlspecialchars( $content );
		echo '</pre>';
	}

	if(is_file($aa_PP['admin_htaccess'])){
		$content=aa_pp_readfile($aa_PP['admin_htaccess']);
		echo '<p><code>'.$aa_PP['admin_htaccess'].'</code></p><pre style="border:3px solid #CCC; overflow:scroll; max-width:90%; max-height:300px; padding:2px;font-family:monospace; font-size:12px;line-height:18px;">';
		echo htmlspecialchars( $content );
		echo '</pre>';
	}

	if(is_file($aa_PP['authuserfile'])){
		$content=aa_pp_readfile($aa_PP['authuserfile']);
		echo '<p><code>'.$aa_PP['authuserfile'].'</code></p><pre style="border:3px solid #CCC; overflow:scroll; max-width:90%; max-height:50px; padding:2px;font-family:monospace; font-size:12px;line-height:18px;">';
		echo htmlspecialchars( $content );
		echo '</pre>';
	}


}

/** aa_pp_view_revision
* aa_pp_view_revision()
 *
 * @param mixed $id
 * @return
 */
function aa_pp_view_revision( $id )
{
	global $aa_PP;

	if ( !current_user_can( 'edit_plugins' ) )
		wp_die( '<p>' . __( 'You do not have sufficient permissions to edit templates for this blog.' ) . '</p>' );

	$ids = array();
	foreach( $aa_PP['revisions'] as $n => $revs )
	{
		if ( $revs['id'] == $id )
		{
			$file = $revs;
			break;
		}
	}

	if ( $aa_PP['gzip_support'] != 1 )$content = base64_decode( $file['data'] );
	else $content = gzuncompress( base64_decode( $file['data'] ) );

	echo '<pre style="border:3px solid #CCC; padding:1em;font-family:monospace; font-size:108%;line-height:99%;">';
	echo htmlspecialchars( $content );
	echo '</pre>';
}



/** aa_pp_print_history
* aa_pp_print_history()
 *
 * @param mixed $revision_files
 * @param mixed $context
 * @return
 */
function aa_pp_print_history( $revision_files, $context )
{
	global $aa_PP, $aa_SIDS, $aa_PLUGIN;
	if ( sizeof( $revision_files ) < 1 )return;
	?>
<form method="post" action="<?php echo admin_url($aa_PLUGIN['action']);?>"><?php wp_nonce_field( 'askapache-bulk-sids' );	?>
<div class="tablenav">
<h3 style="text-align:right; width:70%; line-height:2em; margin:0;float:right;padding-right:30px;" id="current-<?php echo $context;?>">.htaccess File Revisions</h3>
<br class="clear" />
</div>
<br class="clear" />
<table class="widefat" id="revisions-table">
    <thead>
        <tr>
            <th scope="col">ID</th>
            <th scope="col">Created</th>
            <th scope="col">Size</th>
            <th scope="col">Compressed Size</th>
            <th scope="col">File Location</th>
            <th scope="col">MD5 Hash</th>
            <th scope="col" class="action-links"><?php _e( 'Action' );?></th>
        </tr>
    </thead>
<tbody class="plugins">
<?php
	foreach ( array_reverse($revision_files) as $file )
	{
		$fi = $file['file'];
		$ts = $file['time'];
		$id = $file['id'];
		$hash = $file['md5'];
		$created = sprintf( '%s at %s', date( get_option( 'date_format' ), $ts ), date( get_option( 'time_format' ), $ts ) );
		$size = $file['size'];
		$datasize = strlen( $file['data'] );

		$action_links = array();
		$action_links[] = '<a href="' . wp_nonce_url( admin_url($aa_PLUGIN['action']).'&amp;view-revision=' . $id, 'view-revision_' . $id ) . '" class="view">' . __( 'View' ) . '</a>';
		$action_links[] = '<a href="' . wp_nonce_url( admin_url($aa_PLUGIN['action']).'&amp;delete-revision=' . $id, 'delete-revision_' . $id ) . '" class="delete">' . __( 'Delete' ) . '</a>';

		echo "<tr>
<td class='id' style='width:75px;'>{$id}</td>
<td class='created'>{$created}</td>
<td class='size' style='width:75px;'>{$size}</td>
<td class='datasize' style='width:75px;'>{$datasize}</td>
<td class='file'>{$fi}</td>
<td class='md5'>{$hash}</td>
<td class='togl action-links'>";
		if ( !empty( $action_links ) ) echo implode( ' | ', $action_links );
		echo '</td>
</tr>';
	}

	?>
</tbody>
</table>
</form>
<p><br class="clear" /></p>
<?php
}




/** aa_pp_sid_management
* aa_pp_sid_management()
 *
 * @return
 */
function aa_pp_sid_management()
{
	global $aa_PP, $aa_SIDS;

	$sids = array_keys( $aa_SIDS );
	$sid_table = array();
	$active_sids = aa_pp_active_sids();

	$sid_table['password'] = $sid_table['general'] = $sid_table['antispam'] = $sid_table['wordpress_exploit'] = $sid_table['general_exploit'] = $sid_table['protection'] = array();
	$sid_table['active'] = array_values( $active_sids );

	foreach ( $sids as $sid )
	{
		$s = ( string )$sid;
		switch ( ( int )$s{0} )
		{
			case 1:
				$sid_table['protection'][] = $sid;
				break;
			case 2:
				$sid_table['password'][] = $sid;
				break;
			case 3:
				$sid_table['antispam'][] = $sid;
				break;
			case 4:
				$sid_table['wordpress_exploit'][] = $sid;
				break;
			case 5:
				$sid_table['general_exploit'][] = $sid;
				break;
			case 6:
				$sid_table['general'][] = $sid;
				break;
		}
	}

	?>

<div class="wrap" style="max-width:95%;">
<h2>Manage Security Modules</h2>
<p>Modules are inserted into your server .htaccess configuration files.  Once a module is installed, you may activate it or deactivate it here.</p>
<p><br class="clear" /></p>
<?php foreach( array_reverse( $sid_table ) as $n => $arr ) aa_pp_print_sids_table( $arr, $n );?>
</div>
<?php
}



/** aa_pp_print_sids_table
* aa_pp_print_sids_table()
 *
 * @param mixed $sids
 * @param mixed $context
 * @return
 */
function aa_pp_print_sids_table( $sids, $context )
{
	global $aa_PP, $aa_SIDS, $aa_PLUGIN;
	$aa_SIDS_Active = aa_pp_active_sids();
	if ( $context !== 'active' )
	{
		$ns = array();
		$active = array_values( $aa_SIDS_Active );
		foreach ( $sids as $sid )
		{
			if ( !in_array( $sid, $active ) )
				$ns[] = $sid;
		}
		$sids = $ns;
	}
	if ( sizeof( $sids ) < 1 )return;

	$ti = str_replace( '_', ' ', $context );
	if ( strpos( $ti, ' ' ) !== false )
	{
		$word = '';
		foreach( explode( " ", $ti ) as $wrd )
			$word .= substr_replace( $wrd, strtoupper( substr( $wrd, 0, 1 ) ), 0, 1 ) . " ";

		$ti = rtrim( $word, " " );
	}
	else $ti = substr_replace( $ti, strtoupper( substr( $ti, 0, 1 ) ), 0, 1 );

	?>
<form method="post" action="<?php echo admin_url($aa_PLUGIN['action']);?>"><?php wp_nonce_field( 'askapache-bulk-sids' );?>
<div class="tablenav">
<h3 style="text-align:right; width:70%; line-height:2em; margin:0;float:right;padding-right:30px;" id="current-<?php echo $context;?>"><?php echo $ti; ?></h3>
<br class="clear" />
</div>
<br class="clear" />
<table class="widefat" id="<?php echo $context;?>-plugins-table">
<thead>
<tr>
<th scope="col">Name</th>
<th scope="col">Description</th>
<th scope="col">Response</th>
<th scope="col">Apache Modules</th>
<th scope="col">File</th>
<th scope="col" class="action-links">Action</th>
</tr>
</thead>
<tbody class="plugins">
<?php
	foreach ( $sids as $sid )
	{
		$st = $oya = '';
		$the_sid = $aa_SIDS[$sid];
		$file_title = ( $the_sid['File'] == 'root' ) ? $aa_PP['root_htaccess'] : $aa_PP['admin_htaccess'];

		if ( $context == 'active' )
		{
			$st = 'background-color:#DBF8DA;';
			$oya = $the_sid['Type'] . '<br />';
			$action_links = '<a href="' . wp_nonce_url( admin_url($aa_PLUGIN['action']).'&amp;deactivate-sid=' . $sid, 'deactivate-sid_' . $sid ) . '" class="delete">' . __( 'Deactivate' ) . '</a>';
		}
		else $action_links = '<a href="' . wp_nonce_url( admin_url($aa_PLUGIN['action']).'&amp;activate-sid=' . $sid, 'activate-sid_' . $sid ) . '" class="edit">' . __( 'Activate' ) . '</a>';

		echo "<tr style='{$st}'>
<td class='name' style='width:200px;'>" . $oya . "<dfn style='font-style:normal;color:#3366CC;' title='SID: " . $sid . " Version: " . $the_sid['Version'] . "'>" . $the_sid['Name'] . "</dfn></td>
<td class='desc' style='width:450px;'><p>" . $the_sid['Description'] . "</p></td>
<td class='vers'>" . $the_sid['Response'] . "</td>
<td class='file'>" . $the_sid['Module'] . "</td>
<td class='file'><dfn style='font-style:normal;color:#9999DD;' title='" . $file_title . "'>" . $the_sid['File'] . "</dfn></td>
<td class='action-links'>" . $action_links . '</td></tr>';
	}

	?>
</tbody>
</table>
</form>
<p><br class="clear" /></p>
<?php
}



/** aa_pp_active_sids
* aa_pp_active_sids()
 *
 * @param mixed $file
 * @return
 */
function aa_pp_active_sids( $file = false )
{
	global $aa_PP, $aa_SIDS;

	$result = array();
	$files = array( $aa_PP['root_htaccess'], $aa_PP['admin_htaccess'] );
	foreach ( $files as $f )
	{
		if ( !is_readable( $f ) )return new WP_Error( 'not-readable', __( "aa_pp_active_sids cant read from {$f}" ) );
		if ( $markerdata = @explode( "\n", @implode( '', @file( $f ) ) ) )
		{
			foreach ( $markerdata as $line )
			{
				if ( strpos( $line, "# +SID " ) !== false ) $result[] = ( int )str_replace( '# +SID ', '', rtrim( $line ) );
			}
		}
	}

	return array_unique( $result );
}



/** aa_pp_gen_sid
* aa_pp_gen_sid()
 *
 * @param mixed $incoming
 * @return
 */
function aa_pp_gen_sid( $incoming )
{
	global $aa_PP, $aa_SIDS;
	$scheme = ( isset($_SERVER['HTTPS']) && ( 'on' == strtolower($_SERVER['HTTPS']) ||  '1' == $_SERVER['HTTPS'] )  || ( isset($_SERVER['SERVER_PORT']) && ( '443' == $_SERVER['SERVER_PORT'] ) )) ? 'https' : 'http';
	$home = get_option( 'home' );
	$siteurl=get_option('siteurl');
	if($scheme=='https' && strpos($siteurl.$home,'https://')!==FALSE)$aa_PP['scheme']='http';

	if ( $aa_PP['authtype'] == 'Basic' ) $replacement = 'AuthType %authtype%%n%AuthName "%authname%"%n%AuthUserFile %authuserfile%%n%Require user %user%';
	else $replacement = 'AuthType %authtype%%n%AuthName "%authname%"%n%AuthDigestDomain %authdomain%%n%'.$aa_PP['authuserdigest'].' %authuserfile%%n%Require valid-user';

	if ( strpos( $aa_PP['apache_version'], '2.2' ) !== false && $aa_PP['authtype'] != 'Basic' )$replacement = str_replace( 'AuthUserFile', 'AuthUserFile', $replacement );

	$aa_S = array( '%n%', '%authname%', '%user%', '%authuserfile%', '%relative_root%', '%scheme%', '%authdomain%', '%host%', '%authtype%', '%generate_auth%' );

	$aa_R = array( "\n", $aa_PP['authname'], $aa_PP['user'], $aa_PP['authuserfile'], $aa_PP['root_path'], $aa_PP['scheme'], $aa_PP['authdomain'], $aa_PP['host'], $aa_PP['authtype'], $replacement );

	return str_replace( $aa_S, $aa_R, str_replace( $aa_S, $aa_R, $incoming ) );
}



/** aa_pp_deactivate_sid
* aa_pp_deactivate_sid()
 *
 * @param mixed $sid
 * @param string $mark
 * @param mixed $file
 * @return
 */
function aa_pp_deactivate_sid( $sid, $mark = 'SID ', $file = false )
{
	global $aa_PP, $aa_SIDS;

	if ( !$file )
	{
		$the_sid = $aa_SIDS[( int )$sid];
		$file = ( $the_sid['File'] == 'root' ) ? $aa_PP['root_htaccess'] : $aa_PP['admin_htaccess'];
	}

	$file = ( @is_readable( $file ) ) ? realpath( rtrim( $file, '/' ) ) : rtrim( $file, '/' );
	if ( !is_readable( $file ) || !is_writable( $file ) ) return new WP_Error( 'sid-deactivation-failed', __( "{$file} not readable/writable by aa_pp_deactivate_sid for {$the_sid['Name']}" ) );

	aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "Deleting {$the_sid['Name']} from {$file}" );

	$result = array();
	if ( $markerdata = @explode( "\n", @implode( '', @file( $file ) ) ) )
	{
		$state = false;
		if ( !$f = @fopen( $file, 'w' ) ) return new WP_Error( 'fopen-failed', __( "aa_pp_deactivate_sid couldnt fopen {$file}" ) );

		foreach ( $markerdata as $n => $line )
		{
			if ( strpos( $line, "# +{$mark}{$sid}" ) !== false ) $state = true;
			if ( !$state ) fwrite( $f, $line . "\n" );
			if ( strpos( $line, "# -{$mark}{$sid}" ) !== false ) $state = false;
		}
	}

	@$_POST['notice'] = "Successfully Deactivated {$the_sid['Name']}";

	if ( !fclose( $f ) )return new WP_Error( 'fclose-failed', __( "fclose failed to close {$file} in aa_pp_deactivate_sid" ) );

	return true;
}



/** aa_pp_activate_sid
* aa_pp_activate_sid()
 *
 * @param mixed $sid
 * @param mixed $file
 * @return
 */
function aa_pp_activate_sid( $sid, $file = false )
{
	global $aa_PP, $aa_SIDS;
	$the_sid = $aa_SIDS[( int )$sid];

	if ( !$file ) $file = ( $the_sid['File'] == 'root' ) ? $aa_PP['root_htaccess'] : $aa_PP['admin_htaccess'];

	$file = ( @is_readable( $file ) ) ? realpath( rtrim( $file, '/' ) ) : rtrim( $file, '/' );
	if ( !is_readable( $file ) || !is_writable( $file ) ) return new WP_Error( 'not-writable', __( "{$file} not readable/writable by aa_pp_activate_sid for {$the_sid['Name']}" ) );

	aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "Activating {$the_sid['Name']} to {$file}" );

	$rules = aa_pp_gen_sid( explode( "\n", $the_sid['Rules'] ) );

	if ( !aa_pp_insert_sids( $file, $sid, $rules ) ) return new WP_Error( 'sid-activation-failed', __( "Failed to Activate {$the_sid['Name']}" ) );
	else
	{
		@$_POST['notice'] = "Successfully Activated {$sid}: &quot;{$the_sid['Name']}&quot;<br /><pre>";
		foreach( $rules as $line )@$_POST['notice'] .= htmlentities( $line );
		@$_POST['notice'] .= '</pre>';
	}
	return true;
}



/** aa_pp_htaccess_file_init
* aa_pp_htaccess_file_init()
 *
 * @param mixed $file
 * @return
 */
function aa_pp_htaccess_file_init( $file = false )
{
	global $aa_PP;

	if ( !$file ) $files = array( $aa_PP['admin_htaccess'], $aa_PP['root_htaccess'] );
	else $files = array( $file );

	foreach( $files as $file )
	{
		$wordp = $new = $jot = array();
		$aapasspro = $wpg = $s = false;
		$l1 = str_repeat( '#', 55 );
		$l2 = '# - - - - - - - - - - - - - - - - - - - - - - - - - - -';
        $logo = array(
		'#               __                          __', 
		'#   ____ ______/ /______ _____  ____ ______/ /_  ___', 
		'#  / __ `/ ___/ //_/ __ `/ __ \/ __ `/ ___/ __ \/ _ \ ', 
		'# / /_/ (__  ) ,< / /_/ / /_/ / /_/ / /__/ / / /  __/', 
		'# \__,_/____/_/|_|\__,_/ .___/\__,_/\___/_/ /_/\___/', 
		'#                     /_/'
		);

		$ot = array_merge( array( '# +ASKAPACHE PASSPRO ' . $aa_PP['plugin_data']['Version'], $l1 ), $logo );
		$ot = array_merge( $ot, array( $l2, '# +APRO SIDS' ) );
		$ot = array_merge( $ot, array( '# -APRO SIDS', $l2 ), $logo );
		$ot = array_merge( $ot, array( $l1, '# -ASKAPACHE PASSPRO ' . $aa_PP['plugin_data']['Version'], '' ) );

		$markerdata = ( is_writable( dirname( $file ) ) && touch( $file ) ) ? @explode( "\n", @implode( '', @file( $file ) ) ) : false;
		if ( $markerdata )
		{
			foreach ( $markerdata as $line )
			{
				if ( strpos( $line, '# BEGIN WordPress' ) !== false )
				{
					$s = $wpg = true;
					$wordp[] = "";
				}
				if ( $s === true ) $wordp[] = $line;
				if ( strpos( $line, '# END WordPress' ) !== false )
				{
					$s = false;
					continue;
				}

				if ( !$s ) $new[] = $line;

				if ( strpos( $line, '# +ASKAPACHE PASSPRO' ) !== false ) $aapasspro = true;
			}
		}

		@chmod( $file, 0644 );

		if ( !$aapasspro )
		{
			$jot = ( $wpg ) ? array_merge( $new, $ot, $wordp ) : array_merge( $markerdata, $ot );

			if ( !$f = @fopen( $file, 'w' ) ) return new WP_Error( 'fopen-failed', __( "aa_pp_htaccess_file_init couldnt fopen {$file}" ) );
			$pr = join( "\n", $jot );
			if ( !@fwrite( $f, $pr, strlen( $pr ) ) ) return new WP_Error( 'aa_pp_htaccess_file_init', __( "aa_pp_insert_mark couldnt fwrite {$file}" ) );
			if ( !@fclose( $f ) ) return new WP_Error( 'fclose-failed', __( "Couldnt fclose {$file}" ) );
		}
	}

	return true;
}



/** aa_pp_insert_mark
* aa_pp_insert_mark()
 *
 * @param mixed $file
 * @param mixed $marker
 * @param mixed $insertion
 * @param mixed $backup
 * @return
 */
function aa_pp_insert_mark( $file, $marker, $insertion, $backup = false )
{
	global $aa_PP;

	$file = ( @is_readable( $file ) ) ? realpath( rtrim( $file, '/' ) ) : rtrim( $file, '/' );
	if ( !is_writable( $file ) && @!chmod( $file, 0644 ) && !@touch( $file ) ) return new WP_Error( 'creation-failed', __( "aa_pp_insert_mark could not write, create, or touch {$file}" ) );
	if ( $backup ) $backedup = aa_pp_backup( $file, $file . '-' . time() );

	aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "Inserting {$marker} array to {$file}" );
	$oldone = $foundit = false;
	$out = array();
	if ( !is_array( $insertion ) || ( is_array( $insertion ) && count( $insertion ) < 1 ) )
	{
		aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "aa_pp_insert_mark1 called without array, creating one for {$marker}" );
		$my = array( "# +{$marker}", "", "# -{$marker}" );
	}
	else
	{
		$my = array();
		$my[] = "# +{$marker}";
		foreach ( $insertion as $l ) $my[] = $l;
		$my[] = "# -{$marker}";
	}

	@chmod( $file, 0644 );
	
	if ( !$f = @fopen( $file, 'w' ) ) return new WP_Error( 'fopen-failed', __( "aa_pp_insert_mark couldnt fopen {$file}" ) );
	$pr = join( "\n", $my );
	if ( !@fwrite( $f, $pr, strlen( $pr ) ) ) return new WP_Error( 'fwrite-failed', __( "aa_pp_insert_mark couldnt fwrite {$file}" ) );
	if ( !@fwrite( $f, $out, strlen( $out ) ) ) return new WP_Error( 'fwrite-failed', __( "aa_pp_insert_mark couldnt fwrite {$file}" ) );
	if ( !@fclose( $f ) ) return new WP_Error( 'fclose-failed', __( "Couldnt fclose {$file}" ) );
	return true;
}



/** aa_pp_insert_sids
* aa_pp_insert_sids()
 *
 * @param mixed $file
 * @param mixed $marker
 * @param mixed $insertion
 * @param mixed $backup
 * @return
 */
function aa_pp_insert_sids( $file, $marker, $insertion, $backup = false )
{
	global $aa_PP;

	$file = ( @is_readable( $file ) ) ? realpath( rtrim( $file, '/' ) ) : rtrim( $file, '/' );
	if ( !is_writable( $file ) && @!chmod( $file, 0644 ) && !@touch( $file ) ) return new WP_Error( 'creation-failed', __( "aa_pp_insert_sids could not write, create, or touch {$file}" ) );
	if ( $backup ) $backedup = aa_pp_backup( $file, $file . '-' . time() );

	aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "Inserting {$marker} array to {$file}" );
	$foundit = false;
	$out = array();
	if ( !is_array( $insertion ) || ( is_array( $insertion ) && count( $insertion ) < 1 ) )
	{
		aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "aa_pp_insert_sids called without array, creating one for {$marker}" );
		$my = array( "# +SID {$marker}", "", "# -SID {$marker}" );
	}
	else
	{
		$my = array();
		$my[] = "# +SID {$marker}";
		foreach ( $insertion as $l ) $my[] = $l;
		$my[] = "# -SID {$marker}";
	}

	if ( $markerdata = @explode( "\n", @implode( '', @file( $file ) ) ) )
	{
		if ( !$f = @fopen( $file, 'w' ) ) return new WP_Error( 'fopen-failed', __( "aa_pp_insert_sids couldnt fopen {$file}" ) );

		$state = $s = $found = false;
		foreach ( $markerdata as $line )
		{
			if ( strpos( $line, '-ASKAPACHE PASSPRO' ) !== false )
			{
				fwrite( $f, $line . "\n" );
				continue;
			}

			if ( strpos( $line, "# +APRO SIDS" ) !== false )
			{
				$s = true;
				fwrite( $f, $line . "\n" );
				continue;
			}

			if ( strpos( $line, "# -APRO SIDS" ) !== false )
			{
				$s = false;
				if ( !$found )
				{
					foreach ( $my as $in ) fwrite( $f, $in . "\n" );
				}
				fwrite( $f, $line . "\n" );
				continue;
			}

			if ( !$s ) fwrite( $f, $line . "\n" );
			else
			{
				if ( strpos( $line, "# +SID {$marker}" ) !== false ) $state = true;
				if ( !$state )fwrite( $f, $line . "\n" );
				if ( strpos( $line, "# -SID {$marker}" ) !== false )
				{
					$state = false;
					$found = true;
					foreach ( $my as $in ) fwrite( $f, $in . "\n" );
				}
			}
		}
		fclose( $f );
	}

	return true;
}




function aa_pp_run_tests()
{
	aa_pp_notify( __FUNCTION__ . ':' . __LINE__ );
	global $wpdb, $wp_version, $aa_PP, $aa_SIDS, $aa_PLUGIN;
	require_once dirname(__FILE__).'/class-askapache-net.php';
	 
	 
	 $_apache_modules = array(
  'apache', 'apache2filter', 'apache2handler', 'core', 'http_core', 'mod_access', 'mod_actions', 'mod_alias',
  'mod_asis', 'mod_auth', 'mod_auth_anon', 'mod_auth_basic', 'mod_auth_dbm', 'mod_auth_digest', 'mod_auth_ldap',
  'mod_auth_mysql', 'mod_authn_alias', 'mod_authn_anon', 'mod_authn_dbd', 'mod_authn_dbm', 'mod_authn_default',
  'mod_authn_file', 'mod_authnz_ldap', 'mod_authz_dbm', 'mod_authz_default', 'mod_authz_groupfile', 'mod_authz_host',
  'mod_authz_owner', 'mod_authz_svn', 'mod_authz_user', 'mod_autoindex', 'mod_bucketeer', 'mod_cache', 'mod_case_filter',
  'mod_case_filter_in', 'mod_cband', 'mod_cern_meta', 'mod_cgi', 'mod_cgid', 'mod_charset_lite', 'mod_dav', 'mod_dav_fs',
  'mod_dav_lock', 'mod_dav_svn', 'mod_dbd', 'mod_deflate', 'mod_dir', 'mod_disk_cache', 'mod_dosevasive', 'mod_dumpio',
  'mod_echo', 'mod_encoding', 'mod_env', 'mod_example', 'mod_expires', 'mod_ext_filter', 'mod_fastcgi', 'mod_fcgid',
  'mod_file_cache', 'mod_filter', 'mod_headers', 'mod_ident', 'mod_imagemap', 'mod_imap', 'mod_include', 'mod_info',
  'mod_isapi', 'mod_limitipconn', 'mod_log_config', 'mod_log_forensic', 'mod_logio', 'mod_mem_cache', 'mod_mime',
  'mod_mime_magic', 'mod_negotiation', 'mod_netware', 'mod_nw_ssl', 'mod_optional_fn_export', 'mod_optional_fn_import',
  'mod_optional_hook_export', 'mod_optional_hook_import', 'mod_passenger', 'mod_proxy', 'mod_proxy_ajp', 'mod_proxy_balancer',
  'mod_proxy_connect', 'mod_proxy_ftp', 'mod_proxy_http', 'mod_rewrite', 'mod_security', 'mod_setenvif', 'mod_so',
  'mod_speling', 'mod_ssl', 'mod_status', 'mod_substitute', 'mod_suexec', 'mod_test', 'mod_unique_id', 'mod_userdir',
  'mod_usertrack', 'mod_version', 'mod_vhost_alias', 'mod_win32', 'prefork', 'sapi_apache2'
  );

	$ap = array();
	$ap = $aa_PP;
	$scheme = ( isset($_SERVER['HTTPS']) && ( 'on' == strtolower($_SERVER['HTTPS']) ||  '1' == $_SERVER['HTTPS'] )  || ( isset($_SERVER['SERVER_PORT']) && ( '443' == $_SERVER['SERVER_PORT'] ) )) ? 'https' : 'http';
	$home = get_option( 'home' );
	$siteurl=get_option('siteurl');
	if($scheme=='https' && strpos($siteurl.$home,'https://')!==FALSE)$scheme='http';
	$home = get_option( 'siteurl' );
	$hu = str_replace( $scheme . '://', '', $home );
	$uri =  plugins_url('/tests/',__FILE__);
	aa_pp_notify('uri: '.$uri);
	$test_root_path = str_replace(ABSPATH,'/',dirname(__FILE__).'/tests/');
	aa_pp_notify('test_root_path: '.$test_root_path);
	$test_url_base = plugins_url('/tests/',__FILE__);
	aa_pp_notify('test_url_base: '.$test_url_base);
	$home_path = rtrim( get_home_path(), '/' ) . '/';
	$basic_authuserfile = $ap['test_dir'] . '/.htpasswd-basic';
	$digest_authuserfile = $ap['test_dir'] . '/.htpasswd-digest';

	$img = pack( "H*", "47494638396101000100800000ffffff0000002c00000000010001000002024401003b" );
	$aok = '<strong style="color:#319F52;background-color:#319F52;">[  ]</strong> ';
	$fail = '<strong style="color:#CC0000;background-color:#CC0000;">[  ]</strong> ';
	$info = '<strong style="color:#9999DD;background-color:#9999DD;">[  ]</strong> ';
	$warn = '<strong style="color:#992898;background-color:#992898;">[  ]</strong> ';
	$m_s = '<h4 style="font-weight:normal">';
	$m_e = '</h4>';

	$test_htaccess_rules = array( 
		"DirectoryIndex test.gif {$test_root_path}test.gif",
		"Options +FollowSymLinks",
		"ServerSignature On",
		"ErrorDocument 401 {$test_root_path}err.php",
		"ErrorDocument 403 {$test_root_path}err.php",
		"ErrorDocument 404 {$test_root_path}err.php",
		"ErrorDocument 500 {$test_root_path}err.php",

		"<IfModule mod_alias.c>",
		'RedirectMatch 305 ^.*modaliastest$ ' . $home,
		"</IfModule>",

		"<IfModule mod_rewrite.c>",
		"RewriteEngine On",
		"RewriteBase /",
		'RewriteCond %{QUERY_STRING} modrewritetest [NC]',
		'RewriteRule .* ' . $home . ' [R=307,L]',
		"</IfModule>",

		'<Files modsec_check.gif>',
		"<IfModule mod_security.c>",
		'SetEnv MODSEC_ENABLE On',
		"SecFilterEngine On",
		'SecFilterDefaultAction "nolog,noauditlog,pass"',
		'SecAuditEngine Off',
		'SecFilterInheritance Off',
		'SecFilter modsecuritytest "deny,nolog,noauditlog,status:503"',
		'Deny from All',
		"</IfModule>",
		'</Files>',

		'<Files basic_auth_test.gif>',
		"AuthType Basic",
		'AuthName "askapache test"',
		"AuthUserFile " . $basic_authuserfile,
		"Require valid-user",
		'</Files>',

		'<Files digest_check.gif>',
		'AuthType Digest',
		'AuthName "askapache test"',
		"AuthDigestDomain {$test_root_path} {$test_url_base}",
		"AuthUserFile " . $digest_authuserfile,
		'Require none',
		'</Files>',

		'<Files authdigestfile_test.gif>',
		'AuthType Digest',
		'AuthName "askapache test"',
		"AuthDigestDomain {$test_root_path} {$test_url_base}",
		"AuthUserFile " . $digest_authuserfile,
		'Require valid-user',
		'</Files>',
		
		'<Files authuserfile_test.gif>',
		'AuthType Digest',
		'AuthName "askapache test"',
		"AuthDigestDomain {$test_root_path} {$test_url_base}",
		"AuthUserFile " . $digest_authuserfile,
		'Require valid-user',
		'</Files>'
		);
		
		?>
<div class="wrap" style="max-width:95%;">

<h2>Why Test?</h2>
<p>First we need to run a series of tests on your server to determine what capabilities your site has and also to locate any potential installation problems.</p>
<p>The tests will be run on temporary files I'll create in your <?php echo dirname(__FILE__).'/tests';?> folder.  They will create .htaccess and .htpasswd files in that location and then use
 fsockopen networking functions to query those files.  This tells us exactly how your server handles .htaccess configurations, HTTP authentication schemes, Apache Module capability, etc..</p></p>
<p>Several tests send specially crafted HTTP requests which are designed to elicit very specific HTTP Protocol Responses to accurately determine your servers capabilities.</p>
<p>Other important checks will run:  file permissions, function availability, much more testing.  You can re-run them whenever you want.   If you'd like to see the action, define AA_PP_DEBUG to 1 in this file. Good Luck!</p>


<h2>Test Results</h2>
<p>Get WAYYY more debugging information by using my ultra-powerful <a href="http://wordpress.org/extend/plugins/askapache-debug-viewer/">AskApache Debug Viewer Plugin</a>.</p>

<br /><br /><h2 style="font-size:16px;border-bottom:1px solid #CCC;padding-bottom:3px;">Required Checks</h2>
<p>The tests performed by this page are currently required to determine your servers capabilities to make sure we don't crash your server.  The utmost care was taken to make these tests work for everyone running Apache, which is crazy hard because we are testing server configuration settings programmatically from a php binary without access to server configuration settings.</p>
<p>So we achieve this by modifying your server's .htaccess configuration file and then making special HTTP requests to your server which result in specific HTTP responses which tell us if the configuration changes failed or succeeded.  The most widely allowed (by web hosts) and compatible 4+5 php function that provides access to sockets is fsockopen, so it is required.</p>
<?php
	$netok = $atest = ( aa_pp_checkfunction( 'fsockopen' ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $fail;
	echo $m_s . $msg . " Fsockopen Networking Functionality" . $m_e;
	echo '<p>You can also test headers from an external location using my <a href="http://www.askapache.com/online-tools/http-headers-tool/">HTTP Raw Header Tool</a>, which also has hexdumps <code>;)</code></p>';

	if((bool)$atest) {
		$tester = new AskApacheNet;
		$atest = ( $tester->sockit( "{$siteurl}" ) == 200 ) ? 1 : 0;
		$msg = ( $atest ) ? $aok : $fail;
		$tester->print_tcp_trace();
	}

	?>



<br /><br /><h2 style="font-size:16px;border-bottom:1px solid #CCC;padding-bottom:3px;">File Permission Tests</h2>
<p>If any of these (other than one of the .htpasswda3 writable checks) fail this plugin will not work.  Both your /.htaccess and /wp-admin/.htaccess files must be writable for this plugin, those are the only 2 files this plugin absolutely must be able to modify.  However note that changing these files (or the parent dir) permissions to 777 is not advised and may cause your site to be unreachable.</p>
<?php
	$open_basedir = @ini_get( 'open_basedir' );
	$msg = ( empty( $open_basedir ) ) ? $info : $warn;
	$open_basedir = ( empty( $open_basedir ) ) ? $open_basedir : "<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &middot; ".join("<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &middot; ",explode(':',$open_basedir.':'));
	echo $m_s . $msg . " open_basedir on/off {$open_basedir}" . $m_e;

	$htaccess_test1 = $atest = ( @is_writable( $ap['admin_htaccess'] ) || @touch( $ap['admin_htaccess'] ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $fail;
	echo $m_s . $msg . " {$ap['admin_htaccess'] } file writable" . $m_e;
	echo ( true ) ? aa_pp_writable_error($ap['admin_htaccess']) : '';

	$htaccess_test2 = $atest = ( @is_writable( $ap['root_htaccess'] ) || @touch( $ap['root_htaccess'] ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $fail;
	echo $m_s . $msg . " {$ap['root_htaccess']} file writable" . $m_e;
	echo ( true ) ? aa_pp_writable_error($ap['root_htaccess']) : '';

	$atest = ( @is_writable( dirname( dirname( $ap['root_htaccess'] ) ) . '/.htpasswda3' ) || @touch( dirname( dirname( $ap['root_htaccess'] ) ) . '/.htpasswda3' ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $fail;
	echo $m_s . $msg . dirname( dirname( $ap['root_htaccess'] ) ) . '/.htpasswda3' . " file writable" . $m_e;
	echo ( true ) ? aa_pp_writable_error(dirname( dirname( $ap['root_htaccess'] ) ) . '/.htpasswda3') : '';

	if ( !$atest )
	{
		$atest = ( @is_writable( $ap['authuserfile'] ) || @touch( $ap['authuserfile'] ) ) ? 1 : 0;
		$msg = ( $atest ) ? $aok : $fail;
		echo $m_s . $msg . $ap['authuserfile'] . " file writable" . $m_e;
		echo ( true ) ? aa_pp_writable_error($ap['authuserfile']) : '';
	}
	else $ap['authuserfile'] = dirname( dirname( $ap['root_htaccess'] ) ) . '/.htpasswda3';

	if(@is_file($ap['authuserfile']) && @filesize($ap['authuserfile']) == 0) aa_pp_unlink($ap['authuserfile']);


	$atest = ( aa_pp_mkdir( $ap['test_dir'] ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $fail;
	echo $m_s . $msg . " Creating test folder" . $m_e;
	if( (bool)$atest ===false ) wp_die("Couldnt create test folder {$ap['test_dir']}!");
	echo ( true ) ? aa_pp_writable_error($ap['test_dir']) : '';

	$atest = ( @is_writable( $ap['test_dir'] ) || @chmod( $ap['test_dir'], 777 ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $fail;
	echo $m_s . $msg . " Test folder writable" . $m_e;
	echo ( true ) ? aa_pp_writable_error( $ap['test_dir']) : '';

	$atest = ( aa_pp_insert_mark( $ap['test_dir'] . '/.htpasswd-basic', 'AskApache PassPro', array() ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $fail;
	echo $m_s . $msg . " Basic Auth htpasswd file writable" . $m_e;
	echo ( true ) ? aa_pp_writable_error($ap['test_dir'] . '/.htpasswd-basic') : '';

	$msg = ( $atest ) ? $aok : $fail;
	$atest = ( aa_pp_insert_mark( $ap['test_dir'] . '/.htpasswd-digest', 'AskApache PassPro', array() ) ) ? 1 : 0;
	echo $m_s . $msg . " Digest Auth htpasswd file writable" . $m_e;
	echo ( true ) ? aa_pp_writable_error($ap['test_dir'] . '/.htpasswd-digest') : '';

	aa_pp_htaccess_file_init( $ap['test_dir'] . '/.htaccess' );
	$atest = ( aa_pp_insert_sids( $ap['test_dir'] . '/.htaccess', 'Test', $test_htaccess_rules ) ) ? 1 : 0;
	echo $m_s . $msg . " .htaccess test file writable" . $m_e;
	echo ( true ) ? aa_pp_writable_error($ap['test_dir'] . '/.htaccess') : '';
		
?>


<br /><h2 style="font-size:16px;border-bottom:1px solid #CCC;padding-bottom:3px;">Compatibility Checks</h2>
<p>Checks different software to make sure its compatible with this plugin.</p>
<?php
	$msg = ( $wp_version < 2.6 ) ? $info : $aok;
	echo $m_s . $msg . " WordPress Version " . $wp_version . $m_e;

	$ap['apache_version'] = $apache_version = preg_replace( '|Apache/?([0-9.-]*?) (.*)|i', '\\1', $_SERVER['SERVER_SOFTWARE'] );
	$msg = ( strlen( $apache_version ) == 0 ) ? $info : $aok;
	echo $m_s . $msg . " Apache Version:  " . $apache_version . $m_e;

	$msg = ( @version_compare( phpversion(), '4.2.0', '=<' ) ) ? $info : $aok;
	echo $m_s . $msg . " PHP Version " . phpversion() . $m_e;?>


<br /><br /><h2 style="font-size:16px;border-bottom:1px solid #CCC;padding-bottom:3px;">PHP.ini Information</h2>
<p>Some information about your php.ini settings.  The following settings <strong>may</strong> need to be tweaked.  Likely they are fine.</p>
<?php

	$time = abs( intval( @ini_get( "max_execution_time" ) ) );
	echo $m_s . $info . " Max Execution Time: " . $time . $m_e;

	$memm = 10;
	if ( function_exists( "memory_get_peak_usage" ) )$memm = memory_get_peak_usage( true );
	else if ( function_exists( "memory_get_usage" ) )$memm = memory_get_usage( true );
	echo $m_s . $info . "Memory Usage: " . round( $memm / 1024 / 1024, 2 ) . $m_e;

	$mem = abs( intval( @ini_get( 'memory_limit' ) ) );
	echo $m_s . $info . 'Memory Limit: ' . "{$mem}" . $m_e;
	if ( $mem && $mem < abs( intval( 32 ) ) )@ini_set( 'memory_limit', 64 );

	$phpini = @get_cfg_var( 'cfg_file_path' );
	echo $m_s . $info . "php.ini " . $phpini . $m_e;

	$safe_mode = @ini_get( 'safe_mode' );
	$msg = ( empty( $safe_mode ) ) ? $info : $warn;
	echo $m_s . $msg . " safe_mode on/off {$safe_mode}" . $m_e;

	$disabled_functions = @ini_get( 'disable_functions' );
	$msg = ( empty( $disabled_functions ) ) ? $info : $warn;
	echo $m_s . $msg . " disable_functions {$disabled_functions}" . $m_e;?>



<br /><br /><h2 style="font-size:16px;border-bottom:1px solid #CCC;padding-bottom:3px;">Encryption Function Tests</h2>
<p>Your php installation should have all of these.  The md5 is the only one absolutely required, otherwise I can't create the neccessary password files for you.</p>
<?php
	$ap['crypt_support'] = $atest = ( aa_pp_checkfunction( 'crypt' ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $warn;
	echo $m_s . $msg . " CRYPT Encryption Function Available" . $m_e;

	$ap['md5_support'] = $atest = ( aa_pp_checkfunction( 'md5' ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $fail;
	echo $m_s . $msg . " MD5 Encryption Function Available" . $m_e;

	$ap['sha1_support'] = $atest = ( aa_pp_checkfunction( 'sha1' ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $warn;
	echo $m_s . $msg . " SHA1 Encryption Function Available" . $m_e;

	$atest = ( aa_pp_checkfunction( 'pack' ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $warn;
	echo $m_s . $msg . " pack Function Available" . $m_e;

	$atest = ( aa_pp_checkfunction( 'md5_file' ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $warn;
	echo $m_s . $msg . " md5_file Function Available" . $m_e;?>




<br /><br /><h2 style="font-size:16px;border-bottom:1px solid #CCC;padding-bottom:3px;">Revision Tests</h2>
<p>This checks for the neccessary file permissions and functions needed to utilize the .htaccess file revision support.</p>
<?php

	$atest = ( aa_pp_checkfunction( 'base64_encode' ) && aa_pp_checkfunction( 'base64_decode' ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $warn;
	echo $m_s . $msg . " base64_encode/base64_decode Functions Available" . $m_e;

	$ap['gzip_support'] = $atest = ( aa_pp_checkfunction( 'gzuncompress' ) && aa_pp_checkfunction( 'gzcompress' ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $warn;
	echo $m_s . $msg . " gzuncompress/gzcompress Functions Available" . $m_e;

	if ( $atest )
	{
		$data = aa_pp_readfile( $ap['test_dir'] . '/.htaccess' );
		$data_md5 = md5_file( $ap['test_dir'] . '/.htaccess' );

		$data_compress = base64_encode( gzcompress( $data, 9 ) );
		aa_pp_file_put_c( $ap['test_dir'] . '/.htaccess-compress', $data_compress );

		$data_decompress = gzuncompress( base64_decode( aa_pp_readfile( $ap['test_dir'] . '/.htaccess-compress' ) ) );
		aa_pp_file_put_c( $ap['test_dir'] . '/.htaccess-decompress', $data_decompress );

		$data_decompress_md5 = md5_file( $ap['test_dir'] . '/.htaccess-decompress' );

		$atest = ( $data_decompress_md5 == $data_md5 ) ? 1 : 0;
		$msg = ( $atest ) ? $aok : $fail;
		echo $m_s . $msg . " Revisions Enabled" . $m_e;
		echo "<p>Decompressed MD5: " . $data_decompress_md5 . "<br />Compressed MD5: " . $data_md5 . "</p>";
	}

	?>


<br /><br /><h2 style="font-size:16px;border-bottom:1px solid #CCC;padding-bottom:3px;">.htaccess Capabilities</h2>
<p>These tests determine with a high degree of accuracy whether or not your server is able to handle .htaccess files, and also checks for various Apache modules that extend the functionality of this plugin.  The 2 modules you really want to have are mod_rewrite and mod_auth_digest.  In future versions of this plugin, we will be utilizing the advanced security features of mod_security more and more, so if you don't have it, bug your web host about it non-stop ;)</p>
<?php
	$atest = (  aa_pp_file_put_c( $ap['test_dir'] . "/test.gif", $img ) 
				&& aa_pp_file_put_c( $ap['test_dir'] . "/basic_auth_test.gif", $img ) 
				&& aa_pp_file_put_c( $ap['test_dir'] . "/authuserfile_test.gif", $img ) 
				&& aa_pp_file_put_c( $ap['test_dir'] . "/authdigestfile_test.gif", $img ) 
				&& aa_pp_file_put_c( $ap['test_dir'] . "/modsec_check.gif", $img ) 
				&& aa_pp_file_put_c( $ap['test_dir'] . "/digest_check.gif", $img )  ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $fail;
	echo $m_s . $msg . " Creating .htaccess test files" . $m_e;
	

	if ( (bool)AA_PP_DEBUG === true ) {
		echo $m_s . $msg . " Test .htaccess Contents" . $m_e;
		echo '<pre style="padding:5px;width:auto;border:1px dotted #CCC;">';
		foreach ( $test_htaccess_rules as $l )
			echo htmlentities($l)."\n";
		echo '</pre>';
	}
	
	$tester = new AskApacheNet;
	$ap['htaccess_support'] = $atest = ( $tester->sockit( "{$test_url_base}err.php" ) == 200 ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $fail;
	echo $m_s . $msg . " .htaccess files allowed [200]" . $m_e;
	if ( (bool)AA_PP_DEBUG === true || !$atest )$tester->print_tcp_trace();


	$tester = new AskApacheNet;
	$ap['mod_alias_support'] = $atest = ( $tester->sockit( "{$test_url_base}modaliastest" ) == 305 ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $warn;
	echo $m_s . $msg . " mod_alias detection [305]" . $m_e;
	if ( (bool)AA_PP_DEBUG === true || !$atest )$tester->print_tcp_trace();

	$tester = new AskApacheNet;
	$ap['mod_rewrite_support'] = $atest = ( $tester->sockit( "{$test_url_base}err.php?modrewritetest=1" ) == 307 ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $fail;
	echo $m_s . $msg . " mod_rewrite detection [307]" . $m_e;
	if ( (bool)AA_PP_DEBUG === true || !$atest )$tester->print_tcp_trace();

	$tester = new AskApacheNet;
	$ap['mod_security_support'] = $atest = ( $tester->sockit( "{$test_url_base}modsec_check.gif?modsecuritytest" ) == 403 ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $fail;
	echo $m_s . $msg . " mod_security detection [!403]" . $m_e;
	if ( (bool)AA_PP_DEBUG === true || !$atest )$tester->print_tcp_trace();

	$tester = new AskApacheNet;
	$ap['mod_auth_digest_support'] = $atest = ( $tester->sockit( "{$test_url_base}digest_check.gif" ) == 401 ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $fail;
	echo $m_s . $msg . " mod_auth_digest detection [401]" . $m_e;
	if ( (bool)AA_PP_DEBUG === true || !$atest )$tester->print_tcp_trace();

?>



<br /><br /><h2 style="font-size:16px;border-bottom:1px solid #CCC;padding-bottom:3px;">HTTP Digest Authentication</h2>
<p>Now we know the encryption and apache module capabilities of your site.  This test literally logs in to your server using Digest Authenticationts, providing the ultimate answer as to if your server supports this scheme.</p>
<?php
	if ( $ap['mod_auth_digest_support'] != 0 && $ap['md5_support'] != 0 )
	{
		$digest_htpasswds = array();
		$digest_htpasswds[] = aa_pp_hashit( 'DIGEST', "testDIGEST", "testDIGEST", "askapache test" );
		$atest = ( aa_pp_insert_mark( $digest_authuserfile, 'AskApache PassPro Test', $digest_htpasswds ) ) ? 1 : 0;
		$msg = ( $atest ) ? $aok : $fail;
		echo $m_s . $msg . " Creating Digest htpasswd test file" . $m_e;

		$tester = new AskApacheNet;
		$tester->authtype = '';
		$rb = ( $tester->sockit( $test_url_base . 'authdigestfile_test.gif' ) == 401 ) ? 1 : 0;
		
		$tester->sockit( str_replace( '://', '://testDIGEST:testDIGEST@', $test_url_base ) . 'authdigestfile_test.gif' );
		$tester->authtype = 'Digest';
		$rg = ( $tester->sockit( str_replace( '://', '://testDIGEST:testDIGEST@', $test_url_base ) . 'authdigestfile_test.gif' ) == 200 ) ? 1 : 0;

		$ap['digest_support'] = $atest = ( $rb && $rg ) ? 1 : 0;
		$msg = ( $atest ) ? $aok : $fail;
		echo $m_s . $msg . " Digest Authentication Attempt" . $m_e;
		if ( (bool)AA_PP_DEBUG === true || !$atest )$tester->print_tcp_trace();
		
		if ( !$atest )
		{
			$tester = new AskApacheNet;
			$tester->authtype = '';
			$rb = ( $tester->sockit( $test_url_base . 'authuserfile_test.gif' ) == 401 ) ? 1 : 0;
			
			$tester->sockit( str_replace( '://', '://testDIGEST:testDIGEST@', $test_url_base ) . 'authuserfile_test.gif' );
			$tester->authtype = 'Digest';
			$rg = ( $tester->sockit( str_replace( '://', '://testDIGEST:testDIGEST@', $test_url_base ) . 'authuserfile_test.gif' ) == 200 ) ? 1 : 0;
			
			$ap['digest_support'] = $a1test = ( $rb && $rg ) ? 1 : 0;
			$msg = ( $a1test ) ? $aok : $fail;
			echo $m_s . $msg . "2nd Digest Authentication Attempt" . $m_e;
			if ( (bool)AA_PP_DEBUG === true || !$a1test )$tester->print_tcp_trace();
		}
		
		if ( (bool)$ap['digest_support'] !== false ) $ap['authuserdigest'] = ( $atest ) ? 'AuthUserFile' : 'AuthUserFile';
	}
	else echo $m_s . $msg . $fail . " Bummer... you don't have digest capabilities." . $m_e;?>


<br /><br /><h2 style="font-size:16px;border-bottom:1px solid #CCC;padding-bottom:3px;">Basic Authentication Encryption Algorithms</h2>
<p>Basic Authentication uses the .htpasswd file to store your encrypted password.  These checks perform actual logins to your server using a different .htpasswd encryption each time.</p>
<?php
	$basic_htpasswds = array();
	if ( $ap['crypt_support'] != 0 ) $basic_htpasswds[] = aa_pp_hashit( 'CRYPT', 'testCRYPT', 'testCRYPT' );
	if ( $ap['md5_support'] != 0 ) $basic_htpasswds[] = aa_pp_hashit( 'MD5', 'testMD5', 'testMD5' );
	if ( $ap['sha1_support'] != 0 ) $basic_htpasswds[] = aa_pp_hashit( 'SHA1', 'testSHA1', 'testSHA1' );

	$atest = ( aa_pp_insert_mark( $basic_authuserfile, 'AskApache PassPro Test', $basic_htpasswds ) ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $fail;
	echo $m_s . $msg . " Creating Basic htpasswd test file" . $m_e;

	$tester = new AskApacheNet;
	$rb = ( $tester->sockit( $test_url_base . 'basic_auth_test.gif' ) == 401 ) ? 1 : 0;

	if ( $ap['crypt_support'] != 0 )
	{
		$tester = new AskApacheNet;
		$rg = ( $tester->sockit( str_replace( '://', '://testCRYPT:testCRYPT@', $test_url_base ) . 'basic_auth_test.gif' ) == 200 ) ? 1 : 0;
		$ap['crypt_support'] = $atest = ( $rb && $rg ) ? 1 : 0;
		$msg = ( $atest ) ? $aok : $fail;
		echo $m_s . $msg . " Basic Authentication Attempt using Crypt Encryption" . $m_e;
		if ( (bool)AA_PP_DEBUG === true || !$atest )$tester->print_tcp_trace();
	}

	if ( $ap['md5_support'] != 0 )
	{
		$tester = new AskApacheNet;
		$rg = ( $tester->sockit( str_replace( '://', '://testMD5:testMD5@', $test_url_base ) . 'basic_auth_test.gif' ) == 200 ) ? 1 : 0;
		$ap['md5_support'] = $atest = ( $rb && $rg ) ? 1 : 0;
		$msg = ( $atest ) ? $aok : $fail;
		echo $m_s . $msg . " Basic Authentication Attempt using MD5 Encryption" . $m_e;
		if ( (bool)AA_PP_DEBUG === true || !$atest )$tester->print_tcp_trace();
	}

	if ( $ap['sha1_support'] != 0 )
	{
		$tester = new AskApacheNet;
		$rg = ( $tester->sockit( str_replace( '://', '://testSHA1:testSHA1@', $test_url_base ) . 'basic_auth_test.gif' ) == 200 ) ? 1 : 0;
		$ap['sha1_support'] = $atest = ( $rb && $rg ) ? 1 : 0;
		$msg = ( $atest ) ? $aok : $fail;
		echo $m_s . $msg . " Basic Authentication Attempt using SHA1 Encryption" . $m_e;
		if ( (bool)AA_PP_DEBUG === true || !$atest )$tester->print_tcp_trace();
	}

	$ap['basic_support'] = $atest = ( $ap['sha1_support'] != 0 || $ap['md5_support'] != 0 || $ap['crypt_support'] != 0 ) ? 1 : 0;
	$msg = ( $atest ) ? $aok : $warn;
	echo $m_s . $msg . " Basic Authentication Access Scheme Supported" . $m_e;



	foreach( array( 'htaccess_support', 'mod_alias_support', 'mod_rewrite_support', 'mod_security_support', 'mod_auth_digest_support', 'digest_support', 'basic_support' ) as $k )
	{
		if ( $aa_PP[$k] == 1 && $ap[$k] != 1 )
		{
			aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "You preset {$k} to on even though it failed the test." );
			$ap[$k] = 1;
		}
	}

	$aa_PP = $ap;
	update_option( 'askapache_password_protect', $aa_PP );


	echo '<br class="clear" /><form action="'.admin_url($aa_PLUGIN['action']).'" method="post">';
	wp_nonce_field( 'askapache-passpro-form' );
	echo '<input type="hidden" id="a_step" name="a_step" value="setup" />';
	echo '<p class="submit"><input name="sub" type="submit" id="sub" class="button button-primary button-large" value="Continue to Setup &raquo;" /></p>';
	echo '</form><br class="clear" /><br class="clear" /><br class="clear" />';
	
	
	echo '<br class="clear" /><br class="clear" /><br class="clear" /><hr /><br class="clear" /><br class="clear" /><br class="clear" /><h2>DEBUGGING INFO</h2>';
	echo '<p>Get WAYYY more debugging information by using my ultra-powerful <a href="http://wordpress.org/extend/plugins/askapache-debug-viewer/">AskApache Debug Viewer Plugin</a>.</p>';

	aa_pp_show_htaccess_files();
	
	$c=array();
	$vb=false;
	foreach ((array)(aa_pp_checkfunction('get_defined_constants')?@get_defined_constants():array())as $k=>$v) {
		if(($vb||(!$vb&&$k=='WP_ADMIN'&&$vb=true)) && (strlen($v)>10||strpos($v,'/')!==FALSE))$c[$k]=$v;
	}
	echo '<pre>';
	ksort($c);
	echo htmlspecialchars(print_r(array('Plugin Options'=>$aa_PP,'Plugin Data'=>$aa_PLUGIN,'Active SIDS'=>aa_pp_active_sids(),'Constants'=>$c),1));
	echo '</pre>';


	aa_pp_pls(WP_CONTENT_DIR, 1);
	aa_pp_pls(dirname(__FILE__), 1);
	aa_pp_pls(ABSPATH, 1);


	echo '</div>';
}



/** aa_pp_hashit()
* 
 *
 * @param mixed $algorithm
 * @param string $user
 * @param string $pass
 * @param string $authname
 * @return
 */
function aa_pp_hashit( $alg, $u = '', $p = '', $an = '' )
{
	aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "Creating  $alg of $u for $an");

	switch (strtoupper($alg))
	{
		case 'DIGEST':	return $u.":".$an.":".md5($u.":".$an.":".$p); break;
		case 'SHA1':	return $u.':{SHA}'.base64_encode(pack("H*",sha1($p))); break;
		case 'CRYPT':	for($s='',$i=0;$i<8;$i++,$s.=substr('0123456789abcdef',rand(0,15),1)); return"{$u}:".crypt($p,"$".$s); break;
		case 'MD5':
			for ($i=strlen($p), $ss = substr(str_shuffle('abcdefghijklmnopqrstuvwxyz0123456789'),0,8), $tt = $p.'$apr1$'.$ss, $b=pack("H32",md5($p.$ss.$p)); $i>0; $tt.=substr($b,0,min(16,$i)), $i-=16);
			for ($i=strlen($p), $s1='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'; $i>0; $tt.=($i&1)?chr(0):$p{0}, $i>>=1);
			for ($b=pack("H32",md5($tt)), $i=0; $i<1000; $b=pack("H32",md5((($i&1)?$p:$b).(($i%3)?$ss:'').(($i%7)?$p:'').(($i&1)?$b:$p))), $i++);
			for ($m='', $i=0, $s2='./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'; $i<5; $m=$b[$i].$b[$i+6].$b[($i==4)?5:($i+12)].$m, $i++);
			return $u.':$apr1$'.$ss.'$'.strtr(strrev(substr(base64_encode(chr(0).chr(0).$b[11].$m),2)),$s1,$s2); break;
	}
}


/** aa_pp_sid_info
* aa_pp_sid_info()
 *
 * @param mixed $sid
 * @return
 */
function aa_pp_sid_info( $sid )
{
	$sid = ( string )$sid;

	$types = array( 
		1 => 'Protection',
		2 => 'Password',
		3 => 'Anti-Spam',
		4 => 'WordPress Exploit',
		5 => 'General Exploit',
		6 => 'General'
		);

	$files = array( 0 => 'root',
		1 => 'wp-admin',
		2 => 'other'
		);

	$modules = array( 0 => 'core',
		1 => 'mod_rewrite',
		2 => 'mod_alias',
		3 => 'mod_security',
		4 => 'mod_setenv' );

	$response = array( 0 => 'none',
		1 => '503 Service Temporarily Unavailable',
		2 => '505 HTTP Version Not Supported',
		3 => '401 Authorization Required',
		4 => '403 Forbidden',
		5 => '405 Method Not Allowed'
		);

	return array( 'Type' => $types[$sid{0}], 'File' => $files[$sid{1}], 'Module' => $modules[$sid{2}], 'Response' => $response[$sid{3}] );
}


/** aa_pp_list_files
* aa_pp_list_files()
 *
 * @param mixed $dir
 * @return
 */
function aa_pp_list_files( $dir )
{
	$files = array();
	if ( is_dir( $dir ) && !is_link( $dir ) )
	{
		$d = dir( $dir );
		while ( false !== ( $r = $d->read() ) )
		{
			if ( strpos( $r, '.htaccess-' ) === false )continue;
			else $files[] = $r;
		}
		$d->close();
		ksort( $files );
	}
	return $files;
}
/** aa_pp_mkdir
* aa_pp_mkdir()
 *
 * @param mixed $dirname
 * @return
 */
function aa_pp_mkdir( $dir )
{
	$old=@umask( 0 );
	$dirname = ( @is_readable( $dir ) ) ? realpath( rtrim( $dir, '/' ) ) : rtrim( $dir, '/' );
	$dirname = str_replace( '//', '/', $dirname );
	aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "Creating directory {$dirname}" );
	@chmod( $dirname, 0755 );
	if ( is_dir( $dirname ) || @wp_mkdir_p( $dirname ) ) {
		$new=@umask($old);
		return $dirname;
	}
	elseif ( is_writable( $dirname ) && @wp_mkdir_p( $dirname ) ) {
		$new=@umask($old);
		return $dirname;
	}
	else {
		$ok=@mkdir( $dirname, 0755 );
		$new=@umask($old);
		return( (bool)$ok ? $dirname : new WP_Error( 'mkdir-failed', __( "Failed to create directory {$dirname}" ) ));
	}
}
/** aa_pp_unlink
* aa_pp_unlink()
 *
 * @param mixed $f
 * @param mixed $backup
 * @return
 */
function aa_pp_unlink( $f, $backup = false )
{
	$old=@umask( 0 );
	$f = ( @is_readable( $f ) ) ? realpath( rtrim( $f, '/' ) ) : rtrim( $f, '/' );
	$f = str_replace( '//', '/', $f );

	if ( !@file_exists( $f ) ) {
		$new=@umask($old);
		return true;
	}
	if ( $backup ) $backedup = aa_pp_backup( $f, $f . '-' . time() );

	aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "Deleted {$f}" );

	if ( is_dir( $f ) ) {
		$new=@umask($old);
		return aa_pp_rmdir( $f );
	}
	else @unlink( $f );

	if ( !@file_exists( $f ) ) {
		$new=@umask($old);
		return true;
	}
	$ret=( @chmod( $f, 0777 ) && @unlink( $f ) ) ? true : ( @chmod( dirname( $f ), 0777 ) && @unlink( $f ) ) ? true : new WP_Error( 'delete-failed', __( "Failed to delete {$f} in aa_pp_unlink" ) );
	
	$new=@umask($old);
	return $ret;
}
/** aa_pp_backup
* aa_pp_backup()
 *
 * @param mixed $f
 * @param mixed $bf
 * @return
 */
function aa_pp_backup( $f, $bf = 0 )
{
	if ( !$bf || $f == $bf )$bf = dirname( $f ) . '/' . basename( $f ) . '.AABK-' . time();

	aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "Backing up {$f} to {$bf}" );

	if ( !@copy( $f, $bf ) ) aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "Failed to backup {$f} to {$bf} using copy" );
	elseif ( !@rename( $f, $bf ) ) return new WP_Error( 'rename-failed', __( "Couldnt rename {$f} to {$bf}" ) );
	else return $bf;
}
/** aa_pp_bytes
* aa_pp_bytes()
 *
 * @param mixed $bytes
 * @return
 */
function aa_pp_bytes($b = 0)
{
	static $s=NULL;
	if(is_null($s)) $s = array('B', 'Kb', 'MB', 'GB', 'TB', 'PB');
	$e = floor(log($b) / log(1024));
	return sprintf('%.2f ' . $s[$e], (($b > 0) ? ($b / pow(1024, floor($e))) : 0));
}
/** aa_pp_file_put_c
* aa_pp_file_put_c()
 *
 * @param mixed $file
 * @param mixed $content
 * @param mixed $backup
 * @return
 */
function aa_pp_file_put_c( $f, $content, $backup = false )
{
	$old=@umask( 0 );
	//$f = ( @is_readable( $f ) ) ? realpath( rtrim( $f, '/' ) ) : rtrim( $f, '/' );
	aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "Creating {$f}" );
	if ( !is_dir( dirname( $f ) ) ) aa_pp_mkdir( dirname( $f ) );

	if ( file_exists( $f ) && is_readable( $f ) && $backup ) $backedup = aa_pp_backup( $f );

	if ( aa_pp_checkfunction( "file_put_contents" ) ) {
		$new=@umask($old);
		return @file_put_contents( $f, $content );
	}

	if ( !$fh = @fopen( $f, 'wb' ) ) {
		$new=@umask($old);
		return new WP_Error( 'fopen-failed', __( "Couldnt fopen {$f}" ) );
	}
	if ( !@fwrite( $fh, $content, strlen( $content ) ) ) {
		$new=@umask($old);
		return new WP_Error( 'fwrite-failed', __( "Couldnt fwrite {$f}" ) );
	}
	if ( !@fclose( $fh ) ) {
		$new=@umask($old);
		return new WP_Error( 'fclose-failed', __( "Couldnt fclose {$f}" ) );
	}
	
	$new=@umask($old);
	return true;
}
/** aa_pp_readfile
* aa_pp_readfile()
 *
 * @param mixed $file
 * @return
 */
function aa_pp_readfile( $f, $size='all' )
{
	$old=@umask( 0 );
	$f = ( @is_readable( $f ) ) ? realpath( rtrim( $f, '/' ) ) : rtrim( $f, '/' );
	aa_pp_notify( __FUNCTION__ . ":" . __LINE__ . ' ' . "Reading {$f}" );

	
	if ( !$fh = @fopen( $f, 'rb' ) ) {
		$new=@umask($old);
		return new WP_Error( 'fopen-failed', __( "Couldnt fopen {$f}" ) );
	}
	if  ($size=='all' ) $size=@filesize( $f );
	if ( !$filecontent = @fread( $fh, $size ) ) {
		$new=@umask($old);
		return new WP_Error( 'fread-failed', __( "Couldnt fread {$f}" ) );
	}
	if ( !@fclose( $fh ) ) {
		$new=@umask($old);
		return new WP_Error( 'fclose-failed', __( "Couldnt fclose {$f}" ) );
	}

	$new=@umask($old);
	return $filecontent;
}



/** aa_pp_errors
* aa_pp_errors()
 *
 * @param mixed $message
 * @param string $title
 * @return
 */
function aa_pp_errors( $message, $title = '' )
{
	$class = 'id="message" class="updated fade"';
	if ( aa_pp_checkfunction( 'is_wp_error' ) && is_wp_error( $message ) )
	{
		$class = 'class="error"';

		if ( empty( $title ) )
		{
			$error_data = $message->get_error_data();
			if ( is_array( $error_data ) && isset( $error_data['title'] ) ) $title = $error_data['title'];
		}

		$errors = $message->get_error_messages();
		switch ( count( $errors ) )
		{
			case 0 :
				$g = '';
				break;
			case 1 :
				$g = "<p>{$errors[0]}</p>";
				break;
			default :
				$g = '<ul>';
				foreach( $errors as $mess )$g .= "<li>{$mess}</li>\n";
				$g .= '</ul>';
				break;
		}
	} elseif ( is_string( $message ) ) $g = "<p>{$message}</p>";
	if ( !empty( $g ) )echo "<br /><div {$class} style='max-width:95%;'>{$g}</div><br />";
}

/** aa_pp_checkfunction
* aa_pp_checkfunction()
 *
 * @param string $f
 * @return bool
 */
function aa_pp_checkfunction($f)
{
	static $b,$g = array();

	if(!isset($b)) {
		$b=$disabled=array();
		$disabled=array( @ini_get('disable_functions'), @ini_get('suhosin.executor.func.blacklist'), @get_cfg_var('disable_functions'),@get_cfg_var('suhosin.executor.func.blacklist'));
		if (@ini_get('safe_mode')) {
			$disabled[]='shell_exec';
			$disabled[]='set_time_limit';
		}
		$b=aa_pp_array_iunique(array_map('trim',explode(',',strtolower(preg_replace('/[,]+/',',',trim(join(',',$disabled),','))))));
	}

	$f=strtolower($f);
	if ( ( in_array($f, $g) || in_array($f, $b)) ) return (in_array($f, $g));
	else return ( in_array($f,array($g,$b)) ? in_array($f, $g) : ( (!function_exists($f)) ? !( $b[]=$f ) : !!( $g[]=$f ) ) );
}

/** aa_pp_array_iunique
* aa_pp_array_iunique()
 *
 * @param array $array
 * @return array
 */
function aa_pp_array_iunique($array)
{
	return array_intersect_key($array,array_unique(array_map('strtolower',$array)));
}


/** aa_pp_debug
* aa_pp_debug()
 *
 * @param string $message
 * @return
 */
function aa_pp_debug( $m = '' )
{
	error_log("PHP AAPP Error: {$m}");
	return false;
}



/** aa_pp_notify
* aa_pp_notify()
 *
 * @param string $message
 * @return
 */
function aa_pp_notify( $message = '' )
{
	if ( (bool)AA_PP_DEBUG === true ) @error_log( ltrim( "PHP AAPP Info: {$message}" ), 0 );
}



function aa_pp_get_plugin_data()
{
	$plugin = get_option('askapache_password_protect_plugin');
	if(!is_array($plugin) || !!!$plugin || !array_key_exists('file',$plugin) || "{$plugin['file']}"!=__FILE__)
	{
		$data = aa_pp_readfile(__FILE__, 1450);
		$mtx = $plugin = array();
		preg_match_all('/[^a-z0-9]+((?:[a-z0-9]{2,25})(?:\ ?[a-z0-9]{2,25})?(?:\ ?[a-z0-9]{2,25})?)\:[\s\t]*(.+)/i', $data, $mtx, PREG_SET_ORDER);
		foreach ($mtx as $m) {
			$plugin[trim(str_replace(' ', '-', strtolower($m[1])))] = str_replace(array("\r", "\n", "\t"), '', trim($m[2]));
		}

		$plugin['file'] = __FILE__;
		$plugin['title'] = '<a href="' . $plugin['plugin-uri'] . '" title="Visit plugin homepage">' . $plugin['plugin-name'] . '</a>';
		$plugin['author'] = '<a href="' . $plugin['author-uri'] . '" title="Visit author homepage">' . $plugin['author'] . '</a>';
		$plugin['pb'] = preg_replace('|^' . preg_quote(WP_PLUGIN_DIR, '|') . '/|', '', __FILE__);
		$plugin['page'] = basename(__FILE__);
		$plugin['pagenice'] = rtrim($plugin['page'], '.php');
		$plugin['nonce'] = 'form_' . $plugin['pagenice'];
		$plugin['hook'] = 'settings_page_' . $plugin['pagenice'];
		$plugin['action'] = 'options-general.php?page=' . $plugin['page'];
		$plugin['op'] = 'aapp7';
	}
	
	return $plugin;
}

/** aa_pp_writable_error
* aa_pp_writable_error()
 *
 * @param string $file
 * @return string
 */
function aa_pp_writable_error( $file )
{
	ob_start();
	
	echo '<pre>';
	
	$dir=dirname($file);
	if(($ss=@stat($dir))!==false) {
		$fs = aa_ppnew_stat( $dir );
		printf( "%10s %04s %06s %'	8s %s %' 15s %s\n", $fs['human'], $fs['octal'], $fs['decimal'], $fs['owner_name'], $fs['group_name'], $fs['size'] . ' bytes', $dir.'/' );
	}
	
	if(($ss=@stat($file))!==false) {
		$fs = aa_ppnew_stat( $file );
		printf( "%10s %04s %06s %'	8s %s %' 15s %s", $fs['human'], $fs['octal'], $fs['decimal'], $fs['owner_name'], $fs['group_name'], $fs['size'] . ' bytes', $file.(is_dir($file) ? '/':'') );
	}
	
	echo '</pre>';
	return ob_get_clean();
}








if (is_admin()) :

	$_aabf=basename(__FILE__);
	$_aapb=preg_replace('|^' . preg_quote(WP_PLUGIN_DIR, '|') . '/|', '', __FILE__);
	$_aahk=rtrim('settings_page_'.$_aabf, '.php');

	register_activation_hook( __FILE__, 'aa_pp_activate' );
	register_deactivation_hook( __FILE__, 'aa_pp_deactivate');
	
	add_filter("plugin_action_links_{$_aapb}",
						 create_function('$l', 'return array_merge(array("<a href=\"options-general.php?page='.$_aabf.'\">Settings</a>"), $l);'));


	add_action('admin_menu', 
						 create_function('','add_options_page("AskApache Password Protection","AA PassPro",8,"'.$_aabf.'","aa_pp_main_page");'));
	
	
	add_action("load-{$_aahk}", 
						 create_function('','
						 @set_time_limit(60);
						 @set_magic_quotes_runtime(0);
						 global $aa_PP,$aa_SIDS,$aa_PLUGIN;
						 $aa_PP=get_option("askapache_password_protect");
						 $aa_SIDS=get_option("askapache_password_protect_sids");
						 $aa_PLUGIN=get_option("askapache_password_protect_plugin");
						'));



	unset($_aapb,$_aahk,$_aabf);

endif;



?>