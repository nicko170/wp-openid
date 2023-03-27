<?php

/*
Plugin Name: WP OpenID
Plugin URI: https://github.com/nicko170/wp-openid
Description: Simple OpenID authentication for WordPress.
Version: VERSION
Author: Nick Pratley
Author URI: https://theitdept.au
Text Domain: openid
Domain Path: /languages
Documentation: https://github.com/nicko170/wp-openid
*/


// Define the plugin version. This will be replaced by the build script.
const WP_OPENID_VERSION = 'VERSION';

defined('ABSPATH') or die('');

if (!function_exists('is_plugin_active_for_network')) {
    require_once(ABSPATH . '/wp-admin/includes/plugin.php');
}

require_once __DIR__ . '/OpenID.php';
require_once __DIR__ . '/Updater.php';

// We only want to run the updater if we are in the admin area.
add_action('admin_init', function () {
    Updater::make()
        ->transient('wp_openid_update')
        ->repository('nicko170/wp-openid')
        ->asset_name('wp-openid.zip')
        ->readme_url('https://raw.githubusercontent.com/nicko170/wp-openid/main/README.md')
        ->boot(__FILE__);
});

// Boot the plugin.
OpenID::make()
    ->boot();
