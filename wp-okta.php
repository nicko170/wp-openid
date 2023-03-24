<?php

/*
Plugin Name: WP Okta
Plugin URI: https://github.com/nicko170/wp-okta
Description: Okta authentication for WordPress Admin
Version: 1.0.1
Author: Nick Pratley
Author URI: https://theitdept.au
Text Domain: wp-okta
Domain Path: /languages
Documentation: https://developer.okta.com/docs/guides/sign-into-web-app-redirect/php/main/
*/

defined('ABSPATH') or die('');

if (!function_exists('is_plugin_active_for_network')) {
    require_once(ABSPATH . '/wp-admin/includes/plugin.php');
}

require_once __DIR__ . '/WPOktaLogin.php';

(new WPOktaLogin)
    ->boot();
