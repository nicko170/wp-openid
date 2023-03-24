# WP-Okta

A WordPress plugin to authenticate users via Okta. This plugin scratches a very specific itch, and I do not want to
use other OpenID Connect plugins because they are too complicated and/or too opinionated. This plugin is very simple
and does not do anything other than authenticate users via Okta (technically, any compliant OpenID provider).

## Installation

Download the plugin from the Releases page, and upload it to your WordPress site. Activate the plugin, and then
configure the plugin via the Settings > Okta page.

## Setting up Okta

1. If you don't already have an Okta account, sign up for free developer account at https://developer.okta.com/signup/
2. [Sign in to your Okta organization](https://developer.okta.com/login) with your administrator account.
3. From the Admin dashboard, go to **Applications** > **Applications**.
4. Click **Create App Integration** and select "OIDC - OpenID Connect" as the **Sign-in method**, and "Web Application"
   as the **Application Type**.
5. Enter the following values:
    - **Name**: WordPress (or whatever, I don't care)
    - **Grant type**: Authorization Code
    - **Sign-in redirect URIs**: `https://example.com/index.php?rest_route=/okta/callback`
    - **Sign-out redirect URIs**: `https://example.com/`
6. Click **Save**, and copy the **Client ID** and **Client Secret** values.
7. If you want to show this application in the Okta Dashboard, click **Edit** on the **General Settings** tab and
   enter the following values:
    - **Login initiated by**: Either Okta or App
    - **Application visibility**: Show in both the Okta End-User Dashboard and the Okta Admin Console
    - **Initiate login URI**: `https://example.com/index.php?rest_route=/okta/login`

## Configuration

The plugin requires the following configuration options:

1. Okta Domain URL (e.g. `https://example.okta.com`)
2. Okta Client ID (e.g. `0oa1b2c3d4e5f6g7h8i9j`)
3. Okta Client Secret (e.g. `0oa1b2c3d4e5f6g7h8i9j0oa1b2c3d4e5f6g7h8i9j`)

You can set these options via the Settings > Okta page in the WordPress admin, or in your `wp-config.php` file:

```php
define('WP_OKTA_DOMAIN', 'https://example.okta.com');
define('WP_OKTA_CLIENT_ID', '0oa1b2c3d4e5f6g7h8i9j');
define('WP_OKTA_CLIENT_ID', '0oa1b2c3d4e5f6g7h8i9j');
```

If a user already exists in WordPress we will just log them in. If a user does not exist in WordPress,
we will create a new user with the same username as their Okta preferred username. The user will be assigned the Editor
role by default, but this can be changed via the `wp_okta_default_role` filter.

## Changing the default role

The default role can be changed via the `wp_okta_default_role` filter. For example, to change the default role to
Administrator:

Shove this in your theme's `functions.php` file:

```php
add_filter('wp_okta_default_role', function() {
    return 'administrator';
});
```

## Security

If you discover any security related issues, please email me at [nick@npratley.net](mailto:nick@npratley.net) instead of
using the issue tracker.

## License

GNU General Public License v3.0

Copyright (c) 2023 Nick Pratley