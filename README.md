# WP-OpenID

A WordPress plugin to authenticate users via a OpenID Provider. This plugin scratches a very specific itch. This plugin
is very
simple and does not do anything other than authenticate users via an OpenID Provider.

This plugin has been tested with both Keycloak and Okta, but should work with any OpenID Connect provider that supports
the Authorization Code flow with PKCE.

![The WordPress Login Page](docs/images/login_page.png?raw=true)

## Installation

1. Download the latest release
   from [GitHub Releases](https://github.com/nicko170/wp-openid/releases/latest/download/wp-openid.zip)
2. In WordPress, go to **Plugins** > **Add New** > **Upload Plugin** and upload the zip file.
3. Activate the plugin.
4. A new **OpenID** menu item will appear in the WordPress admin Settings menu.
5. Follow the instructions on the Settings page to configure the plugin.

## Setting up Keycloak

1. If you don't already have a Keycloak
   instance, [you can run it up in Docker](https://www.keycloak.org/guides#getting-started)
2. Sign in to your Keycloak instance with your administrator account.
3. From the Admin dashboard, go to **Clients** > **Create**.
4. Enter the following values:
    - **Client Type**: OpenID Connect
    - **Client ID**: wordpress
    - **Name**: WordPress

5. Click **Next**, and enable Client Authentication. You can leave the other options as their defaults.
6. Click **Save**, and set your URLs:
    - **Root URL**: `https://example.com/`
    - **Valid Redirect URIs**: `https://example.com/index.php?rest_route=/openid/callback`
    - **Admin URL**: `https://example.com/wp-admin`
    - The other URLs can be left as their defaults.
7. Click **Save**, and copy the **Client ID** and **Client Secret** values from the **Credentials** tab.

## Setting up Okta

1. If you don't already have an Okta account, sign up for free developer account at https://developer.okta.com/signup/
2. [Sign in to your Okta organization](https://developer.okta.com/login) with your administrator account.
3. From the Admin dashboard, go to **Applications** > **Applications**.
4. Click **Create App Integration** and select "OIDC - OpenID Connect" as the **Sign-in method**, and "Web Application"
   as the **Application Type**.
5. Enter the following values:
    - **Name**: WordPress (or whatever, I don't care)
    - **Grant type**: Authorization Code
    - **Sign-in redirect URIs**: `https://example.com/index.php?rest_route=/openid/callback`
    - **Sign-out redirect URIs**: `https://example.com/`
6. Click **Save**, and copy the **Client ID** and **Client Secret** values.
7. If you want to show this application in the Okta Dashboard, click **Edit** on the **General Settings** tab and
   enter the following values:
    - **Login initiated by**: Either Okta or App
    - **Application visibility**: Show in both the Okta End-User Dashboard and the Okta Admin Console
    - **Initiate login URI**: `https://example.com/index.php?rest_route=/openid/login`

## Configuration

The plugin requires the following configuration options:

1. Metadata URL (e.g. `https://example.okta.com/.well-known/openid-configuration` or for
   Keycloak `https://example.com/auth/realms/example/.well-known/openid-configuration`)
2. Client ID (e.g. `0oa1b2c3d4e5f6g7h8i9j`)
3. Client Secret (e.g. `0oa1b2c3d4e5f6g7h8i9j0oa1b2c3d4e5f6g7h8i9j`)

You can set these options via the Settings > Okta page in the WordPress admin, or in your `wp-config.php` file if you
don't want them to be editable by other users:

```php
define('WP_OPENID_METADATA_URL', 'https://example.okta.com/.well-known/openid-configuration');
define('WP_OPENID_CLIENT_ID', '0oa1b2c3d4e5f6g7h8i9j');
define('WP_OPENID_CLIENT_SECRET', '0oa1b2c3d4e5f6g7h8i9j0oa1b2c3d4e5f6g7h8i9j');
```

![Settings Page](docs/images/settings_page.png?raw=true)

## Mapping User Attributes

You can map user attributes from your OpenID Provider to WordPress user meta fields using the Settings > OpenID page.

The following WordPress user attributes are supported:

- user_login: The user's login username
- user_url: The user's website URL
- user_email: The user's email address
- display_name: The user's display name
- nickname: The user's nickname
- first_name: The user's first name
- last_name: The user's last name

The following OpenID Connect attributes are supported:

- sub: The user's unique identifier
- preferred_username: The user's preferred username
- name: The user's full name
- given_name: The user's first name
- family_name: The user's last name
- middle_name: The user's middle name
- nickname: The user's nickname
- profile: The user's profile page
- picture: The user's profile picture
- website: The user's website
- email: The user's email address

![Attribute Mapping](docs/images/attribute_mapping.png?raw=true)

## User matching is performed by matching:

- The `sub` claim from the ID Token to the `openid_id` meta field on the user
- The `email` claim from the ID Token to the `user_email` field on the user
- The `preferred_username` claim from the ID Token to the `user_login` field on the user

If you have remapped the `email` or `preferred_username` claims, your mapping will be used for user matching, before
falling back to `email` and `preferred_username` respectively.

If a user is not found, a new user will be created with the attributes as mapped in the Settings > OpenID page.

## Security

If you discover any security related issues, please email me at [nick@npratley.net](mailto:nick@npratley.net) instead of
using the issue tracker.

## Credits

- [Nick Pratley](https://github.com/nicko170)

## License

GNU General Public License v3.0

Copyright (c) 2023 Nick Pratley
