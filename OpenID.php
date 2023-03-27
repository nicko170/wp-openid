<?php

class OpenID
{
    private ?string $metadata_url;
    private ?string $client_id;
    private ?string $client_secret;
    private ?string $default_role;
    private ?bool $is_network;
    private ?array $metadata;
    private ?array $user_mapping;
    private ?array $user_fields;
    private ?string $login_button_text;
    /**
     * @var mixed|string
     */
    private ?string $login_separator_text;
    /**
     * @var mixed|string
     */
    private ?string $login_image;
    private ?int $login_image_id = null;
    private ?string $default_image;
    /**
     * @var false|mixed
     */
    private ?bool $take_over_login;

    private ?string $take_over_login_secret;

    public function __construct()
    {
        // General Options
        $this->is_network = is_plugin_active_for_network('wp-openid');
        $this->metadata_url = defined('WP_OPENID_METADATA_URL') ? WP_OPENID_METADATA_URL : ($this->is_network ? get_site_option('openid_metadata_url') : get_option('openid_metadata_url'));
        $this->client_id = defined('WP_OPENID_CLIENT_ID') ? WP_OPENID_CLIENT_ID : ($this->is_network ? get_site_option('openid_client_id') : get_option('openid_client_id'));
        $this->client_secret = defined('WP_OPENID_CLIENT_SECRET') ? WP_OPENID_CLIENT_SECRET : ($this->is_network ? get_site_option('openid_client_secret') : get_option('openid_client_secret'));
        $this->default_role = defined('WP_OPENID_DEFAULT_ROLE') ? WP_OPENID_DEFAULT_ROLE : ($this->is_network ? get_site_option('openid_default_role') : get_option('openid_default_role'));
        $this->take_over_login = defined('WP_OPENID_TAKE_OVER_LOGIN') ? WP_OPENID_TAKE_OVER_LOGIN : ($this->is_network ? get_site_option('openid_take_over_login') : get_option('openid_take_over_login'));
        $this->take_over_login_secret = defined('WP_OPENID_TAKE_OVER_LOGIN_SECRET') ? WP_OPENID_TAKE_OVER_LOGIN_SECRET : ($this->is_network ? get_site_option('openid_take_over_login_secret') : get_option('openid_take_over_login_secret'));

        // Styling
        if ($login_button_text = defined('WP_OPENID_LOGIN_BUTTON_TEXT') ? WP_OPENID_LOGIN_BUTTON_TEXT : ($this->is_network ? get_site_option('openid_login_button_text') : get_option('openid_login_button_text'))) {
            $this->login_button_text = $login_button_text;
        } else {
            $this->login_button_text = 'Login with OpenID';
        }

        if ($login_separator_text = defined('WP_OPENID_LOGIN_SEPARATOR_TEXT') ? WP_OPENID_LOGIN_SEPARATOR_TEXT : ($this->is_network ? get_site_option('openid_login_separator_text') : get_option('openid_login_separator_text'))) {
            $this->login_separator_text = $login_separator_text;
        } else {
            $this->login_separator_text = '--- or ---';
        }

        $this->default_image = plugins_url('assets/images/openid.svg', __FILE__);
        if ($login_image_id = $this->is_network ? get_site_option('openid_login_image_id') : get_option('openid_login_image_id')) {
            if ($login_image = wp_get_attachment_url($login_image_id)) {
                $this->login_image_id = $login_image_id;
                $this->login_image = $login_image;
            } else {
                $this->login_image = $this->default_image;
            }
        } else {
            $this->login_image = $this->default_image;
        }

        // User Mapping
        if ($user_mapping = defined('WP_OPENID_USER_MAPPING') ? WP_OPENID_USER_MAPPING : ($this->is_network ? get_site_option('openid_user_mapping') : get_option('openid_user_mapping'))) {
            $this->user_mapping = $user_mapping;
        } else {
            $this->user_mapping = [
                'user_login' => 'preferred_username',
                'user_email' => 'email',
                'user_url' => 'website',
                'display_name' => 'name',
                'first_name' => 'given_name',
                'last_name' => 'family_name',
                'nickname' => 'nickname',
            ];
        }

        $this->metadata = [];

        if ($this->metadata_url) {
            $this->metadata = $this->_get_metadata();
        }

        $this->user_fields = [
            'sub',
            'email',
            'name',
            'given_name',
            'family_name',
            'middle_name',
            'preferred_username',
            'nickname',
            'picture',
            'profile',
            'website',
        ];
    }

    public static function make(): self
    {
        return new self();
    }

    public function boot(): void
    {
        add_action('login_message', [$this, 'openid_login_page_button']);
        add_action('admin_init', [$this, 'admin_init']);
        add_action('admin_menu', [$this, 'admin_menu'], 99);
        add_action('admin_enqueue_scripts', [$this, 'admin_enqueue_scripts']);

        register_deactivation_hook(__FILE__, [$this, 'deactivate']);

        add_action('login_init', [$this, 'login_init']);
    }

    public function admin_enqueue_scripts($page): void
    {
        // If we are on the settings or options-general page, enqueue the scripts
        if ($page === 'settings_page_openid') {
            // Load the WordPress media scripts
            wp_enqueue_media();

            // Load the plugin scripts
            wp_enqueue_script('openid-admin', plugins_url('assets/js/admin-image-select.js', __FILE__), ['jquery'], WP_OPENID_VER);
        }
    }

    public function login_init(): void
    {
        // We don't want to get in the way of the logout function.
        if (isset($_REQUEST['action']) && $_REQUEST['action'] === 'logout') {
            return;
        }

        // Load the OpenID routes
        if (isset($_REQUEST['openid']) && $_REQUEST['openid'] === 'login') {
            $this->login_redirect();
            exit();
        } elseif (isset($_REQUEST['openid']) && $_REQUEST['openid'] === 'callback') {
            $this->login_callback();
            exit();
        }

        // If we are "taking over" the login page, we need to disable the default login form and only show ours.
        // This is easily achieved by taking over the login_init action, rendering the header (where our form is shown) and then exiting.

        // We also need to check to see if they have the fallback query string, and if so, disable the take_over_login functionality.
        if (isset($_REQUEST['fallback']) && $_REQUEST['fallback'] === $this->take_over_login_secret) {
            // We need to disable the take_over_login functionality.
            $this->take_over_login = false;

            // We add a filter on set_url_scheme to change the login_post and login url to the fallback URL.
            // This is so that the login form will post to the fallback URL, and we can disable the take_over_login functionality.
            add_filter('site_url', function ($url, $scheme, $orig_scheme) {
                if ($orig_scheme === 'login_post' || $orig_scheme === 'login') {
                    return add_query_arg('fallback', $this->take_over_login_secret, $url);
                }
                return $url;
            }, 10, 3);

            // Let's also add a message to the login form, to let the user know they have used the fallback URL.
            add_filter('login_message', function () {
                return '</br><div id="login_error">You have used the Fallback URL to enable the password form. This is only visible for you.</div>';
            });
        }

        if ($this->take_over_login) {
            // Because we hook login_message to show our button, we can just show the default header and footer, ignoring
            // everything else in the login page.
            login_header(__('Log In'));
            login_footer();

            // We exit here, to prevent the default login form from being shown. This also prevents the form being submitted.
            exit();
        }

        // If we are not taking over the login page, we can just return here, and the default login form will be shown.
        // Which uses the login_message to show our button!
    }

    /**
     * @throws Exception
     */
    public function login_redirect(): bool
    {
        // Redirect to OpenID , passing the state and nonce
        // Implementation taken from: https://developer.openid.com/docs/guides/sign-into-web-app-redirect/php/main/#redirect-to-the-sign-in-page

        $state = $this->_create_oauth_state();

        // Create the PKCE code verifier and code challenge
        $hash = hash('sha256', $state['verifier'], true);
        $code_challenge = rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');

        return wp_redirect(add_query_arg([
            'response_type' => 'code',
            'client_id' => $this->client_id,
            'state' => $state['state'],
            'redirect_uri' => add_query_arg('openid', 'callback', site_url('/wp-login.php')),
            'code_challenge' => $code_challenge,
            'code_challenge_method' => 'S256',
            'scope' => 'openid profile email',
        ], $this->metadata['authorization_endpoint']));
    }

    public function login_callback(): bool
    {
        if (!$state = $this->_get_oauth_state()) {
            die("state not found");
        }

        // Check the state
        if (empty($_GET['state']) || $_GET['state'] != $state['state']) {
            die("state does not match");
        }

        if (!empty($_GET['error'])) {
            die("authorization server returned an error: " . $_GET['error']);
        }

        if (empty($_GET['code'])) {
            die("this is unexpected, the authorization server redirected without a code or an  error");
        }

        // Exchange the authorization code for an access token by making a request to the token endpoint,
        // using the authorization code. The authorization code is a one-time use code, and if the token endpoint
        // returns us a set of tokens instead of an error, we can assume the user and token are valid.
        $token = $this->_get_token($_GET['code']);

        // Because we've asked the OpenID server for the openid scope, the response will contain an id_token
        // We do not need to validate the token, as it's been retrieved from the OpenID server - not the user.
        // We can just decode it and use the claims.
        if (empty($token['id_token'])) {
            die("No id_token returned");
        }

        // Decode the id_token
        $claim = json_decode(base64_decode(explode('.', $token['id_token'])[1]), true);

        // Find or create a WordPress user for the claim, based on the user field mapping
        $user = $this->_user_from_claim($claim);

        // Log the user in
        $this->_login_user($user);

        // Delete the state
        $this->_delete_oauth_state();

        // Redirect to the admin page
        return wp_redirect($this->is_network ? network_admin_url() : admin_url());
    }

    private function _login_user(WP_User $user): void
    {
        if (is_user_logged_in()) {
            wp_logout();
        }

        add_filter('authenticate', [$this, 'allow_programmatic_login'], 10, 3);
        $user = wp_signon(['user_login' => $user->user_login]);
        remove_filter('authenticate', [$this, 'allow_programmatic_login'], 10, 3);

        if (is_a($user, 'WP_User')) {
            wp_set_current_user($user->ID, $user->user_login);
        }
    }

    public function allow_programmatic_login($user, $username, $password): WP_User
    {
        return get_user_by('login', $username);
    }

    private function _get_token(string $code): array
    {
        // Exchange the authorization code for an access token by making a request to the token endpoint

        if (!$state = $this->_get_oauth_state()) {
            die("state not found3");
        }

        $response = wp_safe_remote_post($this->metadata['token_endpoint'], [
            'headers' => [
                'Accept' => 'application/json',
                'Content-Type' => 'application/x-www-form-urlencoded'
            ],
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => add_query_arg('openid', 'callback', site_url('/wp-login.php')),
                'client_id' => $this->client_id,
                'client_secret' => $this->client_secret,
                'code_verifier' => $state['verifier'],
            ],
            'sslverify' => true,
        ]);

        if (is_wp_error($response)) {
            die("Error getting token from token server: " . $response->get_error_message());
        }

        return json_decode($response['body'], true);
    }

    private function _user_from_claim(array $claim): WP_User
    {
        // Check if we already have a user with this OpenID Subject ID
        if ($user = get_users([
            'meta_key' => 'openid_id',
            'meta_value' => $claim['sub'],
            'number' => 1,
        ])[0] ?? null) {
            return $user;
        }

        // Check if we have a user with this username - we need to use the user_mapping to map the username from the OpenID provider
        // We can fall back to the preferred_username claim if the user_mapping doesn't contain a user_login key
        if ($user = get_user_by('login', $claim[$this->user_mapping['user_login']] ?? $claim['preferred_username'])) {
            // We have a user with this username, so update their meta to include the OpenID Subject ID
            update_user_meta($user->ID, 'openid_id', $claim['sub']);
            return $user;
        }

        // Check if we have a user with this email address - we need to use the user_mapping to map the email from the OpenID provider
        // We can fall back to the email claim if the user_mapping doesn't contain a user_email key
        if ($user = get_user_by('email', $claim[$this->user_mapping['user_email']] ?? $claim['email'])) {
            // We have a user with this email address, so update their meta to include the OpenID Subject ID
            update_user_meta($user->ID, 'openid_id', $claim['sub']);
            return $user;
        }

        // We don't have a user with this OpenID Subject ID, username or email address, so create one, using the
        // user_mapping to map the fields from the OpenID provider

        // We can fall back to the preferred_username claim if the user_mapping doesn't contain a user_login key
        $user_data = [
            'user_login' => $claim[$this->user_mapping['user_login']] ?? $claim['preferred_username'],
            'user_email' => $claim[$this->user_mapping['user_email']] ?? $claim['email'],
            'user_pass' => wp_generate_password(),
            'role' => $this->default_role,
            'meta_input' => [
                'openid_id' => $claim['sub']
            ],
        ];

        // We loop through the user_mapping to map the fields from the OpenID provider.
        foreach ($this->user_mapping as $key => $value) {
            // We don't want to overwrite the user_login or user_email fields, as we've already set those above
            if ($key === 'user_login' || $key === 'user_email') {
                continue;
            }

            // If the value is null or the property doesn't exist in the claim, we don't want to set it
            if ($value === null || !isset($claim[$value])) {
                continue;
            }

            // Set the mapped property on the user
            $user_data[$key] = $claim[$value];
        }

        // Create the user, and return it
        $user_id = wp_insert_user($user_data);

        if (is_wp_error($user_id)) {
            die("Error Creating User: " . $user_id->get_error_message());
        }

        return get_user_by('id', $user_id);
    }

    public function openid_login_page_button(): void
    {
        // If we have an issuer, client_id and client_secret, we can display the login button
        if (isset($this->metadata['issuer']) && $this->client_id && $this->client_secret) {
            ?>
            <style>
                .openid-logo {
                    background-image: url("<?php echo esc_url($this->login_image); ?>");
                    overflow: hidden;
                    background-position: 45% 45%;
                    background-repeat: no-repeat;
                    background-size: cover;
                    height: 100px;
                    margin-bottom: 20px;
                }
            </style>
            <form style="padding-bottom: 26px; text-align: center;">
                <div class="openid-logo"></div>
                <a href="<?php echo esc_url(add_query_arg('openid', 'login', site_url('/wp-login.php'))) ?>" class="button">
                    <?php printf(
                        esc_html__($this->login_button_text, 'openid')
                    ); ?>
                </a>
            </form>

            <?php
            if (!$this->take_over_login) {
                // If we are not taking over the login page, we can display the separator text
                ?>
                <p style="margin-top: 20px; text-align: center;">
                    <?php esc_html_e($this->login_separator_text, 'openid'); ?>
                </p>
                <?php
            }
        }
    }

    /**
     * @throws Exception
     */
    public function admin_init(): void
    {
        // General options
        register_setting('openid', 'openid_metadata_url');
        register_setting('openid', 'openid_client_id');
        register_setting('openid', 'openid_client_secret');
        register_setting('openid', 'openid_default_role');
        register_setting('openid', 'openid_user_mapping');

        // Styling options
        register_setting('openid', 'openid_login_button_text');
        register_setting('openid', 'openid_login_separator_text');
        register_setting('openid', 'openid_login_image_id');

        // Advanced options
        register_setting('openid', 'openid_take_over_login');
        register_setting('openid', 'openid_take_over_login_secret');

        // Set a random secret if we don't have one
        // This secret is used to bypass the "take_over_login" check to ensure there is a way for admins to login,
        // even if the OpenID provider is down or unavailable
        if (!get_option('openid_take_over_login_secret')) {
            update_option('openid_take_over_login_secret', bin2hex(random_bytes(32)));
        }

        add_action('network_admin_edit_openid', [$this, 'save_settings']);

        add_filter('plugin_action_links_wp-openid/wp-openid.php', function ($links) {
            $links[] = sprintf(
                '<a href="%s">%s</a>',
                esc_url($this->is_network ? network_admin_url('settings.php?page=openid') : admin_url('options-general.php?page=openid')),
                esc_html__('Settings', 'openid')
            );

            return $links;
        });
    }

    public function admin_menu(): void
    {
        add_options_page('OpenID Authentication', 'OpenID', $this->is_network ? 'manage_network_options' : 'manage_options', 'openid', [$this, 'settings_page']);
    }

    public function settings_page(): void
    {
        ?>
        <div class="wrap">
            <h1>
                <?php esc_html_e('OpenID Authentication', 'openid'); ?>
            </h1>
            <form action="<?php echo esc_url($this->is_network ? network_admin_url('edit.php?action=openid') : admin_url('options.php')); ?>"
                  method="post" autocomplete="off">
                <?php settings_fields('openid'); ?>
                <?php do_settings_sections('openid'); ?>
                <p>
                    Any compliant OpenID Connect provider should work, but this plugin has been tested with Okta and
                    Keycloak.
                </p>

                <h2 class="title">
                    <?php esc_html_e('Step 1', 'openid'); ?>
                </h2>
                <p>
                <p>Enter your OpenID Metadata URL in the field below. If you are using Okta, your URL will look like
                    <code>https://dev-123456.okta.com/.well-known/openid-configuration</code>.</p>
                <p>If you are using
                    Keycloak, your URL will look like
                    <code>https://keycloak.example.com/auth/realms/example/.well-known/openid-configuration</code>.
                </p>
                <table class="form-table">
                    <tr>
                        <th scope="row">
                            Metadata URL
                        </th>
                        <td>
                            <label>
                                <input type="url" name="openid_metadata_url"
                                       value="<?php echo esc_url($this->metadata_url); ?>"
                                       size="40"<?php echo esc_attr(defined('WP_OPENID_METADATA_URL') ? ' disabled readonly' : ''); ?>>
                            </label>
                        </td>
                    </tr>
                    <?php

                    // if there is an error, we can show the user the URL is busted
                    if ($this->metadata && array_key_exists('error', $this->metadata)) {
                        ?>
                        <tr>
                            <th scope="row">
                                <?php esc_html_e('Error', 'openid'); ?>
                            </th>
                            <td>
                                <code><?php echo esc_html($this->metadata['error']); ?></code>
                            </td>
                        </tr>

                        <?php
                        // If we have a valid metadata URL, show the issuer and authorization endpoint
                    } elseif ($this->metadata && array_key_exists('issuer', $this->metadata)) {
                        ?>

                        <tr>
                            <th scope="row">
                                <?php esc_html_e('Issuer', 'openid'); ?>
                            </th>
                            <td>
                                <code><?php echo esc_url($this->metadata['issuer']); ?></code>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <?php esc_html_e('Authorization Endpoint', 'openid'); ?>
                            </th>
                            <td>
                                <code><?php echo esc_url($this->metadata['authorization_endpoint']); ?></code>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <?php esc_html_e('Token Endpoint', 'openid'); ?>
                            </th>
                            <td>
                                <code><?php echo esc_url($this->metadata['token_endpoint']); ?></code>
                            </td>
                        </tr>
                        <?php
                    }
                    ?>

                </table>

                <h2 class="title">
                    <?php esc_html_e('Step 2', 'openid'); ?>
                </h2>
                <p>
                    Create a new application in your OpenID provider. The application type should be <code>Web</code>.
                </p>
                <p>
                    The following settings should be used:
                </p>
                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Name', 'openid'); ?>
                        </th>
                        <td>
                            <code><?php echo get_bloginfo(); ?></code>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Grant type', 'openid'); ?>
                        </th>
                        <td>
                            <code>Authorization Code</code>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Sign-in redirect URIs', 'openid'); ?>
                        </th>
                        <td>
                            <code><?php echo esc_url(add_query_arg('openid', 'callback', site_url('/wp-login.php'))); ?></code>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Sign-out redirect URIs', 'openid'); ?>
                        </th>
                        <td>
                            <code><?php echo esc_url(home_url()); ?></code>
                        </td>
                    </tr>
                </table>

                <h2 class="title">
                    <?php esc_html_e('Step 3', 'openid'); ?>
                </h2>
                <p>
                    Enter your Client ID and Client Secret in the fields below.
                </p>
                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Client ID', 'openid'); ?>
                        </th>
                        <td>
                            <label>
                                <input type="text" name="openid_client_id"
                                       value="<?php echo esc_attr($this->client_id); ?>"
                                       size="40"<?php echo esc_attr(defined('OPENID_CLIENT_ID') ? ' disabled readonly' : ''); ?>>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Client Secret', 'openid'); ?>
                        </th>
                        <td>
                            <label>
                                <input type="password" name="openid_client_secret"
                                       value="<?php echo esc_attr($this->client_secret); ?>"
                                       size="40"<?php echo esc_attr(defined('OPENID_CLIENT_SECRET') ? ' disabled readonly' : ''); ?>>
                            </label>
                        </td>
                    </tr>
                </table>

                <h2 class="title">
                    <?php esc_html_e('Step 4', 'openid'); ?>
                </h2>
                <p>
                    If your OpenID provider supports provider initiated login, you can use the following settings:
                </p>
                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Initiate Login URI', 'openid'); ?>
                        </th>
                        <td>
                            <code><?php echo esc_url(add_query_arg('openid', 'login', site_url('/wp-login.php'))) ?></code>
                        </td>
                    </tr>
                </table>

                <h2 class="title">
                    <?php esc_html_e('Step 5', 'openid'); ?>
                </h2>
                <p>
                    User attributes can be mapped to WordPress user fields. The following attributes are supported:
                </p>
                <table class="form-table">
                    <thead>
                    <tr>
                        <th scope="col">
                            WordPress User Field
                        </th>
                        <th scope="col">
                            OpenID Attribute
                        </th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr>
                        <td>
                            <p><code>user_login</code> The user's login username.</p>
                        </td>
                        <td>
                            <?php $this->_render_attribute_select('user_login'); ?>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p><code>user_url</code> The user's URL.</p>
                        </td>
                        <td>
                            <?php $this->_render_attribute_select('user_url'); ?>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p><code>user_email</code> The user's email address.</p>
                        </td>
                        <td>
                            <?php $this->_render_attribute_select('user_email'); ?>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p><code>display_name</code> The user's display name.</p>
                        </td>
                        <td>
                            <?php $this->_render_attribute_select('display_name'); ?>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p><code>nickname</code> The user's nickname.</p>
                        </td>
                        <td>
                            <?php $this->_render_attribute_select('nickname'); ?>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p><code>first_name</code> The user's first name.</p>
                        </td>
                        <td>
                            <?php $this->_render_attribute_select('first_name'); ?>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p><code>last_name</code> The user's last name.</p>
                        </td>
                        <td>
                            <?php $this->_render_attribute_select('last_name'); ?>
                        </td>
                    </tr>

                    <tr>
                        <td>
                            <p><code>role</code> User's role.</p>
                        </td>
                        <td>
                            <?php $roles = get_editable_roles(); ?>
                            <label>
                                <select name="openid_default_role">
                                    <option value=""><?php esc_html_e('None', 'openid'); ?></option>
                                    <?php foreach ($roles as $role => $data): ?>
                                        <option value="<?php echo esc_attr($role); ?>"<?php selected($this->default_role, $role); ?>>
                                            <?php echo esc_html($data['name']); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </label>
                        </td>
                    </tr>
                    </tbody>

                </table>

                <h2 class="title">
                    <?php esc_html_e('Step 6', 'openid'); ?>
                </h2>
                <p>
                    Options for Style and Behavior.
                </p>
                <p>To keep your site secure from brute-force attempts, you can disable the default WordPress
                    login page. If you enable this option, you can use the Fallback URL to access the default
                    WordPress login function. Your Fallback URL should be kept secure! When you hit it, the password
                    form will be enabled for 1 hour, for your browser session.</p>
                <table class="form-table">
                    <tr>
                        <th scope="row">Hide Default Login Form</th>
                        <td>
                            <label>
                                <input type="checkbox" name="openid_take_over_login"
                                    <?php echo esc_attr(defined('WP_OPENID_TAKE_OVER_LOGIN') ? ' disabled readonly' : ''); ?>
                                       value="1"<?php checked($this->take_over_login); ?>>
                                <?php esc_html_e('Hide the default WordPress login form.', 'openid'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Fallback URL', 'openid'); ?>
                        </th>
                        <td>
                            <code>
                                <?php echo esc_url(add_query_arg('fallback', $this->take_over_login_secret, wp_login_url())); ?>
                            </code>
                            <input type="hidden" name="openid_take_over_login_secret"
                                   value="<?php echo esc_attr(get_option('openid_take_over_login_secret')); ?>">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Login Button Text', 'openid'); ?>
                        </th>
                        <td>
                            <label>
                                <input type="text" name="openid_login_button_text"
                                       value="<?php echo esc_attr($this->login_button_text); ?>"
                                       size="40"<?php echo esc_attr(defined('WP_OPENID_LOGIN_BUTTON_TEXT') ? ' disabled readonly' : ''); ?>>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Login Separator Text', 'openid'); ?>
                        </th>
                        <td>
                            <label>
                                <input type="text" name="openid_login_separator_text"
                                       value="<?php echo esc_attr($this->login_separator_text); ?>"
                                       size="40"<?php echo esc_attr(defined('WP_OPENID_LOGIN_SEPARATOR_TEXT') ? ' disabled readonly' : ''); ?>>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Login Page Image', 'openid'); ?>
                        </th>
                        <td>
                            <table>
                                <tr>
                                    <td>
                                        <img id="openid_image_preview"
                                             src="<?php echo esc_url($this->login_image); ?>"
                                             style="max-width: 150px; height: auto;" alt="Login page image"
                                             data-default-image="<?php echo esc_url($this->default_image); ?>"/>
                                    </td>
                                </tr>
                                <tr>
                                    <td>
                                        <input type="hidden" name="openid_login_image_id" id="openid_login_image_id"
                                               value="<?php echo esc_attr($this->login_image_id); ?>"
                                               class="regular-text"/>
                                        <input type='button' class="button-primary"
                                               value="<?php esc_attr_e('Select Image', 'openid'); ?>"
                                               id="openid_media_manager"/>
                                        <input type='button' class="button-link-delete"
                                               value="<?php esc_attr_e('Remove Image', 'openid'); ?>"
                                               id="openid_remove_image"/>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>

                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

    public function save_settings(): void
    {
        // We need to check the nonce here because to make sure the user intended to change these values.
        if (!isset($_POST['_wpnonce']) || !wp_verify_nonce($_POST['_wpnonce'], 'openid-options')) {
            wp_die(esc_html__('Invalid nonce.', 'openid'));
        }

        // Check permissions
        if (!current_user_can('manage_network_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'openid'));
        }

        // Check the referer
        check_admin_referer('openid-options');

        // Validate and save the settings
        update_site_option('openid_metadata_url', esc_url_raw(filter_var($_POST['openid_metadata_url'], FILTER_VALIDATE_URL) ?? '', ['https']));
        update_site_option('openid_client_id', sanitize_text_field($_POST['openid_client_id'] ?? ''));
        update_site_option('openid_client_secret', sanitize_text_field($_POST['openid_client_secret'] ?? ''));
        update_site_option('openid_default_role', sanitize_text_field($_POST['openid_default_role'] ?? ''));
        update_site_option('openid_user_mapping', sanitize_text_field($_POST['openid_user_mapping'] ?? ''));

        // Redirect back to the settings page
        wp_redirect($_POST['_wp_http_referer']);
    }

    public function deactivate(): void
    {
        if ($this->is_network) {
            delete_site_option('openid_metadata_url');
            delete_site_option('openid_client_id');
            delete_site_option('openid_client_secret');
            delete_site_option('default_role');
            delete_site_option('user_mapping');
        } else {
            delete_option('openid_metadata_url');
            delete_option('openid_client_id');
            delete_option('openid_client_secret');
            delete_option('openid_default_role');
            delete_option('openid_user_mapping');
        }
    }

    private function _get_metadata(): array
    {
        // validate the url has been set
        if (!$this->metadata_url) {
            return [];
        }

        // We cache on the hash of the url, to expire the cache if its changed
        $hash = md5($this->metadata_url);

        // if we have it cached, use that, if not - cache it
        $metadata = get_transient('openid_metadata_' . $hash);
        if (empty($metadata)) {
            $response = wp_remote_get($this->metadata_url);
            if (is_wp_error($response)) {
                return ['error' => $response->get_error_message()];
            }

            // grab the decoded body
            $metadata = json_decode(wp_remote_retrieve_body($response), true);

            // we don't want to cache an empty result, so this is needed
            if (empty($metadata)) {
                return [];
            }

            // cache for 2 hrs
            set_transient('openid_metadata_' . $hash, $metadata, 24 * HOUR_IN_SECONDS);
        }

        return $metadata;
    }

    private function _render_attribute_select(string $option): void
    {
        ?>
        <label>
            <select name="openid_user_mapping[<?= $option ?>]">
                <option value="">— <?php esc_html_e('Do not map', 'openid'); ?> —</option>
                <?php foreach ($this->user_fields as $name) { ?>
                    <option value="<?php echo esc_attr($name); ?>"<?php selected($this->user_mapping[$option] ?? false, $name); ?>>
                        <?php echo esc_html($name); ?>
                    </option>
                <?php } ?>
            </select>
        </label>
        <?php
    }

    /**
     * @throws Exception
     */
    private function _create_oauth_state(): array
    {
        // If we have a session cookie, delete it.
        if (isset($_COOKIE['openid_session'])) {
            delete_transient('openid_oauth_state_' . $_COOKIE['openid_session']);
        }

        // Create a random hash for the user, and store it in a cookie.
        $session = bin2hex(random_bytes(32));
        setcookie('openid_session', $session, time() + 3600);

        // Create a random state and verifier
        $oauth_state = [
            'state' => bin2hex(random_bytes(10)),
            'verifier' => bin2hex(random_bytes(50)),
        ];

        // Store the state and verifier in a transient, so we can verify the response later.
        set_transient('openid_oauth_state_' . $session, $oauth_state, 60 * MINUTE_IN_SECONDS);

        return $oauth_state;
    }

    /**
     * @return array|false
     */
    private function _get_oauth_state()
    {
        // Return the state and verifier from the transient, if it exists.
        if (isset($_COOKIE['openid_session'])) {
            return get_transient('openid_oauth_state_' . $_COOKIE['openid_session']) ?? false;
        }

        return false;
    }

    private function _delete_oauth_state(): void
    {
        // Delete the state and verifier from the transient, if it exists.
        if (isset($_COOKIE['openid_session'])) {
            delete_transient('openid_oauth_state_' . $_COOKIE['openid_session']);
        }

        // Delete the session cookie
        setcookie('openid_session', '', time() - 3600);
    }
}
