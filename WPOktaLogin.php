<?php

class WPOktaLogin
{
    private ?string $org_url;

    private ?string $client_id;

    private ?string $client_secret;

    private ?bool $is_network;

    public function __construct()
    {
        $this->is_network = is_plugin_active_for_network('wp-okta');
        $this->org_url = defined('WP_OKTA_DOMAIN') ? WP_OKTA_DOMAIN : ($this->is_network ? get_site_option('okta_org_url') : get_option('okta_org_url'));
        $this->client_id = defined('WP_OKTA_CLIENT_ID') ? WP_OKTA_CLIENT_ID : ($this->is_network ? get_site_option('okta_client_id') : get_option('okta_client_id'));
        $this->client_secret = defined('WP_OKTA_CLIENT_SECRET') ? WP_OKTA_CLIENT_SECRET : ($this->is_network ? get_site_option('okta_client_secret') : get_option('okta_client_secret'));
    }

    public function boot(): void
    {
        add_action('init', [$this, 'start_session']);
        add_action('rest_api_init', [$this, 'rest_api_init']);
        add_action('login_message', [$this, 'login_message']);
        add_action('admin_init', [$this, 'admin_init']);
        add_action('admin_menu', [$this, 'admin_menu'], 99);

        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
    }

    public function start_session(): void
    {
        if (!session_id()) {
            session_start();
        }
    }

    public function rest_api_init(): void
    {
        register_rest_route('okta', '/login', array(
            'methods' => 'GET',
            'callback' => array($this, 'login_redirect'),
        ));

        register_rest_route('okta', '/callback', array(
            'methods' => 'GET',
            'callback' => array($this, 'login_callback'),
        ));

    }

    /**
     * @throws Exception
     */
    public function login_redirect(): WP_REST_Response
    {
        // Redirect to Okta, passing the state and nonce
        // Implementation taken from: https://developer.okta.com/docs/guides/sign-into-web-app-redirect/php/main/#redirect-to-the-sign-in-page
        $_SESSION['oauth_state'] = bin2hex(random_bytes(10));

        // Create the PKCE code verifier and code challenge
        $_SESSION['oauth_code_verifier'] = bin2hex(random_bytes(50));
        $hash = hash('sha256', $_SESSION['oauth_code_verifier'], true);
        $code_challenge = rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');

        $response = new WP_REST_Response();

        $response->set_status(302);
        $response->header('Location', $this->org_url . 'oauth2/v1/authorize?' . http_build_query([
                'response_type' => 'code',
                'client_id' => $this->client_id,
                'state' => $_SESSION['oauth_state'],
                'redirect_uri' => rest_url('/okta/callback'),
                'code_challenge' => $code_challenge,
                'code_challenge_method' => 'S256',
                'scope' => 'openid profile email',
            ]));

        return $response;

    }

    public function login_callback(): WP_REST_Response
    {
        // Check the state
        if (empty($_GET['state']) || $_GET['state'] != $_SESSION['oauth_state']) {
            die("state does not match");
        }

        if (!empty($_GET['error'])) {
            die("authorization server returned an error: " . $_GET['error']);
        }

        if (empty($_GET['code'])) {
            die("this is unexpected, the authorization server redirected without a code or an  error");
        }

        // Exchange the authorization code for an access token by making a request to the token endpoint
        $token = $this->_get_token($_GET['code']);

        // Because we've asked Okta for the openid scope, the response will contain an id_token
        // We do not need to validate the token, as it's been retrieved from Okta.
        // We can just decode it and use it.
        if (empty($token['id_token'])) {
            die("No id_token returned");
        }

        $claim = json_decode(base64_decode(explode('.', $token['id_token'])[1]), true);

        // Grab the user, or create it if it doesn't exist
        $user = $this->_user_from_claim($claim);

        // Log the user in
        $this->_login_user($user);

        // Redirect to the admin dashboard
        $response = new WP_REST_Response();
        $response->set_status(302);
        $response->header('Location', $this->is_network ? network_admin_url() : admin_url());
        return $response;
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
        $response = wp_safe_remote_post($this->org_url . '/oauth2/v1/token', [
            'headers' => [
                'Accept' => 'application/json',
                'Content-Type' => 'application/x-www-form-urlencoded'
            ],
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => rest_url('/okta/callback'),
                'client_id' => $this->client_id,
                'client_secret' => $this->client_secret,
                'code_verifier' => $_SESSION['oauth_code_verifier']
            ],
            'sslverify' => true
        ]);

        if (is_wp_error($response)) {
            die("Error getting token: " . $response->get_error_message());
        }

        return json_decode($response['body'], true);
    }

    private function _user_from_claim(array $claim): WP_User
    {
        if (!$user = get_user_by('login', $claim['preferred_username'])) {
            $default_role = apply_filters('wp_okta_default_role', 'editor', $claim);

            // We don't have a user with this username, so create one
            $user_id = wp_insert_user([
                'user_login' => $claim['preferred_username'],
                'user_email' => $claim['email'],
                'user_pass' => wp_generate_password(),
                'nickname' => $claim['name'],
                'display_name' => $claim['name'],
                'role' => $default_role,
                'meta_input' => [
                    'okta_id' => $claim['sub']
                ],
            ]);

            if (is_wp_error($user_id)) {
                die("Error creating user: " . $user_id->get_error_message());
            }

            $user = get_user_by('id', $user_id);
        }

        return $user;
    }

    public function login_message(): void
    {
        ?>
        <style>
            .okta-logo {
                background-image: url(data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjxzdmcgdmVyc2lvbj0iMS4xIiBpZD0ibGF5ZXIiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHg9IjBweCIgeT0iMHB4Ig0KCSB2aWV3Qm94PSIwIDAgNjUyIDY1MiIgc3R5bGU9ImVuYWJsZS1iYWNrZ3JvdW5kOm5ldyAwIDAgNjUyIDY1MjsiIHhtbDpzcGFjZT0icHJlc2VydmUiPg0KPHN0eWxlIHR5cGU9InRleHQvY3NzIj4NCgkuc3Qwe2ZpbGw6IzE5MTkxOTt9DQo8L3N0eWxlPg0KPHBhdGggY2xhc3M9InN0MCIgZD0iTTU2NS4zLDM1Mi4xYy0xNi44LDAtMjguNi0xMy4xLTI4LjYtMzAuM2MwLTE3LjIsMTEuOC0zMC4zLDI4LjYtMzAuM2MxNi44LDAsMjguMiwxMy4xLDI4LjIsMzAuMw0KCUM1OTMuNiwzMzksNTgxLjksMzUyLjEsNTY1LjMsMzUyLjF6IE01NjIuNywzNzAuMWMxMy41LDAsMjUtNS4zLDMyLjMtMTYuM2MxLjQsMTAuNyw5LjEsMTQuNiwxOC45LDE0LjZoNy44di0xN2gtMy40DQoJYy01LjUsMC02LjktMi43LTYuOS05di02Ny4xaC0xNy45djEzLjhjLTYuMS05LjctMTcuNi0xNS41LTMwLjgtMTUuNWMtMjMuNSwwLTQ1LjEsMTkuNy00NS4xLDQ4LjINCglDNTE3LjUsMzUwLjMsNTM5LjIsMzcwLjEsNTYyLjcsMzcwLjFMNTYyLjcsMzcwLjF6IE00NzAuNCwzNDYuOGMwLDE1LjMsOS41LDIxLjYsMjAuOCwyMS42SDUxM3YtMTdoLTE1LjljLTYuNiwwLTgtMi41LTgtOXYtNTAuMg0KCUg1MTN2LTE3aC0yMy44VjI0NGgtMTguN0M0NzAuNCwyNDQsNDcwLjQsMzQ2LjgsNDcwLjQsMzQ2Ljh6IE0zODUuMSwzNjguNGgxOC43di0zOS45aDYuM2wzMS45LDM5LjloMjMuN0w0MjUsMzE3LjhsMzEuMy00Mi41DQoJaC0yMS4xbC0yNS41LDM1LjloLTUuOFYyNDRoLTE4LjdDMzg1LjEsMjQ0LDM4NS4xLDM2OC40LDM4NS4xLDM2OC40eiBNMzI0LjMsMjczLjZjLTI2LjIsMC00Ny44LDE5LjctNDcuOCw0OC4yDQoJczIxLjYsNDguMiw0Ny44LDQ4LjJzNDcuOC0xOS43LDQ3LjgtNDguMlMzNTAuNCwyNzMuNiwzMjQuMywyNzMuNnogTTMyNC4zLDM1Mi4xYy0xNi44LDAtMjguNi0xMy4xLTI4LjYtMzAuM3MxMS44LTMwLjMsMjguNi0zMC4zDQoJczI4LjYsMTMuMSwyOC42LDMwLjNTMzQxLDM1Mi4xLDMyNC4zLDM1Mi4xeiIvPg0KPHBhdGggY2xhc3M9InN0MCIgZD0iTTEzMC40LDIyMy41bC00LjEsNTAuMWMtMS45LTAuMi0zLjgtMC4zLTUuOC0wLjNjLTIuNSwwLTQuOSwwLjItNy4zLDAuNWwtMi4zLTI0LjNjLTAuMS0wLjgsMC41LTEuNCwxLjMtMS40DQoJaDQuMWwtMi0yNC42Yy0wLjEtMC44LDAuNS0xLjQsMS4zLTEuNGgxMy41QzEyOS45LDIyMi4xLDEzMC41LDIyMi44LDEzMC40LDIyMy41TDEzMC40LDIyMy41TDEzMC40LDIyMy41eiBNOTYuNCwyMjYNCgljLTAuMi0wLjctMS0xLjItMS43LTAuOWwtMTIuNiw0LjZjLTAuNywwLjMtMSwxLjEtMC43LDEuOGwxMC4zLDIyLjRsLTMuOSwxLjRjLTAuNywwLjMtMSwxLjEtMC43LDEuOGwxMC41LDIyDQoJYzMuOC0yLjEsNy45LTMuNywxMi4zLTQuN0w5Ni40LDIyNkw5Ni40LDIyNnogTTY1LjQsMjM5LjlsMjkuMSw0MWMtMy43LDIuNC03LDUuMy05LjksOC42bC0xNy40LTE3LjFjLTAuNS0wLjUtMC41LTEuNCwwLjEtMS45DQoJbDMuMi0yLjZsLTE3LjMtMTcuNWMtMC41LTAuNS0wLjUtMS40LDAuMS0xLjlsMTAuMy04LjZDNjQuMSwyMzkuMiw2NC45LDIzOS4zLDY1LjQsMjM5LjlMNjUuNCwyMzkuOXogTTQxLDI2My42DQoJYy0wLjYtMC40LTEuNS0wLjItMS45LDAuNGwtNi43LDExLjZjLTAuNCwwLjctMC4xLDEuNSwwLjUsMS44bDIyLjMsMTAuNWwtMi4xLDMuNmMtMC40LDAuNy0wLjEsMS41LDAuNiwxLjhMNzYsMzAzLjYNCgljMS42LTQuMSwzLjctOCw2LjQtMTEuNEw0MSwyNjMuNnogTTI0LjYsMjk1LjNjMC4xLTAuOCwwLjktMS4yLDEuNi0xbDQ4LjYsMTIuN2MtMS4zLDQuMS0yLDguNS0yLjEsMTNsLTI0LjMtMg0KCWMtMC44LTAuMS0xLjMtMC44LTEuMi0xLjVsMC43LTQuMUwyMy40LDMxMGMtMC44LTAuMS0xLjMtMC44LTEuMi0xLjVMMjQuNiwyOTUuM0wyNC42LDI5NS4zTDI0LjYsMjk1LjN6IE0yMi44LDMyOC4yDQoJYy0wLjgsMC4xLTEuMywwLjgtMS4yLDEuNWwyLjQsMTMuMmMwLjEsMC44LDAuOSwxLjIsMS42LDFsMjMuOC02LjJsMC43LDQuMWMwLjEsMC44LDAuOSwxLjIsMS42LDFsMjMuNS02LjUNCgljLTEuNC00LjEtMi4zLTguNC0yLjUtMTIuOUwyMi44LDMyOC4yTDIyLjgsMzI4LjJ6IE0zMC42LDM2M2MtMC40LTAuNy0wLjEtMS41LDAuNS0xLjhsNDUuNC0yMS41YzEuNyw0LjEsNCw3LjksNi44LDExLjMNCglsLTE5LjksMTQuMmMtMC42LDAuNC0xLjUsMC4zLTEuOS0wLjRsLTIuMS0zLjZsLTIwLjMsMTRjLTAuNiwwLjQtMS41LDAuMi0xLjktMC40TDMwLjYsMzYzTDMwLjYsMzYzeiBNODUuNiwzNTMuNWwtMzUuMywzNS44DQoJYy0wLjUsMC41LTAuNSwxLjQsMC4xLDEuOWwxMC4zLDguNmMwLjYsMC41LDEuNCwwLjQsMS45LTAuMmwxNC4zLTIwLjFsMy4yLDIuN2MwLjYsMC41LDEuNSwwLjQsMS45LTAuM2wxMy44LTIwLjENCglDOTIuMSwzNTkuNSw4OC42LDM1Ni43LDg1LjYsMzUzLjVMODUuNiwzNTMuNXogTTc4LjYsNDExYy0wLjctMC4zLTEtMS4xLTAuNy0xLjhsMjAuOS00NS43YzMuOCwyLDgsMy41LDEyLjQsNC4zbC02LjIsMjMuNg0KCWMtMC4yLDAuNy0xLDEuMi0xLjcsMC45bC0zLjktMS40bC02LjUsMjMuOGMtMC4yLDAuNy0xLDEuMi0xLjcsMC45TDc4LjYsNDExTDc4LjYsNDExTDc4LjYsNDExeiBNMTE0LjYsMzY4LjRsLTQuMSw1MC4xDQoJYy0wLjEsMC44LDAuNSwxLjQsMS4zLDEuNGgxMy41YzAuOCwwLDEuNC0wLjcsMS4zLTEuNGwtMi0yNC42aDQuMWMwLjgsMCwxLjQtMC43LDEuMy0xLjRsLTIuMy0yNC4zYy0yLjQsMC40LTQuOCwwLjUtNy4zLDAuNQ0KCUMxMTguNSwzNjguOCwxMTYuNiwzNjguNiwxMTQuNiwzNjguNEwxMTQuNiwzNjguNHogTTE2My4xLDIzMi43YzAuMy0wLjcsMC0xLjUtMC43LTEuOGwtMTIuNi00LjZjLTAuNy0wLjMtMS41LDAuMi0xLjcsMC45DQoJbC02LjUsMjMuOGwtMy45LTEuNGMtMC43LTAuMy0xLjUsMC4yLTEuNywwLjlsLTYuMiwyMy42YzQuNCwwLjksOC41LDIuNCwxMi40LDQuM0wxNjMuMSwyMzIuN0wxNjMuMSwyMzIuN3ogTTE5MC43LDI1Mi43DQoJbC0zNS4zLDM1LjhjLTMtMy4yLTYuNC02LTEwLjItOC4zTDE1OSwyNjBjMC40LTAuNiwxLjMtMC44LDEuOS0wLjNsMy4yLDIuN2wxNC4zLTIwLjFjMC40LTAuNiwxLjMtMC43LDEuOS0wLjJsMTAuMyw4LjYNCglDMTkxLjIsMjUxLjIsMTkxLjIsMjUyLjEsMTkwLjcsMjUyLjdMMTkwLjcsMjUyLjd6IE0yMDkuOCwyODAuOGMwLjctMC4zLDAuOS0xLjIsMC41LTEuOGwtNi44LTExLjZjLTAuNC0wLjctMS4zLTAuOC0xLjktMC40DQoJbC0yMC4zLDE0bC0yLjEtMy42Yy0wLjQtMC43LTEuMy0wLjktMS45LTAuNGwtMTkuOSwxNC4yYzIuNywzLjQsNSw3LjIsNi44LDExLjNMMjA5LjgsMjgwLjhMMjA5LjgsMjgwLjh6IE0yMTYuOSwyOTlsMi4zLDEzLjINCgljMC4xLDAuOC0wLjQsMS40LTEuMiwxLjVsLTUwLjEsNC43Yy0wLjItNC41LTEuMS04LjgtMi41LTEyLjlsMjMuNS02LjVjMC43LTAuMiwxLjUsMC4zLDEuNiwxbDAuNyw0LjFsMjMuOC02LjINCgljMC43LTAuMiwxLjUsMC4zLDEuNiwxbDAsMEwyMTYuOSwyOTl6IE0yMTQuNywzNDcuN2MwLjcsMC4yLDEuNS0wLjMsMS42LTFsMi4zLTEzLjJjMC4xLTAuOC0wLjQtMS40LTEuMi0xLjVsLTI0LjYtMi4zbDAuNy00LjENCgljMC4xLTAuOC0wLjQtMS40LTEuMi0xLjVsLTI0LjMtMmMtMC4xLDQuNS0wLjgsOC44LTIuMSwxM0wyMTQuNywzNDcuN0wyMTQuNywzNDcuN0wyMTQuNywzNDcuN3ogTTIwMS43LDM3Ny45DQoJYy0wLjQsMC43LTEuMywwLjgtMS45LDAuNGwtNDEuNC0yOC42YzIuNi0zLjUsNC44LTcuMyw2LjQtMTEuNGwyMi4yLDEwLjJjMC43LDAuMywxLDEuMiwwLjYsMS44bC0yLjEsMy42bDIyLjMsMTAuNQ0KCWMwLjcsMC4zLDAuOSwxLjIsMC41LDEuOEwyMDEuNywzNzcuOUMyMDEuNywzNzcuOSwyMDEuNywzNzcuOSwyMDEuNywzNzcuOXogTTE0Ni40LDM2MWwyOS4xLDQxYzAuNCwwLjYsMS4zLDAuNywxLjksMC4ybDEwLjMtOC42DQoJYzAuNi0wLjUsMC42LTEuNCwwLjEtMS45bC0xNy4zLTE3LjVsMy4yLTIuNmMwLjYtMC41LDAuNi0xLjQsMC4xLTEuOWwtMTcuNC0xNy4xQzE1My4zLDM1NS43LDE1MCwzNTguNiwxNDYuNCwzNjFMMTQ2LjQsMzYxDQoJTDE0Ni40LDM2MXogTTE0Ni4xLDQxNi44Yy0wLjcsMC4zLTEuNS0wLjItMS43LTAuOWwtMTMuMy00OC41YzQuMy0xLDguNS0yLjYsMTIuMy00LjdsMTAuNSwyMmMwLjMsMC43LDAsMS41LTAuNywxLjhsLTMuOSwxLjQNCglsMTAuMywyMi40YzAuMywwLjcsMCwxLjUtMC43LDEuOEwxNDYuMSw0MTYuOEwxNDYuMSw0MTYuOEwxNDYuMSw0MTYuOHoiLz4NCjwvc3ZnPg0K);
                overflow: hidden;
                background-position: 50% 50%;
                background-repeat: no-repeat;
                background-size: cover;
                height: 100px;
            }
        </style>
        <form style="padding-bottom: 26px; text-align: center;">
            <div class="okta-logo"></div>
            <a href="<?php echo esc_url(rest_url('/okta/login')); ?>" class="button">
                <?php printf(
                    esc_html__('Log In with %s', 'okta'),
                    esc_html('Okta')
                ); ?>
            </a>
        </form>
        <p style="margin-top: 20px; text-align: center;">
            <?php esc_html_e('or', 'okta'); ?>
        </p>
        <?php

    }

    public function admin_init(): void
    {
        register_setting('okta', 'okta_org_url');
        register_setting('okta', 'okta_client_id');
        register_setting('okta', 'okta_client_secret');

        add_action('network_admin_edit_okta', [$this, 'save_settings']);
    }

    public function admin_menu(): void
    {
        add_options_page('Okta Authentication', 'Okta', $this->is_network ? 'manage_network_options' : 'manage_options', 'okta', [$this, 'settings_page']);
    }

    public function settings_page(): void
    {
        ?>
        <div class="wrap">
            <h1>
                <?php esc_html_e('Okta Authentication', 'okta'); ?>
            </h1>
            <form action="<?php echo esc_url($this->is_network ? network_admin_url('edit.php?action=okta') : admin_url('options.php')); ?>"
                  method="post" autocomplete="off">
                <?php settings_fields('okta'); ?>
                <?php do_settings_sections('okta'); ?>
                <p>
                    <a href="https://developer.okta.com/login" target="_blank">Sign in to your Okta organization</a>
                    with your administrator account. If you don't already have an Okta account, <a
                            href="https://developer.okta.com/signup/" target="_blank">sign up for a free developer
                        account</a>.

                </p>

                <h2 class="title">
                    <?php esc_html_e('Step 1', 'okta'); ?>
                </h2>
                <p>
                    Enter your Okta organization URL in the field below. This is the URL you use to sign in to your Okta
                    account. It will look something like <code>https://example.okta.com/</code>.
                </p>
                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Org URL', 'okta'); ?>
                        </th>
                        <td>
                            <label>
                                <input type="url" name="okta_org_url" value="<?php echo esc_url($this->org_url); ?>"
                                       size="40"<?php echo esc_attr(defined('OKTA_ORG_URL') ? ' disabled readonly' : ''); ?>>
                            </label>
                        </td>
                    </tr>
                </table>

                <h2 class="title">
                    <?php esc_html_e('Step 2', 'okta'); ?>
                </h2>
                <p>
                    From the Admin dashboard, go to <b>Applications</b> > <b>Applications</b>, then click <b>Create App
                        Integration</b>.
                </p>
                <p>
                    Click <b>Create App Integration</b> and select "OIDC - OpenID Connect" as the <b>Sign-in method</b>,
                    and "Web Application"
                    as the <b>Application Type</b>.
                </p>

                <p>
                    Click <b>Next</b> and enter the following values:
                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Name', 'okta'); ?>
                        </th>
                        <td>
                            <code><?php echo get_bloginfo(); ?></code>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Grant type', 'okta'); ?>
                        </th>
                        <td>
                            <code>Authorization Code</code>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Sign-in redirect URIs', 'okta'); ?>
                        </th>
                        <td>
                            <code><?php echo esc_url(rest_url('/okta/callback')); ?></code>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Sign-out redirect URIs', 'okta'); ?>
                        </th>
                        <td>
                            <code><?php echo esc_url(home_url()); ?></code>
                        </td>
                    </tr>
                </table>

                <h2 class="title">
                    <?php esc_html_e('Step 3', 'okta'); ?>
                </h2>
                <p>
                    Click Save, and then enter your Client ID and Client Secret in the fields below.
                </p>
                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Client ID', 'okta'); ?>
                        </th>
                        <td>
                            <label>
                                <input type="text" name="okta_client_id"
                                       value="<?php echo esc_attr($this->client_id); ?>"
                                       size="40"<?php echo esc_attr(defined('OKTA_CLIENT_ID') ? ' disabled readonly' : ''); ?>>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Client Secret', 'okta'); ?>
                        </th>
                        <td>
                            <label>
                                <input type="password" name="okta_client_secret"
                                       value="<?php echo esc_attr($this->client_secret); ?>"
                                       size="40"<?php echo esc_attr(defined('OKTA_CLIENT_SECRET') ? ' disabled readonly' : ''); ?>>
                            </label>
                        </td>
                    </tr>
                </table>

                <h2 class="title">
                    <?php esc_html_e('Step 4', 'okta'); ?>
                </h2>
                <p>
                    If you want to show this application in the Okta Dashboard, click <b>Edit</b> on the <b>General
                        Settings</b> tab and
                    enter the following values:
                </p>
                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Login initiated by', 'okta'); ?>
                        </th>
                        <td>
                            <code>Either Okta or App</code>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Application visibility', 'okta'); ?>
                        </th>
                        <td>
                            <code>Show in both the Okta End-User Dashboard and the Okta Admin Console</code>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <?php esc_html_e('Initiate login URI', 'okta'); ?>
                        </th>
                        <td>
                            <code><?php echo esc_url(rest_url('/okta/login')); ?></code>
                        </td>
                </table>

                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

    public function save_settings(): void
    {
        // We need to check the nonce here because to make sure the user intended to change these values.
        if (!isset($_POST['_wpnonce']) || !wp_verify_nonce($_POST['_wpnonce'], 'okta-options')) {
            wp_die(esc_html__('Invalid nonce.', 'okta'));
        }

        // Check permissions
        if (!current_user_can('manage_network_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'okta'));
        }

        // Check the referer
        check_admin_referer('okta-options');

        // Validate and save the settings
        update_site_option('okta_org_url', esc_url_raw(filter_var($_POST['okta_org_url'], FILTER_VALIDATE_URL) ?? '', ['https']));
        update_site_option('okta_client_id', sanitize_text_field($_POST['okta_client_id'] ?? ''));
        update_site_option('okta_client_secret', sanitize_text_field($_POST['okta_client_secret'] ?? ''));


        // Redirect back to the settings page
        wp_redirect($_POST['_wp_http_referer']);
    }

    public function deactivate(): void
    {
        if ($this->is_network) {
            delete_site_option('okta_org_url');
            delete_site_option('okta_client_id');
            delete_site_option('okta_client_secret');
        } else {
            delete_option('okta_org_url');
            delete_option('okta_client_id');
            delete_option('okta_client_secret');
        }
    }
}