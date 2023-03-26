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

    public function __construct()
    {
        $this->is_network = is_plugin_active_for_network('wp-openid');
        $this->metadata_url = defined('WP_OPENID_METADATA_URL') ? WP_OPENID_METADATA_URL : ($this->is_network ? get_site_option('openid_metadata_url') : get_option('openid_metadata_url'));
        $this->client_id = defined('WP_OPENID_CLIENT_ID') ? WP_OPENID_CLIENT_ID : ($this->is_network ? get_site_option('openid_client_id') : get_option('openid_client_id'));
        $this->client_secret = defined('WP_OPENID_CLIENT_SECRET') ? WP_OPENID_CLIENT_SECRET : ($this->is_network ? get_site_option('openid_client_secret') : get_option('openid_client_secret'));
        $this->default_role = defined('WP_OPENID_DEFAULT_ROLE') ? WP_OPENID_DEFAULT_ROLE : ($this->is_network ? get_site_option('openid_default_role') : get_option('openid_default_role'));
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
        add_action('rest_api_init', [$this, 'rest_api_init']);
        add_action('login_message', [$this, 'openid_login_page_button']);
        add_action('admin_init', [$this, 'admin_init']);
        add_action('admin_menu', [$this, 'admin_menu'], 99);

        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
    }

    public function rest_api_init(): void
    {
        register_rest_route('openid', '/login', array(
            'methods' => 'GET',
            'callback' => array($this, 'login_redirect'),
        ));

        register_rest_route('openid', '/callback', array(
            'methods' => 'GET',
            'callback' => array($this, 'login_callback'),
        ));

    }

    /**
     * @throws Exception
     */
    public function login_redirect(): WP_REST_Response
    {
        // Redirect to OpenID , passing the state and nonce
        // Implementation taken from: https://developer.openid.com/docs/guides/sign-into-web-app-redirect/php/main/#redirect-to-the-sign-in-page

        $state = $this->_create_oauth_state();

        // Create the PKCE code verifier and code challenge
        $hash = hash('sha256', $state['verifier'], true);
        $code_challenge = rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');

        $response = new WP_REST_Response();
        $response->set_status(302);
        $response->header('Location', $this->metadata['authorization_endpoint'] . '?' . http_build_query([
                'response_type' => 'code',
                'client_id' => $this->client_id,
                'state' => $state['state'],
                'redirect_uri' => rest_url('/openid/callback'),
                'code_challenge' => $code_challenge,
                'code_challenge_method' => 'S256',
                'scope' => 'openid profile email',
            ]));

        return $response;
    }

    public function login_callback(): WP_REST_Response
    {
        if (!$state = $this->_get_oauth_state()) {
            die("state not found2");
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
                'redirect_uri' => rest_url('/openid/callback'),
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
                    background-image: url(data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+CjxzdmcKICAgeG1sbnM6c3ZnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIKICAgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIgogICB2ZXJzaW9uPSIxLjAiCiAgIHdpZHRoPSIzMjAiCiAgIGhlaWdodD0iMTIwIgogICB2aWV3Qm94PSIwIDAgNjQ0MCA4MzM0IgogICBpZD0ic3ZnMjExNCIKICAgeG1sOnNwYWNlPSJwcmVzZXJ2ZSI+PGRlZnMKICAgaWQ9ImRlZnMyMTI3Ij4KICAgIAogICAgCiAgICAKICAgIAogICAgCiAgICAKICAgIAogICAgCiAgPC9kZWZzPgogIAo8ZwogICB0cmFuc2Zvcm09Im1hdHJpeCg2OS40NSwwLDAsNjkuNDUsLTg3NTkuNDc2LC05ODkuMzk2OSkiCiAgIGlkPSJnMjE4OSI+PGcKICAgICB0cmFuc2Zvcm09Im1hdHJpeCgxLjAzMTgwN2UtMiwwLDAsMS4wMzE4MDdlLTIsMTQzLjM2MjEsLTkwLjkxNTM3KSIKICAgICBpZD0iZzIyMDIiPjxwYXRoCiAgICAgICBkPSJNIC0zNDM2LjgsMTQ1NDMuMiBDIC00Mjg0LjgsMTQwMTUuMiAtNTQ2OC44LDEzNjg3LjIgLTY3NjQuOCwxMzY4Ny4yIEMgLTkzNzIuOCwxMzY4Ny4yIC0xMTQ4NC44LDE0OTkxLjIgLTExNDg0LjgsMTY1OTkuMiBDIC0xMTQ4NC44LDE4MDcxLjIgLTk3MjQuOCwxOTI3OS4yIC03NDQ0LjgsMTk0ODcuMiBMIC03NDQ0LjgsMTg2MzkuMiBDIC04OTgwLjgsMTg0NDcuMiAtMTAxMzIuOCwxNzYwNy4yIC0xMDEzMi44LDE2NTk5LjIgQyAtMTAxMzIuOCwxNTQ1NS4yIC04NjI4LjgsMTQ1MTkuMiAtNjc2NC44LDE0NTE5LjIgQyAtNTgzNi44LDE0NTE5LjIgLTQ5OTYuOCwxNDc1MS4yIC00Mzg4LjgsMTUxMjcuMiBMIC01MjUyLjgsMTU2NjMuMiBMIC0yNTU2LjgsMTU2NjMuMiBMIC0yNTU2LjgsMTM5OTkuMiBMIC0zNDM2LjgsMTQ1NDMuMiB6ICIKICAgICAgIHN0eWxlPSJmaWxsOiNjY2M7ZmlsbC1vcGFjaXR5OjEiCiAgICAgICBpZD0icGF0aDIyMDQiIC8+PHBhdGgKICAgICAgIGQ9Ik0gLTc0NDQuOCwxMjI0Ny4yIEwgLTc0NDQuOCwxODYzOS4yIEwgLTc0NDQuOCwxOTQ4Ny4yIEwgLTYwOTIuOCwxODYzOS4yIEwgLTYwOTIuOCwxMTM3NS4yIEwgLTc0NDQuOCwxMjI0Ny4yIHogIgogICAgICAgc3R5bGU9ImZpbGw6I2ZmNjIwMDtmaWxsLW9wYWNpdHk6MSIKICAgICAgIGlkPSJwYXRoMjIwNiIgLz48L2c+PGcKICAgICB0cmFuc2Zvcm09Im1hdHJpeCgxLjM3NzUyMWUtMiwwLDAsMS4zNzc1MjFlLTIsMTQyLjMyMDgsLTEzNS43MTMxKSIKICAgICBpZD0iZzIyMDgiPjxwYXRoCiAgICAgICBkPSJNIC0xMTI0LjgsMTUzNDMuMiBDIC0xMDYwLjgsMTUxMTkuMiAtOTU2LjgsMTQ5MjcuMiAtODIwLjgsMTQ3NTkuMiBDIC02NzYuOCwxNDU5MS4yIC01MDguOCwxNDQ1NS4yIC0zMDAuOCwxNDM1OS4yIEMgLTkyLjgsMTQyNTUuMiAxNDcuMiwxNDIwNy4yIDQxOS4yLDE0MjA3LjIgQyA2OTkuMiwxNDIwNy4yIDkzOS4yLDE0MjU1LjIgMTE0Ny4yLDE0MzU5LjIgQyAxMzQ3LjIsMTQ0NTUuMiAxNTIzLjIsMTQ1OTEuMiAxNjU5LjIsMTQ3NTkuMiBDIDE3OTUuMiwxNDkyNy4yIDE4OTkuMiwxNTExOS4yIDE5NjMuMiwxNTM0My4yIEMgMjAzNS4yLDE1NTU5LjIgMjA2Ny4yLDE1NzkxLjIgMjA2Ny4yLDE2MDMxLjIgQyAyMDY3LjIsMTYyNzEuMiAyMDM1LjIsMTY1MDMuMiAxOTYzLjIsMTY3MjcuMiBDIDE4OTkuMiwxNjk0My4yIDE3OTUuMiwxNzEzNS4yIDE2NTkuMiwxNzMwMy4yIEMgMTUyMy4yLDE3NDcxLjIgMTM0Ny4yLDE3NjA3LjIgMTE0Ny4yLDE3NzAzLjIgQyA5MzkuMiwxNzgwNy4yIDY5OS4yLDE3ODU1LjIgNDE5LjIsMTc4NTUuMiBDIDE0Ny4yLDE3ODU1LjIgLTkyLjgsMTc4MDcuMiAtMzAwLjgsMTc3MDMuMiBDIC01MDguOCwxNzYwNy4yIC02NzYuOCwxNzQ3MS4yIC04MjAuOCwxNzMwMy4yIEMgLTk1Ni44LDE3MTM1LjIgLTEwNjAuOCwxNjk0My4yIC0xMTI0LjgsMTY3MjcuMiBDIC0xMTk2LjgsMTY1MDMuMiAtMTIyOC44LDE2MjcxLjIgLTEyMjguOCwxNjAzMS4yIEMgLTEyMjguOCwxNTc5MS4yIC0xMTk2LjgsMTU1NTkuMiAtMTEyNC44LDE1MzQzLjIgTSAtODIwLjgsMTY1OTkuMiBDIC03NzIuOCwxNjc4My4yIC02OTIuOCwxNjk0My4yIC01ODAuOCwxNzA5NS4yIEMgLTQ3Ni44LDE3MjM5LjIgLTM0MC44LDE3MzUxLjIgLTE3Mi44LDE3NDQ3LjIgQyAtNC44LDE3NTM1LjIgMTg3LjIsMTc1NzUuMiA0MTkuMiwxNzU3NS4yIEMgNjUxLjIsMTc1NzUuMiA4NTEuMiwxNzUzNS4yIDEwMTkuMiwxNzQ0Ny4yIEMgMTE4Ny4yLDE3MzUxLjIgMTMxNS4yLDE3MjM5LjIgMTQyNy4yLDE3MDk1LjIgQyAxNTMxLjIsMTY5NDMuMiAxNjExLjIsMTY3ODMuMiAxNjU5LjIsMTY1OTkuMiBDIDE3MDcuMiwxNjQxNS4yIDE3MzkuMiwxNjIyMy4yIDE3MzkuMiwxNjAzMS4yIEMgMTczOS4yLDE1ODM5LjIgMTcwNy4yLDE1NjU1LjIgMTY1OS4yLDE1NDcxLjIgQyAxNjExLjIsMTUyODcuMiAxNTMxLjIsMTUxMTkuMiAxNDI3LjIsMTQ5NzUuMiBDIDEzMTUuMiwxNDgzMS4yIDExODcuMiwxNDcxMS4yIDEwMTkuMiwxNDYyMy4yIEMgODUxLjIsMTQ1MzUuMiA2NTEuMiwxNDQ5NS4yIDQxOS4yLDE0NDk1LjIgQyAxODcuMiwxNDQ5NS4yIC00LjgsMTQ1MzUuMiAtMTcyLjgsMTQ2MjMuMiBDIC0zNDAuOCwxNDcxMS4yIC00NzYuOCwxNDgzMS4yIC01ODAuOCwxNDk3NS4yIEMgLTY5Mi44LDE1MTE5LjIgLTc3Mi44LDE1Mjg3LjIgLTgyMC44LDE1NDcxLjIgQyAtODY4LjgsMTU2NTUuMiAtODkyLjgsMTU4MzkuMiAtODkyLjgsMTYwMzEuMiBDIC04OTIuOCwxNjIyMy4yIC04NjguOCwxNjQxNS4yIC04MjAuOCwxNjU5OS4yIHogIgogICAgICAgc3R5bGU9ImZpbGw6I2ZmNjIwMDtmaWxsLW9wYWNpdHk6MSIKICAgICAgIGlkPSJwYXRoMjIxMCIgLz48cGF0aAogICAgICAgZD0iTSAyNTYzLjIsMTUyNTUuMiBMIDI1NjMuMiwxNTczNS4yIEwgMjU3MS4yLDE1NzM1LjIgQyAyNjQzLjIsMTU1NTkuMiAyNzYzLjIsMTU0MjMuMiAyOTIzLjIsMTUzMjcuMiBDIDMwODMuMiwxNTIzMS4yIDMyNjcuMiwxNTE4My4yIDM0NzUuMiwxNTE4My4yIEMgMzY2Ny4yLDE1MTgzLjIgMzgzNS4yLDE1MjE1LjIgMzk3OS4yLDE1Mjg3LjIgQyA0MTIzLjIsMTUzNTkuMiA0MjQzLjIsMTU0NTUuMiA0MzM5LjIsMTU1ODMuMiBDIDQ0MjcuMiwxNTcwMy4yIDQ0OTkuMiwxNTg0Ny4yIDQ1NDcuMiwxNjAwNy4yIEMgNDU5NS4yLDE2MTY3LjIgNDYxOS4yLDE2MzQzLjIgNDYxOS4yLDE2NTE5LjIgQyA0NjE5LjIsMTY3MDMuMiA0NTk1LjIsMTY4NzEuMiA0NTQ3LjIsMTcwMzEuMiBDIDQ0OTkuMiwxNzE5MS4yIDQ0MjcuMiwxNzMzNS4yIDQzMzkuMiwxNzQ1NS4yIEMgNDI0My4yLDE3NTgzLjIgNDEyMy4yLDE3Njc5LjIgMzk3OS4yLDE3NzUxLjIgQyAzODM1LjIsMTc4MTUuMiAzNjY3LjIsMTc4NTUuMiAzNDc1LjIsMTc4NTUuMiBDIDMzNzkuMiwxNzg1NS4yIDMyOTEuMiwxNzgzOS4yIDMxOTUuMiwxNzgyMy4yIEMgMzEwNy4yLDE3Nzk5LjIgMzAxOS4yLDE3NzU5LjIgMjk0Ny4yLDE3NzE5LjIgQyAyODY3LjIsMTc2NzEuMiAyNzk1LjIsMTc2MTUuMiAyNzMxLjIsMTc1NDMuMiBDIDI2NzUuMiwxNzQ3OS4yIDI2MjcuMiwxNzM5OS4yIDI1OTUuMiwxNzMwMy4yIEwgMjU4Ny4yLDE3MzAzLjIgTCAyNTg3LjIsMTg3MTEuMiBMIDIyNzUuMiwxODcxMS4yIEwgMjI3NS4yLDE1MjU1LjIgTCAyNTYzLjIsMTUyNTUuMiBNIDQyNTkuMiwxNjEzNS4yIEMgNDIyNy4yLDE1OTk5LjIgNDE3OS4yLDE1ODg3LjIgNDExNS4yLDE1NzgzLjIgQyA0MDQzLjIsMTU2ODcuMiAzOTU1LjIsMTU1OTkuMiAzODUxLjIsMTU1MzUuMiBDIDM3NDcuMiwxNTQ3MS4yIDM2MjcuMiwxNTQ0Ny4yIDM0NzUuMiwxNTQ0Ny4yIEMgMzMwNy4yLDE1NDQ3LjIgMzE2My4yLDE1NDcxLjIgMzA1MS4yLDE1NTM1LjIgQyAyOTMxLjIsMTU1OTEuMiAyODQzLjIsMTU2NzEuMiAyNzcxLjIsMTU3NjcuMiBDIDI3MDcuMiwxNTg2My4yIDI2NTkuMiwxNTk4My4yIDI2MjcuMiwxNjExMS4yIEMgMjYwMy4yLDE2MjM5LjIgMjU4Ny4yLDE2Mzc1LjIgMjU4Ny4yLDE2NTE5LjIgQyAyNTg3LjIsMTY2NTUuMiAyNjAzLjIsMTY3ODMuMiAyNjM1LjIsMTY5MTEuMiBDIDI2NjcuMiwxNzAzOS4yIDI3MTUuMiwxNzE1OS4yIDI3ODcuMiwxNzI1NS4yIEMgMjg1OS4yLDE3MzU5LjIgMjk0Ny4yLDE3NDM5LjIgMzA1OS4yLDE3NTAzLjIgQyAzMTcxLjIsMTc1NjcuMiAzMzE1LjIsMTc1OTkuMiAzNDc1LjIsMTc1OTkuMiBDIDM2MjcuMiwxNzU5OS4yIDM3NDcuMiwxNzU2Ny4yIDM4NTEuMiwxNzUwMy4yIEMgMzk1NS4yLDE3NDM5LjIgNDA0My4yLDE3MzU5LjIgNDExNS4yLDE3MjU1LjIgQyA0MTc5LjIsMTcxNTkuMiA0MjI3LjIsMTcwMzkuMiA0MjU5LjIsMTY5MTEuMiBDIDQyOTEuMiwxNjc4My4yIDQzMDcuMiwxNjY1NS4yIDQzMDcuMiwxNjUxOS4yIEMgNDMwNy4yLDE2MzkxLjIgNDI5MS4yLDE2MjYzLjIgNDI1OS4yLDE2MTM1LjIgeiAiCiAgICAgICBzdHlsZT0iZmlsbDojZmY2MjAwO2ZpbGwtb3BhY2l0eToxIgogICAgICAgaWQ9InBhdGgyMjEyIiAvPjxwYXRoCiAgICAgICBkPSJNIDUxMzkuMiwxNjk1MS4yIEMgNTE3MS4yLDE3MDcxLjIgNTIxOS4yLDE3MTc1LjIgNTI5MS4yLDE3MjcxLjIgQyA1MzU1LjIsMTczNjcuMiA1NDQzLjIsMTc0NDcuMiA1NTQ3LjIsMTc1MDMuMiBDIDU2NTEuMiwxNzU2Ny4yIDU3NzkuMiwxNzU5OS4yIDU5MjMuMiwxNzU5OS4yIEMgNjE0Ny4yLDE3NTk5LjIgNjMyMy4yLDE3NTQzLjIgNjQ1MS4yLDE3NDIzLjIgQyA2NTc5LjIsMTczMDMuMiA2NjY3LjIsMTcxNTEuMiA2NzE1LjIsMTY5NTEuMiBMIDcwMjcuMiwxNjk1MS4yIEMgNjk2My4yLDE3MjM5LjIgNjg0My4yLDE3NDYzLjIgNjY2Ny4yLDE3NjE1LjIgQyA2NDkxLjIsMTc3NzUuMiA2MjQzLjIsMTc4NTUuMiA1OTIzLjIsMTc4NTUuMiBDIDU3MjMuMiwxNzg1NS4yIDU1NTUuMiwxNzgxNS4yIDU0MTEuMiwxNzc1MS4yIEMgNTI1OS4yLDE3Njc5LjIgNTE0Ny4yLDE3NTgzLjIgNTA1MS4yLDE3NDU1LjIgQyA0OTYzLjIsMTczMzUuMiA0ODkxLjIsMTcxOTEuMiA0ODUxLjIsMTcwMzEuMiBDIDQ4MDMuMiwxNjg3MS4yIDQ3ODcuMiwxNjcwMy4yIDQ3ODcuMiwxNjUxOS4yIEMgNDc4Ny4yLDE2MzUxLjIgNDgwMy4yLDE2MTkxLjIgNDg1MS4yLDE2MDMxLjIgQyA0ODkxLjIsMTU4NzEuMiA0OTYzLjIsMTU3MjcuMiA1MDUxLjIsMTU1OTkuMiBDIDUxNDcuMiwxNTQ3MS4yIDUyNTkuMiwxNTM3NS4yIDU0MTEuMiwxNTI5NS4yIEMgNTU1NS4yLDE1MjIzLjIgNTcyMy4yLDE1MTgzLjIgNTkyMy4yLDE1MTgzLjIgQyA2MTIzLjIsMTUxODMuMiA2Mjk5LjIsMTUyMjMuMiA2NDQzLjIsMTUzMDMuMiBDIDY1ODcuMiwxNTM4My4yIDY3MDcuMiwxNTQ5NS4yIDY3OTUuMiwxNTYyMy4yIEMgNjg4My4yLDE1NzU5LjIgNjk0Ny4yLDE1OTExLjIgNjk4Ny4yLDE2MDc5LjIgQyA3MDI3LjIsMTYyNDcuMiA3MDQzLjIsMTY0MjMuMiA3MDM1LjIsMTY1OTkuMiBMIDUwOTEuMiwxNjU5OS4yIEMgNTA5MS4yLDE2NzExLjIgNTEwNy4yLDE2ODMxLjIgNTEzOS4yLDE2OTUxLjIgTSA2NjY3LjIsMTYwMDcuMiBDIDY2MjcuMiwxNTg5NS4yIDY1NzEuMiwxNTc5OS4yIDY1MDcuMiwxNTcxOS4yIEMgNjQzNS4yLDE1NjM5LjIgNjM1NS4yLDE1NTY3LjIgNjI1OS4yLDE1NTE5LjIgQyA2MTU1LjIsMTU0NzEuMiA2MDUxLjIsMTU0NDcuMiA1OTIzLjIsMTU0NDcuMiBDIDU3OTUuMiwxNTQ0Ny4yIDU2ODMuMiwxNTQ3MS4yIDU1ODcuMiwxNTUxOS4yIEMgNTQ5MS4yLDE1NTY3LjIgNTQwMy4yLDE1NjM5LjIgNTMzOS4yLDE1NzE5LjIgQyA1MjY3LjIsMTU3OTkuMiA1MjExLjIsMTU4OTUuMiA1MTcxLjIsMTYwMDcuMiBDIDUxMzEuMiwxNjExMS4yIDUxMDcuMiwxNjIyMy4yIDUwOTEuMiwxNjM0My4yIEwgNjcyMy4yLDE2MzQzLjIgQyA2NzIzLjIsMTYyMjMuMiA2Njk5LjIsMTYxMTEuMiA2NjY3LjIsMTYwMDcuMiB6ICIKICAgICAgIHN0eWxlPSJmaWxsOiNmZjYyMDA7ZmlsbC1vcGFjaXR5OjEiCiAgICAgICBpZD0icGF0aDIyMTQiIC8+PHBhdGgKICAgICAgIGQ9Ik0gNzQ5OS4yLDE1MjU1LjIgTCA3NDk5LjIsMTU2ODcuMiBMIDc1MDcuMiwxNTY4Ny4yIEMgNzU3MS4yLDE1NTM1LjIgNzY3NS4yLDE1NDE1LjIgNzgyNy4yLDE1MzE5LjIgQyA3OTcxLjIsMTUyMzEuMiA4MTM5LjIsMTUxODMuMiA4MzIzLjIsMTUxODMuMiBDIDg0OTkuMiwxNTE4My4yIDg2NDMuMiwxNTIwNy4yIDg3NjMuMiwxNTI0Ny4yIEMgODg4My4yLDE1Mjk1LjIgODk3OS4yLDE1MzU5LjIgOTA1MS4yLDE1NDQ3LjIgQyA5MTIzLjIsMTU1MjcuMiA5MTcxLjIsMTU2MzEuMiA5MjAzLjIsMTU3NTEuMiBDIDkyMzUuMiwxNTg3MS4yIDkyNDMuMiwxNjAwNy4yIDkyNDMuMiwxNjE1OS4yIEwgOTI0My4yLDE3NzgzLjIgTCA4OTM5LjIsMTc3ODMuMiBMIDg5MzkuMiwxNjIwNy4yIEMgODkzOS4yLDE2MDk1LjIgODkzMS4yLDE1OTk5LjIgODkwNy4yLDE1OTAzLjIgQyA4ODkxLjIsMTU4MTUuMiA4ODUxLjIsMTU3MzUuMiA4ODAzLjIsMTU2NjMuMiBDIDg3NTUuMiwxNTU5MS4yIDg2OTEuMiwxNTU0My4yIDg2MDMuMiwxNTUwMy4yIEMgODUyMy4yLDE1NDYzLjIgODQxOS4yLDE1NDQ3LjIgODI5OS4yLDE1NDQ3LjIgQyA4MTcxLjIsMTU0NDcuMiA4MDU5LjIsMTU0NjMuMiA3OTYzLjIsMTU1MTEuMiBDIDc4NjcuMiwxNTU1MS4yIDc3ODcuMiwxNTYxNS4yIDc3MjMuMiwxNTY4Ny4yIEMgNzY1MS4yLDE1NzY3LjIgNzYwMy4yLDE1ODU1LjIgNzU2My4yLDE1OTY3LjIgQyA3NTIzLjIsMTYwNzEuMiA3NTA3LjIsMTYxODMuMiA3NDk5LjIsMTYzMTEuMiBMIDc0OTkuMiwxNzc4My4yIEwgNzE5NS4yLDE3NzgzLjIgTCA3MTk1LjIsMTUyNTUuMiBMIDc0OTkuMiwxNTI1NS4yIHogIgogICAgICAgc3R5bGU9ImZpbGw6I2ZmNjIwMDtmaWxsLW9wYWNpdHk6MSIKICAgICAgIGlkPSJwYXRoMjIxNiIgLz48cGF0aAogICAgICAgZD0iTSA5ODM1LjIsMTQyODcuMiBMIDk4MzUuMiwxNzc4My4yIEwgOTUwNy4yLDE3NzgzLjIgTCA5NTA3LjIsMTQyODcuMiBMIDk4MzUuMiwxNDI4Ny4yIHogIgogICAgICAgc3R5bGU9ImZpbGw6I2ZmNjIwMDtmaWxsLW9wYWNpdHk6MSIKICAgICAgIGlkPSJwYXRoMjIxOCIgLz48cGF0aAogICAgICAgZD0iTSAxMTI5OS4yLDE0Mjg3LjIgQyAxMTgzNS4yLDE0Mjk1LjIgMTIyMzUuMiwxNDQ0Ny4yIDEyNTA3LjIsMTQ3MzUuMiBDIDEyNzcxLjIsMTUwMjMuMiAxMjkwNy4yLDE1NDU1LjIgMTI5MDcuMiwxNjAzMS4yIEMgMTI5MDcuMiwxNjYxNS4yIDEyNzcxLjIsMTcwNDcuMiAxMjUwNy4yLDE3MzM1LjIgQyAxMjIzNS4yLDE3NjIzLjIgMTE4MzUuMiwxNzc2Ny4yIDExMjk5LjIsMTc3ODMuMiBMIDEwMDkxLjIsMTc3ODMuMiBMIDEwMDkxLjIsMTQyODcuMiBMIDExMjk5LjIsMTQyODcuMiBNIDExMTM5LjIsMTc0OTUuMiBDIDExMzg3LjIsMTc0OTUuMiAxMTYwMy4yLDE3NDcxLjIgMTE3ODcuMiwxNzQxNS4yIEMgMTE5NjMuMiwxNzM1OS4yIDEyMTE1LjIsMTcyNzkuMiAxMjIzNS4yLDE3MTU5LjIgQyAxMjM0Ny4yLDE3MDM5LjIgMTI0MzUuMiwxNjg4Ny4yIDEyNDkxLjIsMTY3MDMuMiBDIDEyNTQ3LjIsMTY1MTkuMiAxMjU3MS4yLDE2Mjk1LjIgMTI1NzEuMiwxNjAzMS4yIEMgMTI1NzEuMiwxNTc3NS4yIDEyNTQ3LjIsMTU1NTEuMiAxMjQ5MS4yLDE1MzY3LjIgQyAxMjQzNS4yLDE1MTc1LjIgMTIzNDcuMiwxNTAyMy4yIDEyMjM1LjIsMTQ5MTEuMiBDIDEyMTE1LjIsMTQ3OTEuMiAxMTk2My4yLDE0NzAzLjIgMTE3ODcuMiwxNDY1NS4yIEMgMTE2MDMuMiwxNDU5OS4yIDExMzg3LjIsMTQ1NjcuMiAxMTEzOS4yLDE0NTY3LjIgTCAxMDQyNy4yLDE0NTY3LjIgTCAxMDQyNy4yLDE3NDk1LjIgTCAxMTEzOS4yLDE3NDk1LjIgeiAiCiAgICAgICBzdHlsZT0iZmlsbDojZmY2MjAwO2ZpbGwtb3BhY2l0eToxIgogICAgICAgaWQ9InBhdGgyMjIwIiAvPjwvZz48L2c+PC9zdmc+);
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
                <a href="<?php echo esc_url(rest_url('/openid/login')); ?>" class="button">
                    <?php printf(
                        esc_html__('Log In with %s', 'openid'),
                        esc_html('OpenID')
                    ); ?>
                </a>
            </form>
            <p style="margin-top: 20px; text-align: center;">
                <?php esc_html_e('--- or ---', 'openid'); ?>
            </p>
            <?php
        }
    }

    public function admin_init(): void
    {
        register_setting('openid', 'openid_metadata_url');
        register_setting('openid', 'openid_client_id');
        register_setting('openid', 'openid_client_secret');
        register_setting('openid', 'openid_default_role');
        register_setting('openid', 'openid_user_mapping');


        add_action('network_admin_edit_openid', [$this, 'save_settings']);

        add_filter('plugin_action_links_wp-openid/wp-openid.php', fn($links) => [
            ...$links,
            sprintf(
                '<a href="%s">%s</a>',
                esc_url($this->is_network ? network_admin_url('settings.php?page=openid') : admin_url('options-general.php?page=openid')),
                esc_html__('Settings', 'openid')
            ),
        ]);
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
                            <code><?php echo esc_url(rest_url('/openid/callback')); ?></code>
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
                            <code><?php echo esc_url(rest_url('/openid/login')); ?></code>
                        </td>
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
