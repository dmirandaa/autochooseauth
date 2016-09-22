<?php

/**
 * SimpleSAMLphp module for authentication against SQL database and LDAP in a single routine
 * @author Daniel Miranda <daniellopes at gmail.com>
 * @since 1.13
 * @version 1.0 <2015-11-13>
 */
class sspmod_autochooseauth_Auth_Source_AutoChoose extends sspmod_core_Auth_UserPassBase {

    private $config;
    private $info;

    /**
     *
     * @var string
     * You should change de random string below
     * On Unix use: cat /dev/urandom | tr -cd 'a-f0-9' | head -c 32
     */
    private $site_key = "5877ea39be7ee5c6bd9e6d2307ec18d3";

    /**
     * Database dsn
     * See the documentation for the various database drivers for information about the syntax:
     * http://www.php.net/manual/en/pdo.drivers.php
     * @var string
     */
    private $db_dsn;

    /**
     * Database username
     * @var string
     */
    private $db_username;

    /**
     * Database password
     * @var string
     */
    private $db_password;

    /**
     * Site key
     * Utilizado para gerar hash de autenticação
     * @var string
     */
    private $db_sitekey;

    /**
     * Indica se second step authentication está habilitado para esta conta
     * @var type 
     */
    private $db_token;

    /**
     * LDAP hostname
     * @var type 
     */
    private $ldap_hostname;

    /**
     *
     * @var type 
     */
    private $ldap_tls;

    /**
     *
     * @var type 
     */
    private $ldap_debug;

    /**
     *
     * @var type 
     */
    private $ldap_attributes;

    /**
     *
     * @var type 
     */
    private $ldap_search_enable;

    /**
     *
     * @var type 
     */
    private $ldap_search_base;

    /**
     *
     * @var type 
     */
    private $ldap_search_attributes;

    /**
     *
     * @var type 
     */
    private $ldap_search_username;

    /**
     *
     * @var type 
     */
    private $ldap_search_password;

    /**
     * Change/add constants bellow as needed
     * This constants are from the database we will check the user password
     */
    const TABLE_USERS = 'users';
    const FIELD_USERS_ID = 'id';
    const FIELD_USERS_LOGIN = 'login';
    const FIELD_USERS_FULL_NAME = 'full_name';
    const FIELD_USERS_EMAIL = 'email';
    const FIELD_USERS_PASSWORD_HASHED = 'password';
    const FIELD_USERS_SALT = 'salt';
    const FIELD_USERS_STATE = 'state';
    const VALUE_USERS_STATE_ACTIVE = 1;
    const VALUE_USERS_STATE_INACTIVE = 0;
    const FIELD_USERS_TOKEN = 'token';
    const VALUE_USERS_TOKEN_ACTIVE = 1;
    const VALUE_USERS_TOKEN_INACTIVE = 0;

    /**
     * Constructor
     * @param string $info
     * @param string $config
     * @throws Exception
     */
    public function __construct($info, &$config) {
        parent::__construct($info, $config);

        $this->config = $config;
        $this->info = $info;

        if (!is_string($config['db']['dsn'])) {
            throw new Exception($this->t('{autochooseauth:errors:descr_INVALID_DSN}'));
        }
        $this->db_dsn = $config['db']['dsn'];

        if (!is_string($config['db']['username'])) {
            throw new Exception($this->t('{autochooseauth:errors:descr_INVALID_DSN_USERNAME}'));
        }
        $this->db_username = $config['db']['username'];

        if (!is_string($config['db']['password'])) {
            throw new Exception($this->t('{autochooseauth:errors:descr_INVALID_DSN_PASSWORD}'));
        }
        $this->db_password = $config['db']['password'];

        if (!is_string($config['db']['sitekey'])) {
            throw new Exception($this->t('{autochooseauth:errors:descr_INVALID_SITEKEY}'));
        }
        $this->db_sitekey = $config['db']['sitekey'];

        $this->db_token = false;

        $this->ldap_tls = $config['ldap']['enable_tls'] ? $config['ldap']['enable_tls'] : false;

        $this->ldap_debug = $config['ldap']['debug'] ? $config['ldap']['debug'] : false;

        $this->ldap_search_enable = $config['ldap']['search.enable'] ? $config['ldap']['search.enable'] : false;

        if (!is_string($config['ldap']['hostname'])) {
            throw new Exception($this->t('{autochooseauth:errors:descr_INVALID_LDAP_HOSTNAME}'));
        }
        $this->ldap_hostname = $config['ldap']['hostname'];

        if (!count($config['ldap']['attributes'])) {
            throw new Exception($this->t('{autochooseauth:errors:descr_INVALID_LDAP_ATTRIBUTES}'));
        }
        $this->ldap_attributes = $config['ldap']['attributes'];

        if (!count($config['ldap']['search.base'])) {
            throw new Exception($this->t('{autochooseauth:errors:descr_INVALID_LDAP_SEARCH_BASE}'));
        }
        $this->ldap_search_base = $config['ldap']['search.base'];

        if (!count($config['ldap']['search.attributes'])) {
            throw new Exception($this->t('{autochooseauth:errors:descr_INVALID_LDAP_SEARCH_ATTRIBUTES}'));
        }
        $this->ldap_search_attributes = $config['ldap']['search.attributes'];

        if (!is_string($config['ldap']['search.username'])) {
            throw new Exception($this->t('{autochooseauth:errors:descr_INVALID_LDAP_SEARCH_USERNAME}'));
        }
        $this->ldap_search_username = $config['ldap']['search.username'];

        if (!is_string($config['ldap']['search.password'])) {
            throw new Exception($this->t('{autochooseauth:errors:descr_INVALID_LDAP_SEARCH_PASSWORD}'));
        }
        $this->ldap_search_password = $config['ldap']['search.password'];
    }

    /**
     * The main function SimpleSAMLphp calls on login
     * @param string $login
     * @param string $password
     */
    protected function login($login, $password) {
        $attributes = $this->do_login_db($login, $password);
        if (false === $attributes) {
            $attributes = $this->do_login_ldap($this->info, $this->config, $login, $password);
        }

        return $attributes;
    }

    /**
     * Check if password is valid using encrypt routine
     * @param string $password_hashed
     * @param string $password
     * @param string $salt
     * @return boolean
     */
    private function check_password($password_hashed, $password, $salt) {
        $digest = $this->encrypt($password, $salt);

        if ($password_hashed == $digest) {
            return true;
        }
        return false;
    }

    /**
     * Encrypt the plain password provided by user
     * The stored password and salt in database need to be the same hashed
     * @param string $password The plain password string
     * @param string $salt The plain salt
     * @return string Return plain password + salt encrypted
     */
    private function encrypt($password, $salt) {
        $digest = $this->db_sitekey;
        for ($i = 1; $i <= 10; $i++) {
            $digest = hash('sha256', $digest . $salt . $password);
        }
        return $digest;
    }

    /**
     * Generate a salt
     * @return string Return the sha256 string
     */
    public function pour_salt() {
        $str = time() . $this->site_key . rand(12345, 23456);
        return hash('sha256', $str);
    }

    /**
     * Try to login user using the provided credentials
     * @param string $login The user's login
     * @param string $password The user's password
     * @return array
     * @throws SimpleSAML_Error_Exception
     * @throws SimpleSAML_Error_Error
     */
    private function do_login_db($login, $password) {

        /* Connect to the database. */
        $db = new PDO($this->db_dsn, $this->db_username, $this->db_password);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        /* Ensure that we are operating with UTF-8 encoding.
         * This command is for MySQL. Other databases may need different commands.
         */
        $db->exec("SET NAMES 'utf8'");

        /* With PDO we use prepared statements. This saves us from having to escape
         * the username in the database query.
         */
        $statement = "SELECT ";
        $statement .= self::FIELD_USERS_ID;
        $statement .= "," . self::FIELD_USERS_LOGIN;
        $statement .= "," . self::FIELD_USERS_FULL_NAME;
        $statement .= "," . self::FIELD_USERS_EMAIL;
        $statement .= "," . self::FIELD_USERS_PASSWORD_HASHED;
        $statement .= "," . self::FIELD_USERS_SALT;
        $statement .= "," . self::FIELD_USERS_STATE;
        $statement .= "," . self::FIELD_USERS_TOKEN;
        $statement .= " FROM " . self::TABLE_USERS;
        $statement .= " WHERE ";
        $statement .= self::FIELD_USERS_LOGIN . "=:" . self::FIELD_USERS_LOGIN;

        $st = $db->prepare($statement);

        /**
         * Throws execptions if errors
         */
        if (!$st->execute(array(self::FIELD_USERS_LOGIN => $login))) {
            throw new SimpleSAML_Error_Exception($this->t('{autochooseauth:errors:descr_ERROR_DO_LOGIN_DB_EXECUTE}'));
        }

        /**
         * If user was not found, return to continue execution and try LDAD authentication
         */
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            /* User not found. */
            return false;
        }



        /**
         * Just to ensure that empty password is a danger situation
         */
        if (is_null($row[self::FIELD_USERS_PASSWORD_HASHED]) || trim($row[self::FIELD_USERS_PASSWORD_HASHED]) == '') {
            throw new SimpleSAML_Error_Error("EMPTYPASSWORD");
        }

        /**
         * Ok, we found the user, but with wrong password
         */
        if (!$this->check_password($row[self::FIELD_USERS_PASSWORD_HASHED], $password, $row[self::FIELD_USERS_SALT])) {
            /* Invalid password. */
            SimpleSAML_Logger::warning('AutoChooseAuth: Incorrect username/password ' . var_export($login, TRUE) . '.');
            throw new SimpleSAML_Error_Error('WRONGUSERPASS');
        }

        /**
         * We found user but the account is inactive
         */
        if ($row[self::FIELD_USERS_STATE] != self::VALUE_USERS_STATE_ACTIVE) {
            SimpleSAML_Logger::warning('AutoChooseAuth: Inactive account [' . var_export($login, TRUE) . ']');
            throw new SimpleSAML_Error_Error("ACCOUNTINACTIVE");
        }

        /**
         * User has a valid password and active account, but, the e-mail is not validated yet
         * @todo To use this validation, change the signup procedure in your environment
          if ($row[self::FIELD_USERS_EMAIL_VALID] != self::VALUE_USERS_EMAIL_VALID) {
          SimpleSAML_Logger::warning('AutoChooseAuth: The user e-mail is not validated [' . var_export($login, TRUE) . ']');
          throw new SimpleSAML_Error_Error("EMAILNOTVALIDATE");
          }
         */
        /**
         * The user account is ok, but, the password must be changed
         * @todo To use this validation, change the signup procedure in your environment
          if ($row[self::FIELD_USERS_CHANGE_PASSWORD] != self::VALUE_USERS_CHANGE_PASSWORD) {
          SimpleSAML_Logger::warning('AutoChooseAuth: User must change password [' . var_export($login, TRUE) . ']');
          throw new SimpleSAML_Error_Error("PWDNEEDCHANGE");
          }
         */
        /**
         * @todo Add two factor authenticaton
          if ($row[self::FIELD_USERS_TOKEN] == self::VALUE_USERS_TOKEN_ACTIVE) {

          }
         */
        /**
         * Create the attribute array of the user
         */
        $attributes = array(
            'uid' => array($row[self::FIELD_USERS_LOGIN]),
            'cn' => array($row[self::FIELD_USERS_FULL_NAME]),
            //'givenName' => array(strstr($row[self::FIELD_USERS_FULL_NAME], " ", true)),
            //'surname' => array(strstr($row[self::FIELD_USERS_FULL_NAME], " ")),
            'mail' => array($row[self::FIELD_USERS_EMAIL]),
        );

        /* Return the attributes. */
        return $attributes;
    }

    private function do_login_ldap($info, $config, $login, $password) {
        $ldap_config = new sspmod_ldap_ConfigHelper($config['ldap'], $info['AuthId']);
        return $attributes = $ldap_config->login($login, $password);
    }

}
