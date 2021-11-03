<?php

namespace PayPal\Auth;

use PayPal\Common\PayPalResourceModel;
use PayPal\Core\PayPalHttpConfig;
use PayPal\Core\PayPalHttpConnection;
use PayPal\Core\PayPalLoggingManager;
use PayPal\Exception\PayPalConfigurationException;
use PayPal\Exception\PayPalConnectionException;
use PayPal\Handler\IPayPalHandler;
use PayPal\Rest\ApiContext;
use PayPal\Security\Cipher;

/**
 * Class OAuthTokenCredential
 */
class OAuthTokenCredential extends PayPalResourceModel
{

    public static $CACHE_PATH = '/../../../var/auth.cache';

    /**
     * @var string Default Auth Handler
     */
    public static $AUTH_HANDLER = 'PayPal\Handler\OauthHandler';

    /**
     * Private Variable
     *
     * @var int $expiryBufferTime
     */
    public static $expiryBufferTime = 120;

    /**
     * Client ID as obtained from the developer portal
     *
     * @var string $clientId
     */
    private $clientId;

    /**
     * Client secret as obtained from the developer portal
     *
     * @var string $clientSecret
     */
    private $clientSecret;

    /**
     * Target subject
     */
    private $targetSubject;

    /**
     * Generated Access Token
     *
     * @var string $accessToken
     */
    private $accessToken;

    /**
     * Seconds for with access token is valid
     *
     * @var $tokenExpiresIn
     */
    private $tokenExpiresIn;

    /**
     * Last time (in milliseconds) when access token was generated
     *
     * @var $tokenCreateTime
     */
    private $tokenCreateTime;

    /**
     * Instance of cipher used to encrypt/decrypt data while storing in cache.
     *
     * @var Cipher
     */
    private $cipher;

    /** @var StorageInterface */
    private $tokenStorage;

    /**
     * Construct
     *
     * @param string $clientId     client id obtained from the developer portal
     * @param string $clientSecret client secret obtained from the developer portal
     */
    public function __construct($clientId, $clientSecret, $targetSubject = null, StorageInterface $tokenStorage = null)
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->cipher = new Cipher($this->clientSecret);
        $this->targetSubject = $targetSubject;
        $this->tokenStorage = $tokenStorage;
    }

    /**
     * Get Client ID
     *
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * Get Client Secret
     *
     * @return string
     */
    public function getClientSecret()
    {
        return $this->clientSecret;
    }

    /**
     * Get AccessToken
     *
     * @param $config
     *
     * @return null|string
     */
    public function getAccessToken($config)
    {
        if( ! $this->tokenStorage) {
            return null;
        }

        return $this->tokenStorage->pullToken();
    }


    /**
     * Get a Refresh Token from Authorization Code
     *
     * @param $config
     * @param $authorizationCode
     * @param array $params optional arrays to override defaults
     * @return string|null
     */
    public function getRefreshToken($config, $authorizationCode = null, $params = array())
    {
        static $allowedParams = array(
            'grant_type' => 'authorization_code',
            'code' => 1,
            'redirect_uri' => 'urn:ietf:wg:oauth:2.0:oob',
            'response_type' => 'token'
        );

        $params = is_array($params) ? $params : array();
        if ($authorizationCode) {
            //Override the authorizationCode if value is explicitly set
            $params['code'] = $authorizationCode;
        }
        $payload = http_build_query(array_merge($allowedParams, array_intersect_key($params, $allowedParams)));

        $response = $this->getToken($config, $this->clientId, $this->clientSecret, $payload);

        if ($response != null && isset($response["refresh_token"])) {
            return $response['refresh_token'];
        }

        return null;
    }

    /**
     * Updates Access Token based on given input
     *
     * @param array $config
     * @param string|null $refreshToken
     * @return string
     */
    public function updateAccessToken($config, $refreshToken = null)
    {
        $this->generateAccessToken($config, $refreshToken);
        return $this->accessToken;
    }

    /**
     * Retrieves the token based on the input configuration
     *
     * @param array $config
     * @param string $clientId
     * @param string $clientSecret
     * @param string $payload
     * @return mixed
     * @throws PayPalConfigurationException
     * @throws \PayPal\Exception\PayPalConnectionException
     */
    protected function getToken($config, $clientId, $clientSecret, $payload)
    {
        $httpConfig = new PayPalHttpConfig(null, 'POST', $config);

        // if proxy set via config, add it
        if (!empty($config['http.Proxy'])) {
            $httpConfig->setHttpProxy($config['http.Proxy']);
        }

        $handlers = array(self::$AUTH_HANDLER);

        /** @var IPayPalHandler $handler */
        foreach ($handlers as $handler) {
            if (!is_object($handler)) {
                $fullHandler = "\\" . (string)$handler;
                $handler = new $fullHandler(new ApiContext($this));
            }
            $handler->handle($httpConfig, $payload, array('clientId' => $clientId, 'clientSecret' => $clientSecret));
        }

        $connection = new PayPalHttpConnection($httpConfig, $config);
        $res = $connection->execute($payload);
        $response = json_decode($res, true);

        return $response;
    }


    /**
     * Generates a new access token
     *
     * @param array $config
     * @param null|string $refreshToken
     * @return null
     * @throws PayPalConnectionException
     */
    private function generateAccessToken($config, $refreshToken = null)
    {
        $params = array('grant_type' => 'client_credentials');
        if ($refreshToken != null) {
            // If the refresh token is provided, it would get access token using refresh token
            // Used for Future Payments
            $params['grant_type'] = 'refresh_token';
            $params['refresh_token'] = $refreshToken;
        }
        if ($this->targetSubject != null) {
            $params['target_subject'] = $this->targetSubject;
        }
        $payload = http_build_query($params);
        $response = $this->getToken($config, $this->clientId, $this->clientSecret, $payload);

        if ($response == null || !isset($response["access_token"]) || !isset($response["expires_in"])) {
            $this->accessToken = null;
            $this->tokenExpiresIn = null;
            PayPalLoggingManager::getInstance(__CLASS__)->warning("Could not generate new Access token. Invalid response from server: ");
            throw new PayPalConnectionException(null, "Could not generate new Access token. Invalid response from server: ");
        } else {
            $this->accessToken = $response["access_token"];
            $this->tokenExpiresIn = $response["expires_in"];
        }
        $this->tokenCreateTime = time();

        return $this->accessToken;
    }

    /**
     * Helper method to encrypt data using clientSecret as key
     *
     * @param $data
     * @return string
     */
    public function encrypt($data)
    {
        return $this->cipher->encrypt($data);
    }

    /**
     * Helper method to decrypt data using clientSecret as key
     *
     * @param $data
     * @return string
     */
    public function decrypt($data)
    {
        return $this->cipher->decrypt($data);
    }

    /**
     * @param array $config
     * @return string
     */
    private function getTokenKey($config)
    {
        return ! empty($config['mode']) && $config['mode'] === 'SANDBOX' ? 'TEST' : 'LIVE';
    }
}
