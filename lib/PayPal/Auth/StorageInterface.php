<?php

namespace PayPal\Auth;

interface StorageInterface
{
    /**
     * @param string $key
     * @return string
     */
    public function pull($key);
    
    /**
     * @param string $key
     * @param string $access_token
     * @param int $expires_in
     * @return mixed
     */
    public function push($key, $access_token, $expires_in);
}