<?php

namespace PayPal\Auth;

interface StorageInterface
{
    /** @return string */
    public function pullToken($forceRefresh = false);
}