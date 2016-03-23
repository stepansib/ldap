<?php
/**
 * Created by PhpStorm.
 * User: Stepan
 * Date: 22.03.2016
 * Time: 22:35
 */

namespace StepanSib\LDAP;

class LDAPException extends \Exception
{

    public function setMessage($message)
    {
        $this->message = "LDAP: " . $message;
    }
}
