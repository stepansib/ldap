<?php
/**
 * Created by PhpStorm.
 * User: Stepan Yudin
 * Date: 02.09.2015
 * Time: 18:31
 */

namespace StepanSib\LDAP;

class LDAP
{

    protected $connection;
    protected $host;
    protected $baseDn;
    protected $user;
    protected $password;
    protected $domain;
    protected $filter;
    protected $paramsList;

    protected $authenticated;
    protected $errorText;

    public function __construct()
    {
        $this->authenticated = false;
    }

    public function connect($host)
    {
        if (trim($host) == "") {
            $this->setStatus("Host address is empty");
            return false;
        } else {
            $this->setHost($host);
        }

        if ($ldap = ldap_connect("ldap://{$host}")) {
            ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
            ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

            $this->setConnection($ldap);
            $this->clearStatus();
            return true;
        } else {
            $this->setStatus("LDAP connection error");
            return false;
        }

    }

    public function disconnect()
    {
        if (!empty($this->getConnection())) {
            ldap_close($this->getConnection());
            $this->clearStatus();
            return true;
        } else {
            $this->setStatus("Could not close unestablished connection");
            return false;
        }
    }

    public function authenticate($user, $password, $domain)
    {

        if (empty($this->getConnection())) {
            $this->setStatus("Not connected to LDAP");
            return false;
        }

        if (trim($user) == "") {
            $this->setStatus("Username is empty");
            return false;
        } else {
            $this->setUser($user);
        }

        if (trim($password) == "") {
            $this->setStatus("Password is empty");
            return false;
        } else {
            $this->setPassword($password);
        }

        if (trim($domain) == "") {
            $this->setStatus("Domain is empty");
            return false;
        } else {
            $this->setDomain($domain);
        }

        if (ldap_bind($this->getConnection(), $this->getUser() . '@' . $this->getDomain(), $this->getPassword())) {
            $this->authenticated();
            $this->clearStatus();
            return true;
        } else {
            $this->setStatus("Could not bind to AD");
            return false;
        }

    }

    public function search($baseDn, $filter, array $paramsList)
    {

        if (empty($this->getConnection())) {
            $this->setStatus("Not connected to LDAP");
            return false;
        }

        if (!$this->isAuthenticated()) {
            $this->setStatus("Not authenticated");
            return false;
        }

        if (trim($baseDn) == "") {
            $this->setStatus("Base DN is empty");
            return false;
        } else {
            $this->setBaseDN($baseDn);
        }

        if (trim($filter) == "") {
            $this->setStatus("Filter is empty");
            return false;
        } else {
            $this->setFilter($filter);
        }

        if (!is_array($paramsList) || count($paramsList) == 0) {
            $this->setStatus("AD parameters list is empty or not an array");
            return false;
        } else {
            $this->setParamsList($paramsList);
        }

        if ($sr = ldap_search($this->getConnection(), $this->getBaseDN(), $this->getFilter(), array_merge($paramsList, array('objectguid')))) {
            if ($users = ldap_get_entries($this->getConnection(), $sr)) {
                if (count($users) > 1) {
                    $usersData = array();

                    for ($n = 0; $n < count($users) - 1; $n++) {
                        $userData = array();

                        foreach ($this->getParamsList() as $param) {
                            if (isset($users[$n][$param]) && is_array($users[$n][$param])) {
                                $userData[$param] = $users[$n][$param][0];
                            } else if (isset($users[$n][$param]) && !is_array($users[$n][$param])) {
                                $userData[$param] = $users[$n][$param];
                            } else {
                                $userData[$param] = '';
                            }
                        }

                        $usersData[] = $userData;
                    }

                    $this->clearStatus();
                    return $usersData;
                } else {
                    $this->setStatus("Nothing was found");
                    return false;
                }
            } else {
                $this->setStatus("AD search error");
                return false;
            }
        } else {
            $this->setStatus("AD search error");
            return false;
        }

    }

    protected function setConnection($connection)
    {
        $this->connection = $connection;
    }

    protected function getConnection()
    {
        return $this->connection;
    }

    protected function setHost($host)
    {
        $this->host = $host;
    }

    protected function getHost()
    {
        return $this->host;
    }

    protected function setBaseDN($baseDn)
    {
        $this->baseDn = $baseDn;
    }

    protected function getBaseDN()
    {
        return $this->baseDn;
    }

    protected function setUser($user)
    {
        $this->user = $user;
    }

    protected function getUser()
    {
        return $this->user;
    }

    protected function setPassword($password)
    {
        $this->password = $password;
    }

    protected function getPassword()
    {
        return $this->password;
    }

    protected function setDomain($domain)
    {
        $this->domain = $domain;
    }

    protected function getDomain()
    {
        return $this->domain;
    }

    protected function setFilter($filter)
    {
        $this->filter = $filter;
    }

    protected function getFilter()
    {
        return $this->filter;
    }

    protected function setParamsList($paramsList)
    {
        $this->paramsList = $paramsList;
    }

    protected function getParamsList()
    {
        return $this->paramsList;
    }

    protected function clearStatus()
    {
        $this->errorText = "No errors";
    }

    protected function setStatus($text)
    {
        $this->errorText = $text;
    }

    public function getStatus()
    {
        return $this->errorText;
    }

    protected function isAuthenticated()
    {
        return $this->authenticated;
    }

    protected function authenticated()
    {
        $this->authenticated = true;
    }
}