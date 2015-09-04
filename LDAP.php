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

    protected $conUser;
    protected $conPassword;

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

    public function connect($host, $conUser, $conPassword, $domain, $baseDn)
    {
        if (trim($host) == "") {
            $this->setStatus("Host address is empty");
            return false;
        } else {
            $this->setHost($host);
        }

        if (trim($conUser) == "") {
            $this->setStatus("Connection username is empty");
            return false;
        } else {
            $this->setConUser($conUser);
        }

        if (trim($conPassword) == "") {
            $this->setStatus("Connection password is empty");
            return false;
        } else {
            $this->setConPassword($conPassword);
        }

        if (trim($domain) == "") {
            $this->setStatus("Domain is empty");
            return false;
        } else {
            $this->setDomain($domain);
        }

        if (trim($baseDn) == "") {
            $this->setStatus("Base DN is empty");
            return false;
        } else {
            $this->setBaseDN($baseDn);
        }

        if ($ldap = @ldap_connect("ldap://{$host}")) {
            @ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
            @ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

            if (@ldap_bind($ldap, $this->getConUser() . '@' . $this->getDomain(), $this->getConPassword())) {
                $this->setConnection($ldap);
                $this->clearStatus();
                return true;
            } else {
                $this->setStatus("LDAP connection user bind error");
                return false;
            }

        } else {
            $this->setStatus("LDAP connection error");
            return false;
        }

    }

    public function disconnect()
    {
        if (!empty($this->getConnection())) {
            @ldap_close($this->getConnection());
            $this->clearStatus();
            return true;
        } else {
            $this->setStatus("Could not close unestablished connection");
            return false;
        }
    }

    public function authenticate($user, $password)
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

        $userData = array(
            'cn' => '',
            'dn' => '',
            'login' => ''
        );

        if ($dn = $this->searchByCN($this->getUser())) {
            if (@ldap_bind($this->getConnection(), $dn, $this->getPassword())) {
                $userData['dn'] = $dn;
                $userData['cn'] = $this->getUser();
                if ($users = $this->search("(&(objectClass=user)(distinguishedName=" . $dn . "))", array('sAMAccountName'))) {
                    $userData['login'] = mb_strtolower($users[0]['sAMAccountName'], 'utf-8');
                }

                $this->clearStatus();
                return $userData;
            }
        }

        if (@ldap_bind($this->getConnection(), $this->getUser() . '@' . $this->getDomain(), $this->getPassword())) {
            $userData['login'] = mb_strtolower($this->getUser(), 'utf-8');
            if ($users = $this->search("(&(objectClass=user)(sAMAccountName=" . $this->getUser() . "))", array('distinguishedName', 'cn'))) {
                $userData['dn'] = $users[0]['distinguishedName'];
                $userData['cn'] = $users[0]['cn'];
            }

            $this->clearStatus();
            return $userData;
        }

        $this->setStatus("Could not bind to AD");
        return false;

    }

    protected function dnToCn($dn)
    {
        $dnParts = explode(",", $dn);
        $cnParts = explode("=", $dnParts[0]);
        return $cnParts[1];
    }

    protected function searchByCN($cn)
    {

        if (trim($cn) == "") {
            $this->setStatus("CN is empty");
            return false;
        }

        if (empty($this->getConnection())) {
            $this->setStatus("Not connected to LDAP");
            return false;
        }

        $filter = "(&(objectClass=user)(cn=" . $cn . "))";

        if ($sr = @ldap_search($this->getConnection(), $this->getBaseDN(), $filter, array('objectguid'))) {
            if (@ldap_count_entries($this->getConnection(), $sr) == 1) {
                return ldap_get_dn($this->getConnection(), ldap_first_entry($this->getConnection(), $sr));
            }
        }

        return false;

    }

    public function search($filter, array $paramsList)
    {

        if (empty($this->getConnection())) {
            $this->setStatus("Not connected to LDAP");
            return false;
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
                        //var_dump($users[$n]);
                        $userData = array();

                        foreach ($this->getParamsList() as $param) {
                            $paramOriginName = $param;
                            $param = mb_strtolower($param, 'utf-8');
                            if (isset($users[$n][$param]) && is_array($users[$n][$param])) {
                                $userData[$paramOriginName] = $users[$n][$param][0];
                            } else if (isset($users[$n][$param]) && !is_array($users[$n][$param])) {
                                $userData[$paramOriginName] = $users[$n][$param];
                            } else {
                                $userData[$paramOriginName] = '';
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


    protected function setConUser($conUser)
    {
        $this->conUser = $conUser;
    }

    protected function getConUser()
    {
        return $this->conUser;
    }

    protected function setConPassword($conPassword)
    {
        $this->conPassword = $conPassword;
    }

    protected function getConPassword()
    {
        return $this->conPassword;
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