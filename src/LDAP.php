<?php
/**
 * Created by PhpStorm.
 * User: Stepan Yudin
 * Date: 02.09.2015
 * Time: 18:31
 */

namespace StepanSib\LDAP;

use Symfony\Component\OptionsResolver\OptionsResolver;
use Assert\Assertion;

class LDAP
{

    /** @var array */
    protected $options = array();

    /** @var resource */
    protected $connection;

    /**
     * LDAP constructor.
     * @param array $options
     */
    public function __construct(array $options)
    {
        $resolver = new OptionsResolver();

        $resolver->setDefault('anonymous', false);
        $resolver->setRequired(array(
                'host',
                'domain',
                'username',
                'password',
                'base_dn')
        );

        $this->options = $resolver->resolve($options);
    }

    /**
     * @return resource
     * @throws LDAPException
     */
    public function connect()
    {
        try {
            set_error_handler(array($this, 'errorHandler'));
            $this->connection = ldap_connect("ldap://" . $this->options['host']);
            ldap_set_option($this->connection, LDAP_OPT_REFERRALS, 0);
            ldap_set_option($this->connection, LDAP_OPT_PROTOCOL_VERSION, 3);
            restore_error_handler();
        } catch (\Exception $e) {
            throw new LDAPException($e->getMessage());
        }

        $this->bind();

        return $this->getConnection();
    }

    /**
     * @return bool
     * @throws LDAPException
     */
    protected function bind()
    {
        $username = null;
        $password = null;
        
        if (!$this->options['anonymous']) {
            $username = $this->options['username'] . '@' . $this->options['domain'];
            $password = $this->options['password'];
        }

        try {
            set_error_handler(array($this, 'errorHandler'));
            ldap_bind($this->getConnection(), $username, $password);
            restore_error_handler();
            return true;
        } catch (\Exception $e) {
            throw new LDAPException($e->getMessage());
        }
    }


    /**
     * Tries to authenticate user. If success then returns user account name
     *
     * @param $username
     * @param $password
     * @param null $baseDn
     * @return bool|string
     * @throws LDAPException
     */
    public function authenticate($username, $password, $baseDn = null)
    {

        try {
            Assertion::notEmpty($username);
        } catch (\Exception $e) {
            throw new LDAPException('username not specified');
        }

        $usersToTry = $this->getMatchingUsersAccountNames($username, $baseDn);

        foreach ($usersToTry as $userAccountName) {
            try {
                set_error_handler(array($this, 'errorHandler'));
                if (ldap_bind($this->getConnection(), $userAccountName . '@' . $this->options['domain'], $password)) {
                    restore_error_handler();
                    $this->bind();
                    return $userAccountName;
                }
                restore_error_handler();
            } catch (\Exception $e) {
                // do nothing, suppressing
            }
        }

        $this->bind();
        return false;
    }

    /**
     * Returns user
     * @param $userAccountName
     * @param null $baseDn
     * @return mixed
     * @throws LDAPException
     */
    public function getUserCnByAccountName($userAccountName, $baseDn = null)
    {
        if ($usersFound = $this->search(
            '(&(objectClass=user)(sAMAccountName=' . $userAccountName . '))',
            array('cn'),
            $baseDn
        )
        ) {
            return $usersFound[0]['cn'];
        }

        throw new LDAPException('cannot get user cn name');
    }

    /**
     * Looks for users by matching username and specified fields and returns array of users account names
     *
     * @param $username
     * @param null $baseDn
     * @return array
     * @throws LDAPException
     */
    protected function getMatchingUsersAccountNames($username, $baseDn = null)
    {

        $usernames = array($username);

        $fieldsToMatch = array(
            'cn',
            'mail',
            'userPrincipalName',
            'displayname',
            'name',
            'sAMAccountName',
        );

        foreach ($fieldsToMatch as $field) {
            if ($usersFound = $this->search(
                '(&(objectClass=user)(' . $field . '=' . $username . '))',
                array('sAMAccountName'),
                $baseDn
            )
            ) {
                foreach ($usersFound as $user) {
                    $usernames[] = $user['sAMAccountName'];
                }
            }
        }

        return array_unique($usernames);
    }

    /**
     * @param null $baseDn
     * @return mixed|null
     */
    protected function getBaseDn($baseDn = null)
    {
        if (null === $baseDn) {
            return $this->options['base_dn'];
        }
        return $baseDn;
    }

    /**
     * Searches for users and return an array of users and their specified parameters
     *
     * @param $filter
     * @param array $paramsToRetrieve
     * @param null $baseDn
     * @return array|bool
     * @throws LDAPException
     */
    public function search($filter, array $paramsToRetrieve = array(), $baseDn = null)
    {

        $baseDn = $this->getBaseDn($baseDn);

        try {
            Assertion::notEmpty($filter);
        } catch (\Exception $e) {
            throw new LDAPException('wrong search options - ' . $e->getMessage());
        }

        array_push($paramsToRetrieve, 'objectguid');

        try {
            set_error_handler(array($this, 'errorHandler'));
            $searchResults = ldap_search($this->getConnection(), $baseDn, $filter, $paramsToRetrieve);
            $entries = ldap_get_entries($this->getConnection(), $searchResults);
            restore_error_handler();
        } catch (\Exception $e) {
            throw new LDAPException('search failed, ' . $e->getMessage());
        }

        $result = array();

        foreach ($entries as $entry) {
            $entryData = array();
            foreach ($paramsToRetrieve as $param) {
                $paramOriginName = $param;
                $param = mb_strtolower($param, 'utf-8');
                if (isset($entry[$param]) && is_array($entry[$param])) {
                    $entryData[$paramOriginName] = $entry[$param][0];
                } else if (isset($entry[$param]) && !is_array($entry[$param])) {
                    $entryData[$paramOriginName] = $entry[$param];
                } else {
                    $entryData[$paramOriginName] = '';
                }
            }

            $entryData['objectguid'] = $this->guidToString($entryData['objectguid']);

            if ($entryData['objectguid'] !== "") {
                $result[] = $entryData;
            }
        }

        if (count($result) > 0) {
            return $result;
        }

        return false;
    }

    /**
     * @return resource
     * @throws LDAPException
     */
    protected function getConnection()
    {
        if (null !== $this->connection) {
            return $this->connection;
        }
        $this->connect();
        return $this->connection;
    }

    protected function errorHandler($errno, $errstr)
    {
        throw new \Exception($errstr, $errno);
    }

    /**
     * @return bool
     * @throws LDAPException
     */
    public function close()
    {
        if (null !== $this->connection) {
            try {
                set_error_handler(array($this, 'errorHandler'));
                ldap_close($this->getConnection());
                $this->connection = null;
                restore_error_handler();
                return true;
            } catch (\Exception $e) {
                throw new LDAPException($e->getMessage());
            }
        }

        throw new LDAPException('can not close unestablished LDAP connection');
    }

    protected function guidToString($ADguid)
    {
        $guidinhex = str_split(bin2hex($ADguid), 2);
        $guid = "";
        //Take the first 4 octets and reverse their order
        $first = array_reverse(array_slice($guidinhex, 0, 4));
        foreach($first as $value)
        {
            $guid .= $value;
        }
        $guid .= "-";
        // Take the next two octets and reverse their order
        $second = array_reverse(array_slice($guidinhex, 4, 2, true), true);
        foreach($second as $value)
        {
            $guid .= $value;
        }
        $guid .= "-";
        // Repeat for the next two
        $third = array_reverse(array_slice($guidinhex, 6, 2, true), true);
        foreach($third as $value)
        {
            $guid .= $value;
        }
        $guid .= "-";
        // Take the next two but do not reverse
        $fourth = array_slice($guidinhex, 8, 2, true);
        foreach($fourth as $value)
        {
            $guid .= $value;
        }
        $guid .= "-";
        //Take the last part
        $last = array_slice($guidinhex, 10, 16, true);
        foreach($last as $value)
        {
            $guid .= $value;
        }
        return $guid;
    }

}
