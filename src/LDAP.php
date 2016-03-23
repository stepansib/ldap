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
                'password')
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
        $bindOptions = array($this->getConnection());

        if (!$this->options['anonymous']) {
            array_push($bindOptions, $this->options['username'] . '@' . $this->options['domain']);
            array_push($bindOptions, $this->options['password']);
        }

        try {
            set_error_handler(array($this, 'errorHandler'));
            ldap_bind(...$bindOptions);
            restore_error_handler();
            return true;
        } catch (\Exception $e) {
            throw new LDAPException($e->getMessage());
        }
    }

    /**
     * @param $username
     * @param $password
     * @return bool
     * @throws LDAPException
     */
    public function authenticate($username, $password)
    {

        try {
            Assertion::notEmpty($username);
        } catch (\Exception $e) {
            throw new LDAPException('username not specified');
        }

        $usersToTry = $this->getMatchingUsernames($username);

        foreach ($usersToTry as $usernameToTry) {
            try {
                set_error_handler(array($this, 'errorHandler'));
                if (ldap_bind($this->getConnection(), $usernameToTry . '@' . $this->options['domain'], $password)) {
                    return true;
                }
                restore_error_handler();
            } catch (\Exception $e) {
                // do nothing, suppressing
            }
        }

        return false;

    }

    /**
     * @param $username
     * @return mixed
     * @throws LDAPException
     */
    protected function getMatchingUsernames($username)
    {

        $usernames = array($username);

        $fieldsToMatch = array(
            'cn',
            'mail',
            'displayname',
            'name',
            'sAMAccountName',
        );

        foreach ($fieldsToMatch as $field) {
            $usersFound = $this->search(
                '(&(objectClass=user)(' . $field . '=' . $username . '))',
                'DC=Aplana,DC=com',
                array('sAMAccountName')
            );
            foreach ($usersFound as $user) {
                $usernames[] = $user['sAMAccountName'];
            }
        }

        return array_unique($usernames);
    }

    /**
     * @param $filter
     * @param $baseDn
     * @param array $paramsToRetrieve
     * @return array
     * @throws LDAPException
     */
    public function search($filter, $baseDn, array $paramsToRetrieve = array())
    {
        try {
            Assertion::notEmpty($baseDn);
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

            if ($entryData['objectguid'] !== "") {
                $result[] = $entryData;
            }
        }

        return $result;

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

}
