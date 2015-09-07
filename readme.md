#PHP LDAP library functionality packed in a simple class
Public methods:
 - setOptions($host, $user, $password, $domain, $baseDn)
 - connect()
 - authenticate($user, $password)
 - search($filter, array $paramsList)
 - getStatus()
 - disconnect()

##1. Installation
Just a simple composer command:
```sh
composer require stepansib/ldap
```

##2. Usage example
```php
use StepanSib\LDAP\LDAP;

$host = 'ldap.company.com';
$lpadUser = "ldapadmin";
$lpadPassword = "password";
$baseDn = 'DC=Company,DC=com';
$user_to_auth = 'John Doe';
$password_to_auth = 'johndoe123';
$domain = 'Company';
$searchFilter = "(memberOf=CN=Company All,CN=Users,DC=Company,DC=com)";
$paramsToRetrieve = array("distinguishedname", "displayname", "department", "title");

use StepanSib\LDAP\LDAP;

$ldap = new LDAP();

$ldap->setOptions(
    $host,
    $lpadUser,
    $lpadPassword,
    $domain,
    $baseDn
);

if ($ldap->connect()) {

    // Connected, lets try to auth user
    if ($user = $ldap->authenticate($user_to_auth, $password_to_auth)) {
        Utils::arrDump($user);
    } else {
        echo 'Error: ' . $ldap->getStatus();
    }

    // Try to find users
    if ($users = $ldap->search($searchFilter, $paramsToRetrieve)) {
        var_dump($users);
    } else {
        echo 'Error: ' . $ldap->getStatus();
    }

} else {
    echo 'Error: ' . $ldap->getStatus();
}
```