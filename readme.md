#PHP LDAP library functionality packed in a simple class
Public methods:
 - connect($host, $conUser, $conPassword, $domain, $baseDn)
 - authenticate($user, $password)
 - search($filter, array $paramsList)
 - getErrorText()
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
$user_to_auth = 'John Doe'; // can be LDAP CN name or AD login
$password_to_auth = 'johndoe123';
$domain = 'Company';
$searchFilter = "(memberOf=CN=Company All,CN=Users,DC=Aplana,DC=com)";
$paramsToRetrieve = array("distinguishedname", "displayname", "department", "title");

use StepanSib\LDAP\LDAP;
$ldap = new LDAP();

if ($ldap->connect($host,$lpadUser,$lpadPassword,$domain,$baseDn)) {
    // Connected, lets try to auth user
    if ($user = $ldap->authenticate($user_to_auth, $password_to_auth)) {
        var_dump($user);
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