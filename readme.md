#PHP LDAP library functionality packed in a simple class
Public methods:
 - connect($host)
 - authenticate($user, $password, $domain)
 - search($baseDn, $filter, array $paramsList)
 - getErrorText()
 - disconnect()

##1. Installation
Under construction

##2. Usage example
```php
use StepanSib\LDAP\LDAP;

$host = 'ldap.company.com';
$baseDn = 'DC=Company,DC=com';
$user = 'user_to_log_in';
$password = 'user_password';
$domain = 'Company';
$searchFilter = "(memberOf=CN=Company All Users,CN=Users,DC=company,DC=com)";
$paramsToRetrieve = array("distinguishedname", "displayname", "department", "title");

$ldap = new LDAP();

if ($ldap->connect($host)) {
    if ($ldap->authenticate($user, $password, $domain)) {
        if ($users = $ldap->search($baseDn, $searchFilter, $paramsToRetrieve)) {
            var_dump($users);
        } else {
            echo 'Error: ' . $ldap->getStatus();
        }
    } else {
        echo 'Error: ' . $ldap->getStatus();
    }
} else {
    echo 'Error: ' . $ldap->getStatus();
}
```