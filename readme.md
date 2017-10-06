## PHP LDAP library functionality packed in a simple class

[![SensioLabs Insight](https://img.shields.io/sensiolabs/i/9dc139ea-991c-4294-988f-8445d8f68af0.svg)](https://insight.sensiolabs.com/projects/9dc139ea-991c-4294-988f-8445d8f68af0)
[![Codacy](https://img.shields.io/codacy/38bd187bffde4b008c033a5d1837a0d3.svg)](https://www.codacy.com/app/stepan-sib/ldap)
[![Packagist](https://img.shields.io/packagist/v/stepansib/ldap.svg)](https://packagist.org/packages/stepansib/ldap)

## 1. Installation
Run in your project directory:
```sh
composer require stepansib/ldap
```

## 2. Usage

#### 1. LDAP object
To configure connection instantiate LDAP object with connection params array:
```php
use StepanSib\LDAP\LDAP;

$ldap = new LDAP2(array(
    'host' => 'server.company.com',
    'username' => 'johndoe',
    'password' => '12345',
    'domain' => 'Company',
));
```

#### 2. Connection
To connect and bind to LDAP:
```php
$ldap->connect();
```
Usage of this method is not necessary because connection will be established automatically when it will needed

#### 3. User authentication
To authenticate any account:
```php
$ldap->authenticate("jdoe", "12345");
$ldap->authenticate("johndoe@company.com", "12345");
$ldap->authenticate("John Doe", "12345");
```
The username credential can be any of following LDAP entry parameters:
 - cn
 - mail
 - displayname
 - name
 - sAMAccountName
 
#### 4. Search
To find any record in LDAP directory use the following search method. You need to specify filter string, baseDN string and array of parameters you want to get per entry:
```php
$filter = '(memberOf=CN=Company Management,CN=Users,DC=Company,DC=com)';
//$filter = '&(objectClass=user)(sAMAccountName=jdoe))'; // any valid filter can be passed
$baseDn = 'DC=Company,DC=com';

$data = $ldap->search(
    $filter,
    $baseDn,
    array(
        'cn',
        'distinguishedname',
        'displayname',
        'department',
        'title',
        'sAMAccountName',
        'mail',
        'displayName'
    )
);
```
The method returns assoc array with matched entries and their parameters values

#### 5. Close connection
After things was done you need to close connection:
```php
$ldap->close();
```
