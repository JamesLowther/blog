*2022-04-15*

#guide 

> [!Abstract]
> This page includes a number of initial techniques and one-liners to help with privilege escalaton.

---

## Nmap
**Initial Scan**
`nmap -vv -sV -sC -oN initial <ip>`

**Full Scan**
`nmap -vv -sV -sC -p- -A -oN full <ip>`

## Gobuster
`gobuster dir -u http://<host> -w /usr/share/wordlists/dirb/common.txt`

---

# References
- https://github.com/infosec-ucalgary/CTFCommands/blob/main/Pentesting.md

---