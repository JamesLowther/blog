*2022-04-12*

#guide 

> [!Abstract] Introduction
> This page includes a number of initial techniques and one-liners to help with privilege escalation.

---

## SUID bit escalation
- `find / -perm -u=s -type f 2>/dev/null`
- `getcap -r / 2>/dev/null`

Check your findings against https://gtfobins.github.io/.

## File ownership
- `find / -user <user>`
- `find / -group <group>`

## Pspy64
Used to find root-owned processes and see commands run by other users.

https://github.com/DominicBreuker/pspy

---

# References
* https://github.com/infosec-ucalgary/CTFCommands/blob/main/Pentesting.md

---