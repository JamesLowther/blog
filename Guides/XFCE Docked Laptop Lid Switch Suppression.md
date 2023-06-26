## 2023-06-15
#guide

> [!Abstract]
> XFCE looks to have limited support for laptop lid switch suppression when connected to a dock. Despite setting the lid switch to "ignore" in the XFCE power manager, I found that the computer would still go to sleep when the lid was closed.

There are a few conflicting services that need config changes to get this working.

> [!Note]
> This guide has only been tested on Manjaro - XFCE edition.


---

## Disable UPower
UPower looks to override the lid suppression settings of XFCE power manager so we need to disable it. Disabling this also looks to remove the lid settings in the Power Manager GUI.
```
# /etc/UPower/UPower.conf

IgnoreLid=true
```

## Disable xfce4-power-manager
These commands will tell XFCE to delegate lid switch management to systemd-logind instead:
```sh
# Update config.
xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/logind-handle-lid-switch -n -t bool -s true

# Verify.
xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/logind-handle-lid-switch
```

Verify this change worked by ensuring systemd is not inhibited from `handle-lid-switch`. Look under "WHAT" column from the output of the following command:
```sh
systemd-inhibit --list --mode=block
```

## Configure systemd-logind
Configure systemd-logind to ignore the lid switch when an external monitor is connected (considered docked):
```
# /etc/systemd/logind.conf

HandleLidSwitchDocked=ignore
```

```sh
sudo systemctl restart systemd-logind
```

A reboot after this might not be a bad idea.

## Final steps
- Ensure that OLED screens are disabled when docked to prevent burn-in. 
	-  You can do this in the display settings.

---

# References
- https://docs.xfce.org/xfce/xfce4-power-manager/faq#how_can_i_make_logind_handle_button_events_instead_of_xfce4-power-manager
- https://www.freedesktop.org/software/systemd/man/logind.conf.html

---
