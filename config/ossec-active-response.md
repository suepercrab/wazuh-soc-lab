# Active Response — firewall-drop on rule 100100

This is the active response configuration that automatically blocks an attacker's IP when rule 100100 (SSH brute force) fires. It's added to the Wazuh manager's main config file at `/var/ossec/etc/ossec.conf`.

## The active response block

This is the part I added. It ties the built-in `firewall-drop` command to rule 100100 with a 120-second block:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100100</rules_id>
  <timeout>120</timeout>
</active-response>
```

- `command` — `firewall-drop` drops the offending IP using the endpoint's local firewall (iptables on Linux).
- `location` — `local` runs the response on the agent that generated the alert, not the manager.
- `rules_id` — bound to my custom rule 100100.
- `timeout` — the IP is blocked for 120 seconds, then automatically unblocked. In `active-responses.log` this shows as an `add` followed by a `delete` when the timer expires.

**Why 120 seconds:** short enough to demonstrate the full add/delete lifecycle in a single log capture. In production this would be longer, but not permanent by default — an attacker who spoofs a legitimate source IP can turn an auto-block into a self-inflicted denial of service, so permanent blocks belong behind analyst review.

## The command definition

`firewall-drop` is a default command that ships with Wazuh 4.x, already defined in `ossec.conf`. Listed here for reference:

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

`timeout_allowed` is what makes the 120s auto-unblock possible. Without it, the block would be permanent regardless of the `<timeout>` value in the active-response block.

## Applying it

After editing `ossec.conf`, restart the manager:

```bash
sudo systemctl restart wazuh-manager
```

## Verifying it fired

The response is confirmed on the agent side, not the manager:

```bash
sudo cat /var/ossec/logs/active-responses.log
```

A successful block writes two entries for the same source IP — the `add` when rule 100100 fires, then the `delete` 120 seconds later when the timeout expires. Both are visible in the log screenshot in the [main README](../README.md#attacks-detected).
