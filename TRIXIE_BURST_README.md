# Trixie Deluge Burst Storage

This is the replacement for the old Buster `burst_provision_local.sh` and
`burst_teardown_local.sh` pair.

## Design

The normal Trixie setup keeps Deluge under:

- Incomplete downloads: `/srv/deluge/Downloads`
- Finished downloads: `/srv/deluge/Finished`
- Rsync daemon module: `finished` -> `/srv/deluge/Finished`

Burst mode temporarily creates a Scaleway SBS block volume and mounts it at:

- Burst mount: `/srv/deluge/.burst`
- Burst incomplete downloads: `/srv/deluge/.burst/incomplete`
- Burst completed downloads: `/srv/deluge/.burst/completed`
- Rsync-visible bind mount: `/srv/deluge/Finished/_overflow`

When burst mode is active, Deluge is reconfigured to download new torrents into
the burst incomplete directory and move completed data into
`/srv/deluge/.burst/completed`. That real completed directory is bind-mounted at
`/srv/deluge/Finished/_overflow`. Because `_overflow` is inside the existing
`Finished` tree, the Synology rsync pull keeps using the same `finished` module.
The hidden incomplete directory is not visible to the rsync module.

Deluge must use `/srv/deluge/.burst/completed` as its completed path, not the
bind-mounted `/srv/deluge/Finished/_overflow` view. Moving from the real burst
incomplete directory to the bind-mounted view can degrade into a copy-then-delete
operation and temporarily require roughly 2x the torrent size.

The controller only changes Deluge's path settings:

- `download_location`
- `move_completed`
- `move_completed_path`

It does not change Deluge plugins, labels, ltConfig, Sonarr, or Radarr settings.
The Label plugin can keep using `ingested` so the cleanup script removes torrents
after Sonarr/Radarr ingestion.

## Files

- `deluge_burstctl.sh`: root-only controller with `provision`, `teardown`,
  `repair-active`, `restore-base`, and `status`.
- `remove_oversized_torrents.py`: cron-safe cleanup script that reads Deluge's
  current active download path, so it works during normal and burst modes.
- `install_trixie_burst.sh`: installs the controller, cleanup script, cron entry,
  and optional passwordless sudo policy for an SSH user.

## Debian Deployment

Copy these files to the Debian box, then run:

```bash
sudo bash install_trixie_burst.sh --shortcut-user YOUR_SSH_USER
```

For an IPv6-only box that needs Tailscale for IPv4 API egress, save the exit
node at install time without putting the node name in this repo:

```bash
sudo bash install_trixie_burst.sh \
  --shortcut-user YOUR_SSH_USER \
  --prompt-tailscale-exit-node
```

The prompt writes the value only to `/etc/default/deluge-burst` on the Debian
box. You can also pass `--tailscale-exit-node <node>` explicitly if you are not
concerned about shell history on that host.

If auto-detecting the Scaleway server ID fails, rerun the installer with:

```bash
sudo bash install_trixie_burst.sh \
  --shortcut-user YOUR_SSH_USER \
  --prompt-tailscale-exit-node \
  --prompt-server-id \
  --zone nl-ams-1
```

The server ID is stored locally in `/etc/default/deluge-burst` as
`DELUGE_BURST_SERVER_ID`.

If you already have a cron entry for `remove_oversized_torrents.py`, either point
it at `/usr/local/sbin/remove_oversized_torrents.py` or remove the old duplicate
after the installer creates `/etc/cron.d/deluge-remove-oversized`.

The burst controller expects the Scaleway CLI (`scw`) to be installed and
authenticated on the Debian box. It also uses `python3`, `lsblk`, `blkid`,
`mount`, `findmnt`, `flock`, and `systemctl`, which are normally present on the
Trixie server except for provider-specific tools. If `curl` is present, the
controller uses Scaleway instance metadata to auto-detect the server and zone;
otherwise it falls back to the Scaleway CLI.

The cleanup cron uses the Python `deluge_client` package, matching the existing
cron script's RPC approach. The installer warns if `/usr/bin/python3` cannot
import it.

## iPhone Shortcut Commands

Use the Shortcuts action "Run Script over SSH".

Provision 600 GB:

```bash
sudo -n /usr/local/sbin/deluge-burstctl provision --size-gb 600 --yes
```

Check status:

```bash
sudo -n /usr/local/sbin/deluge-burstctl status
```

Teardown after Synology/Sonarr/Radarr have drained `_overflow`:

```bash
sudo -n /usr/local/sbin/deluge-burstctl teardown --yes
```

Teardown refuses to delete the volume while either
`/srv/deluge/.burst/incomplete` or `/srv/deluge/.burst/completed` still contains
data.

## Operational Flow

1. Run `provision` from the iPhone before adding the large torrent.
2. Add the large torrent to Deluge as usual.
3. Completed burst downloads appear under `Finished/_overflow` for the existing
   Synology rsync pull.
4. Sonarr/Radarr ingest as usual. If they label the torrent `ingested`, the cron
   cleanup removes the torrent and its data.
5. Once `_overflow` and the burst incomplete directory are empty, run `teardown`.

If something looks half-active after a failed operation or reboot, run:

```bash
sudo /usr/local/sbin/deluge-burstctl status
```

If you only need to put Deluge back on the base disk without deleting a volume,
run:

```bash
sudo /usr/local/sbin/deluge-burstctl restore-base
```

If an active burst volume was provisioned by an older script version that set
Deluge's completed path to `/srv/deluge/Finished/_overflow`, repair it with:

```bash
sudo /usr/local/sbin/deluge-burstctl repair-active
```

## IPv6-Only Hosts

The Scaleway control-plane API may resolve to IPv4-only addresses from this
host. If the Deluge box has no IPv4 egress, `scw` commands can fail with
`dial tcp ... network is unreachable`.

Scaleway's Instance metadata service is local to the Instance, not a public DNS
name. On IPv6-only hosts, test the IPv6 metadata endpoint:

```bash
curl -g -6 --max-time 3 'http://[fd00:42::42]/conf?format=json'
```

The IPv4 metadata endpoint is `169.254.42.42`, but it may hang or be unrouted on
an IPv6-only host:

```bash
curl -4 --local-port 1-1023 --max-time 3 'http://169.254.42.42/conf?format=json'
```

The controller can do this automatically. Put the exit node in
`/etc/default/deluge-burst`:

```bash
DELUGE_BURST_TAILSCALE_EXIT_NODE=<exit-node-name-or-100.x.y.z>
DELUGE_BURST_TAILSCALE_ALLOW_LAN_ACCESS=true
DELUGE_BURST_TAILSCALE_RESTORE_ADVERTISE_EXIT_NODE=auto
DELUGE_BURST_SERVER_ID=<scaleway-server-id-if-autodetect-fails>
DELUGE_BURST_ZONE=nl-ams-1
```

Or pass it per command:

```bash
sudo /usr/local/sbin/deluge-burstctl provision --size-gb 600 --tailscale-exit-node <exit-node-name-or-100.x.y.z> --yes
```

When configured, `deluge-burstctl` temporarily disables exit-node advertising,
sets the requested exit node, runs the Scaleway API calls, clears the exit node,
and restores advertising if it was enabled before. Torrent traffic should not
remain routed through the exit node after the command finishes.

The cleaner long-term alternative is to run Scaleway API calls from an
IPv4-capable helper host, then SSH into the IPv6-only Deluge box only for the
local mount and Deluge path changes. That requires splitting the current
all-in-one controller into a remote control-plane script plus a local
mount/config script.
