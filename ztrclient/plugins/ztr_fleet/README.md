# ZTR Fleet

Run a command, a script or a file transfer on several servers at once, each
one reached through its own ZTRelay route. Every server answers as it
finishes; you see each answer, which servers answered the same way, and which
ones didn't.

```bash
ztr_fleet 'uptime'                            # one command on every server
ztr_fleet --group web 'df -h /'               # only the servers in a group
ztr_fleet --script deploy.sh --batch 2        # a local script, two servers at a time
ztr_fleet --put app.conf --to /tmp/           # send a file to every server
ztr_fleet --get /var/log/syslog --into logs   # fetch a file from every server
ztr_fleet --shell web1                        # a terminal on one server
ztr_fleet --gui                               # the same thing in a window
```

Run it as `plugins/ztr_fleet/ztr_fleet` from the client folder, or link it
onto your `PATH`. `ztr_fleet --help` lists every option.

## What you need

- The tunnel service running (`ztr_tunnel_lp.py`, set up by the installer's
  `--with-service`). Fleet opens a tunnel for each server through it.
- A route file in `routes/` for each route you use.
- ssh key login to the servers, with the key in your ssh agent or in `~/.ssh`
  (or named per server in the fleet file). Fleet never types a password,
  except the sudo password you choose to send (see below).
- `ssh` and `scp` on this computer, and Python 3.8 or newer. The window also
  needs Python's Tk 8.6 or newer (Linux: `sudo apt install python3-tk`;
  macOS: `brew install python-tk@3.13`).

## The fleet file

One server per line: a name, the route file, the server's alias (the
`…._ztr` name or an address), the ssh user, the ssh port (`-` for 22), then
optional extras.

```text
# name    route file     alias (--rh)       user     port   options
web1      web.ztr        web1._ztr          deploy   22     group=web env=prod
web2      web.ztr        web2._ztr          deploy   -      group=web env=staging
db1       data.ztr       db1._ztr           deploy   -      group=data key=~/.ssh/id_db
```

It is read from `./fleet.conf` if that exists, otherwise from
`~/.config/ztr_fleet/fleet.conf`; `--file` or `ZTR_FLEET_FILE` choose another.
`ztr_fleet --example` prints a sample and `ztr_fleet --check` looks the file
over without connecting to anything. The window can add, edit and remove
servers, and import the sites you saved in Ferry. To remove one, double-click it
and press **Remove server**, or right-click it; **Remove ticked servers…** under
the list removes every ticked server at once. Removing takes a server out of
the fleet file only; the server itself is untouched.

The extras are `group=NAME`, `key=PATH` (an ssh key for that server) and your
own `NAME=value` variables.

## Variables

A command can use `{name}`, `{alias}`, `{user}`, `{port}`, `{route}`,
`{group}` and any variable from the fleet file; each server fills in its own
values.

```bash
ztr_fleet 'echo {name} is {env}'
```

Write `{{name}}` to keep the braces. A command that uses a variable some
server doesn't have is refused before anything connects. A script isn't
rewritten; it receives the same values as `ZTR_NAME`, `ZTR_ENV` and so on.

## Rolling out safely

- `--batch N` runs N servers at a time and stops at the first failure; the
  servers that never ran are marked as skipped. `--canary` runs on one
  server first and goes on only if it succeeds, `--pause SECONDS` waits
  between batches, and `--keep-going` carries on past a failure.
- `--retries N` tries a failed server again, up to N more times
  (`--retry-wait` sets the gap).
- A command that looks destructive (`rm -r`, `mkfs`, a reboot, dropping a
  database…) asks you to confirm first, or needs `--yes`.
- `--dry-run` shows what would run where, and connects to nothing.
- `--jobs` sets how many servers are contacted at once, `--timeout` how long
  each may take.

### sudo

`--ask-sudo` asks for your sudo password once and sends it to sudo on each
server; `--sudo-each` asks for a different password per server. The password
travels only over the ssh connection, on standard input. It is never put in a
command line or a file, and a server with passwordless sudo never uses it.

## Hooks: scripts that get the answers

A hook is a script on your computer that Fleet runs with each answer, for
example to save the IP addresses a firewall reports, add a row to a CSV, or
raise an alert.

```bash
ztr_fleet --hook ./save_ips.sh 'sudo ufw status | grep DENY'
```

- A hook runs once per server, after that server answers. It receives the
  answer on standard input, and `--server NAME --status ok --answer-file PATH
  --error-file PATH` as arguments. The server's values are in `ZTR_NAME`,
  `ZTR_ALIAS`, `ZTR_USER` and the rest. It is started without a shell, in its
  own folder, and stopped after 60 seconds.
- A hook given with `--hook-all` runs once at the end and receives every
  answer as JSON, on standard input and in `--results-file`.
- Hooks normally run for servers that succeeded; `--hook-failed` includes the
  others.
- A hook can propose a next step by printing a line such as
  `FLEET-NEXT {"title": "Block 203.0.113.7", "command": "sudo ufw deny from
  203.0.113.7", "all": true}` (use `"servers": [...]` or `"group": "web"` to
  name the targets). Fleet shows these for you to review and never runs one by
  itself.

An answer comes from the server, so treat it as untrusted text: don't run it
or paste it into a command.

In the window, **More options → After each answer** opens the hook manager.
It lists your hooks with a switch each and lets you:

- add a script, or start from a template (save the IP addresses in an answer,
  add every answer to a log, save each server's answer in its own file, add a
  CSV row per server, or a blank script);
- limit a hook to certain servers or groups, or to answers that contain a
  word or pattern, and choose whether it also runs for failed servers or once
  at the end for everything;
- try a hook on a real or sample answer before using it for real.

Scripts you drop in `~/.config/ztr_fleet/hooks/` appear in the list switched
off. The templates write their results to `~/fleet-results` (or the folder in
`ZTR_FLEET_OUT`). `--saved-hooks` runs the hooks you have switched on, with
their limits, from the command line.

## Scheduled runs

In the window, set up a run and press **Schedule…** to repeat it every few
minutes or hours, every day, or every week. The **Schedules** tab lists the
saved jobs with their next and last run, and can run, edit, pause, load or
delete each one. A scheduled run goes to your switched-on hooks like any other
run, and its answers are kept in History.

On Linux a schedule is a systemd user timer, which runs while you are logged
in; `loginctl enable-linger $USER` keeps it running after you log out.
A route whose `.ztr` has an `exit_country` shows it next to the route name in the
server list, the Add/Edit dialog and the previews (`US  ·  web.ztr`), and typing
`us` in the server filter finds the servers that leave in the US. In the server list
and on each answer the country is shown as a small flag (about 70 countries; any
other shows its two-letter code).

On macOS a schedule is a launchd agent, and macOS keeps background jobs out of
your Downloads, Desktop and Documents folders. If the client (or the fleet file
or script a job uses) is in one of them, Fleet says so and won't switch the
schedule on; keep the client somewhere else, for example `~/ztrclient`. Each
job's output goes to `~/.config/ztr_fleet/logs/NAME.log` (the Schedules tab has a
**Log** button), and a schedule that is on but can't start says why instead of
"Hasn't run yet". A
scheduled run can't ask for a sudo password, so use passwordless sudo for
those, and a destructive command is confirmed once, when you save the job.
`ztr_fleet --list-jobs` lists the saved jobs and `ztr_fleet --run-job NAME`
runs one exactly as saved, which is what a schedule calls.

## The window

`ztr_fleet --gui` opens it. On the left are your servers, with groups, a
filter, and a dot for how each did last time. On the right you choose what to
run — a command, a script, files to send or files to fetch — and watch the
answers arrive.

- **Answers** shows each server's answer as it arrives, with how long it took
  and a **Full answer** button for long output. **Compare** groups servers
  that answered the same way and highlights the odd ones out (with an option
  to ignore numbers). **History** keeps recent runs to look at or run again.
- **Preview** shows what a run would do, including the exact command Fleet
  uses for each server, before anything is contacted.
- **Retry the ones that failed** runs it again on just those servers.
- **Shell** (on each answer, and in the server's right-click menu) opens a
  terminal on that server through its route. Set `FLEET_TERMINAL` (for
  example `xterm -e`) to choose the terminal program.
- Saved commands, **Copy** and **Save…** for the answers, and a status light
  for the tunnel service are on the same page.

`python3 plugins/ztr_fleet/ztr_fleet_gui.py --demo` opens the window with
pretend servers and contacts nothing.

## Output

Each result prints as soon as its server finishes; `--ordered` waits and
prints them in fleet-file order. `--json` prints one line per server and a
summary, and `--out DIR` also saves every server's output in its own file.
The exit code is 0 when every server succeeded, 1 when any did not, and 2 when
the fleet file, the options or the setup are wrong.

## Where things live

- `~/.config/ztr_fleet/` holds `fleet.conf`, saved commands (`snippets.json`),
  history (`history.json`, readable only by you, since answers can hold
  anything a command printed), the hook list (`hooks.json` and `hooks/`) and
  saved jobs (`jobs.json`). `ZTR_FLEET_HOME` moves the folder.
- `~/.config/ztr_fleet/known_hosts` keeps each server's ssh host key under its
  name, so the changing tunnel ports never look like a new server, and a key
  that changes is refused. `ZTR_FLEET_KNOWN_HOSTS` points elsewhere.

## Files

- `ztr_fleet` — the launcher.
- `ztr_fleet_core.py` — the command line and the engine behind both.
- `ztr_fleet_gui.py` — the window.
