# Lycan CLI

A small, open-source command-line tool that shows the open doors (ports) on your own computer and your own network.
Companion to the passive website scanner at https://lycansoc.com.

> **Use it only on machines you own or have written permission to test.**
> Scanning other people's systems without permission can be a crime (for example under Turkish Penal Code art. 243, the UK Computer Misuse Act or the US CFAA).
> To help with that, `lycan hunt` refuses public internet addresses and only works inside private networks.

## Install

Needs Python 3.10 or newer.

```
pip install git+https://github.com/cagtas0/lycan-tool.git
```

## Commands

### `lycan scan`
Lists the ports listening on **this** computer, which program opened each one, and whether it can be reached from the network or only from this machine. Nothing is sent over the network; it asks the operating system.

```
PROTO ADDRESS                       PORT  REACH     PROCESS (PID)
TCP   0.0.0.0                        445  network   System (4)
TCP   127.0.0.1                    65001  local     nvcontainer.exe (5196)
```

### `lycan hunt <target>`
Checks which ports are open on a machine **in your own network** (127.x, 10.x, 172.16–31.x, 192.168.x), for example a virtual machine you set up for practice. By default it checks 20 common ports and explains each one it finds.

```
lycan hunt 192.168.1.20
lycan hunt 192.168.1.20 --ports 1-1024
```

Add `--banner` to also read what each open port says when you connect (its "banner"), and show the program and version behind it. Web ports get one `HEAD /` request. Anything that is not plain text is stripped before it is printed.

```
lycan hunt 192.168.1.20 --banner

  PORT  SERVICE     VERSION                       NOTE
    22  ssh         OpenSSH 9.2p1                 Remote login. ...
    80  http        Apache 2.4.62                 Web server without encryption.
```

Add `--cve` to also look up known vulnerabilities (CVEs) for each version found, in the US National Vulnerability Database (NVD). It needs internet and implies `--banner`. Only the product and version are sent (for example `OpenSSH 9.2p1`), never the address you scanned. Answers are cached for one day in `~/.lycan/cve-cache.json`. Without a key NVD allows about 5 requests per 30 seconds, so Lycan waits between requests; set `NVD_API_KEY` (free from NVD) to go faster.

```
lycan hunt 192.168.1.20 --cve

    22  OpenSSH 9.2p1: 35 possible CVEs (3 critical, 10 high)
        Debian build: fixes are often added without changing the version.
        Check the installed package version with your package manager before acting.
        CVE-2023-38408   9.8 CRITICAL The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 ...
```

These are **possible** matches: NVD only looks at the version number. Linux distributions such as Debian and Ubuntu fix bugs without changing it, so a listed CVE may already be fixed on your machine.

Limits, on purpose: one machine at a time, at most 1024 ports per run, 50 checks at once. Public addresses and names that resolve to them are refused before any packet is sent.

Add `--save hunt.json` to keep the result as a JSON file for `report` and later comparison.

### `lycan report <file.json>`
Turns a saved hunt into a single HTML file you can open in any browser: summary cards, a "do these first" list, every open port with its version, and the possible CVEs with links to NVD. The page loads nothing from the internet and runs no scripts; text that came from the scanned machine is escaped so it can never act as HTML.

```
lycan hunt 192.168.1.20 --cve --save hunt.json
lycan report hunt.json --open
```

### `lycan watch <target>`
Hunts again and tells you what changed since the first time: ports that opened or closed, versions that changed and new possible CVEs. The first run saves a baseline in `~/.lycan/baselines/`. When something changed it exits with code 1, so it works in a scheduled task. If the change is expected, accept it with `--update`. Takes the same options and address rules as `hunt`.

```
lycan watch 192.168.1.20 --banner
  ! Port 3389 (rdp) is now OPEN. It was closed before.
```

### `lycan version`
Prints the installed version.

## What it does not do

No exploits, no password guessing, no hiding from detection, no scanning of address ranges. It only knocks on doors, tells you which ones are open and, if you ask, reads the name plate on each door.

## Development

```
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -e .
python -m unittest -v
```

## License

MIT, see [LICENSE](LICENSE). Provided as is, without warranty.

---

**Türkçe:** Lycan CLI, kendi bilgisayarındaki ve kendi ağındaki açık kapıları (portları) gösteren açık kaynak bir araçtır. Yalnızca sahibi olduğun ya da yazılı izin aldığın sistemlerde kullan; izinsiz tarama TCK 243 kapsamında suç olabilir. `lycan hunt` internetteki adresleri reddeder, yalnızca özel ağda çalışır.
