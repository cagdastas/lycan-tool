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

Limits, on purpose: one machine at a time, at most 1024 ports per run, 50 checks at once. Public addresses and names that resolve to them are refused before any packet is sent.

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
