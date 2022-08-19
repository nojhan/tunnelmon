tunnelmon -- Monitor and manage autoSSH tunnels
================================================

## SYNOPSIS

`tunnelmon` [-h]

`tunnelmon` [-c] [-n] [-u] [-l LEVEL] [-g FILE]


## DESCRIPTION

`tunnelmon` is an autossh tunnel monitor. It gives a user interface to monitor existing SSH tunnel, and tunnels managed with autossh. 

It can print the current state of your tunnels or display them in an interactive text-based interface.

`tunnelmon` is released under the GNU Public License v3.

![Screenshot](https://raw.github.com/nojhan/tunnelmon/master/screenshot.png)


## INSTALLATION

`tunnelmon` targets Linux operating systems, and depends on:
* `openssh-client`,
* `python` version 3.8 at least, you may also need to install the following python modules (for example via `pip`, but you may use any other package management system going along with your installation):
  * `psutils`
  * `curses`

You may also want to install the recommend packages:
* `autossh`


## OPTIONS

Called without option,`tunnelmon` will print the current state of the autossh tunnels and exit.

* `-h`, `--help`:
  Show a help message and exit

* `-c`, `--curses`:
  Start the interactive user interface. Tunnels states will be updated regularly and you will be able to control them (see below).

* `-n`, `--connections`:
  Display only SSH connections related to a tunnel.

* `-u`, `--tunnels`:
  Only display the list of tunnels processes.

* `-l LEVEL`, `--log-level LEVEL`:
  Control the verbosity of the logging, the greater, the more verbose. Available log levels are: `error` < `warning` <
  `debug`. Defaults to `error`, which only prints unrecoverable problems.

* `-g FILE`, `--log-file FILE`:
  Log messages are written to the given FILE. Useful to debug the interactive interface.
  If not set, asking for the curses interface automatically set logging to the "tunnelmon.log" file.


## INTERACTIVE INTERFACE

Keyboard commands:

* `↑` and `↓`: Select a tunnel.
* `R`: Reload the selected autossh instance (i.e. send a `SIGUSR1`, which is interpreted as a reload command by autossh).
* `C`: Close the selected tunnel (i.e. send a `SIGTERM`).
* `N`: Show the network connections related to each tunnel instances.
* `Q`: Quit tunnelmon.


## DISPLAY

Tunnelmon displays a table where lines are [auto]ssh processes that sets up a tunnel.
Columns of the table indicates:
- TYPE: `auto` if the process is managed by autossh, `ssh` if it is a "raw" SSH tunnel;
- FORWARD: the type of port forwarding method (either `local`, `remote` or `dynamic`, see the SSH manual for details);
- SSHPID: the process identifier;
- INPORT: the client port;
- VIA: the client host;
- TARGET: the host address;
- OUTPORT: the host port.

The interactive interface adds a CONNECTIONS columns that displays one vertical bar for each connection set up by the tunnel.

If you ask for showing the connections list (typing `N` in the interactive interface, or not passing `-u` to the command line one),
Tunnelmon will show indented lines with the type of the connection, its status and the related address:port informations.

In the interactive interface, different colors are used for:
- the tunnel type,
- the port forwarding methods,
- privileged and unprivileged ports,
- loopback, private and regular addresses.


## SSH Tunnels in a nutshell

To open a tunnel to port 1234 of `server` through a `host` reached on port 4567:
```sh
ssh -N host -L4567:server:1234
```
You may add `-f` to run ssh in the background.

Autossh can restart tunnels for you, in case they crash:
```
autossh -f host -L4567:server:1234
```

