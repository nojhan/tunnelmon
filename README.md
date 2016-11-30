ereshkigal -- Monitor and manage autoSSH tunnels
================================================

## SYNOPSIS

`ereshkigal` [-h]

`ereshkigal` [-c] [-n] [-a] [-l LEVEL] [-f FILE]


## DESCRIPTION

`ereshkigal` is an autossh tunnel monitor. It gives a user interface to monitor existing SSH tunnel that are managed with autossh. 

It can print the current state of your tunnels or display them in an interactive text-based interface.

`ereshkigal` is released under the GNU Public License v3.


## INSTALLATION

`ereshkigal` targets Linux operating systems, and depends on:
* `autossh` (which needs `OpenSSH`, obviously)
* `python` ≥ 2.4


## OPTIONS

Called without option,`ereshkigal` will print the current state of the autossh tunnels and exit.

* `-h`, `--help`:
  Show a help message and exit

* `-c`, `--curses`:
  Start the interactive user interface. Tunnels states will be updated regularly and you will be able to control them (see below).

* `-n`, `--connections`:
  Display only SSH connections related to a tunnel. This feature is only available as `root`, because it needs system permissions.

* `-a`, `--autossh`:
  Only display the list of `autossh` processes.

* `-l LEVEL`, `--log-level LEVEL`:
  Control the verbosity of the logging, the greater, the more verbose. Available log levels are: `error` < `warning` <
  `debug`. Defaults to `error`, which only prints unrecoverable problems.

* `-f FILE`, `--log-file FILE`:
  Log messages are written to the given FILE. Useful to debug the interactive interface.
  If not set, asking for the curses interface automatically set logging to the "ereshkigal.log" file.


## INTERACTIVE INTERFACE

Keyboard commands:

* `R`: Reload the selected autossh instance (i.e. send a `SIGUSR1`, which is interpreted as a reload command by autossh).
* `K`: Kill the selected autossh instance (i.e. send a `SIGKILL`).
* `T`: (only available as root) show the tunnel connections related to each autossh instances.
* `Q`: quit ereshkigal.

