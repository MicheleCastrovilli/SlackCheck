# SlackCheck
## eBPF version

To build, run the `get_deps.sh` script in the main folder, in order to get the 
libbpf-bootstrap git repo. Then cd into the folder and `make`.

```
sh ../get_deps.sh
cd src
make
```

To use, open a process, get its PID and with the following command line:
```
sudo ./slackcheck -p <process ID> -a <alpha numerator> -d <alpha denominator> -l <latency in ns>
```
will print the slack of the process as it's running.
