# Kernel Panic Receiver

Kernel Panic Receiver is a simple Python library for processing kernel panic logs and sending them to Sentry.

The only thing the tool does is receiving UDP packages with kernel panic logs from different hosts and calling different hooks (whether default or user-defined) that parse logs and return the specific value that will be sent to Sentry.

## Installation

You have to set up clients' machines (on which there will be panics supposed) and a server where Kernel Panic Receiver will work (it may be a server where Sentry works). When panic is happening a kernel (client) sends the logs to your server with Kernel Panic Receiver, it receives the logs, processes them and sends to Sentry.

### Installation on a client (kernel) side

**CloudLinux**

**1.** Update the initscripts package to >= cl6: 9.03.61-1; cl7: 9.49.49-1; cl8: 10.00.4-1 version with the .cloudlinux postfix. 
```
sudo yum update initscripts
```

(!) If you are on CloudLinux 6, your kernel version must be >= 2.6.32-954.3.5.lve1.4-79.el6 to support proper netconsole configuration. Otherwise, the feature will not work.

By default this package fetches configuration for sending logs to the CloudLinux server for fast responding on kernel panics. If you want to configure netconsole to send panic logs to your server, see the steps below.

**CentOS**

**1.** Configure netconsole. To do this, open a config file (CentOS 6/7/8: `/etc/sysconfig/netconsole`) and specify an IP of your server `SYSLOGADDR=your-server-ip`. Restart netconsole service.
```
sudo service netconsole restart
```
Also you can specify a port(SYSLOGPORT). The default is 514.

**2.** Add to netconsole the `oops_only=1` parameter. To turn the parameter on permanently, open the file (CentOS 6/7: `/etc/rc.d/init.d/netconsole`, CentOS 8: `/usr/libexec/netconsole`) and add to the variable SYSLOGOPTS `oops_only=1`.

(!) CentOS 6 may not have this feature. As workaround you can use 'dmesg -n emerg', but keep in mind that it affects all consoles (not only netconsole), make sure this way is appropriate for you.

Then run the following command (if you use CentOS 7/8):

```
systemctl daemon-reload
```

Restart netconsole service:
```
service netconsole restart
```

### Installation on a server side

**1.** Clone this repository
```
git clone https://clgit.com/thisrepo; cd ./thisrepo
```
**2.** Run install.sh as root (you should have Python3 installed on your server)
```
sudo ./install.sh
```
**3.** That's all.

## Usage

#### The simplest example with parsing kernel version

```python
import kernel_panic_receiver

def parse_kernel_version(addr, klogs):
    start_idx = klogs.find('.el')
    end_idx = start_idx

    if start_idx == -1:
        return ['kernel_version', "unknown"]

    while klogs[start_idx - 1] != ' ' or klogs[end_idx] != ' ':
        if (klogs[start_idx - 1] != ' '):
            start_idx -= 1
        if (klogs[end_idx] != ' '):
            end_idx += 1

    return ['kernel_version', klogs[start_idx:end_idx]]

kreceiver = kernel_panic_receiver.KernelPanicReceiver('your-server-ip', 514, 'https://dsn_sentry')
kreceiver.register_parser_tag(parse_kernel_version)
kreceiver.start_receiving_logs()

```

your-server-ip - is your server's IP a listening socket will be bound with.

dsn_sentry - Sentry DSN. You can find it in the project settings in the Sentry web interface.

## API Reference
```python
class KernelPanicReceiver(listen_ip, listen_port, sentry_dsn):
```
The main class. Takes three parameters: an IP / port it will listen to and the Sentry's DSN.

```python
method register_parser_title(function)
method register_parser_user(function)
method register_parser_fingerprint(function)
method register_parser_message(function)
```

Set functions to parse title, user ID, fingerprint (Sentry will filter different items by it) and message accordingly.

There is the default implementation of the functions in the KernelPanicReceiver class.

Function prototype: `def parse_function(addr, klogs)` where addr is a list of IP and port, klogs is a string with all panic logs.

Return value: string

```python
method register_parser_tag(function)
```
Register a function that will be called when all logs are received and put function's returned value into a **tag section**. The function may parse the logs and must return a **list** (or None) with two fields, the first one will be interpreted as a name of a tag, the second one as a value of a tag.

Function prototype: `def parse_function(addr, klogs)` where addr is a list of IP and port, klogs is a string with all panic logs.

Return value: none

```python
method register_parser_extra(function)
```
Register a function that will be called when all logs are received and put function's returned value into an **extra section**. The function may parse the logs and must return a list (or None) with two fields, the first one will be interpreted as a name of a tag, the second one as a value of a tag.

Function prototype: `def parse_function(addr, klogs)` where addr is a list of IP and port, klogs is a string with all panic logs.

Return value: none

```python
method unregister_parser_tag(function)
```
Unregister a function registered by the register_parser_tag().

Function prototype: `def parse_function(addr, klogs)` where addr is a list of IP and port, klogs is a string with all panic logs.

Return value: True - success; False - fail.

```python
method unregister_parser_extra(function)
```
Unregister a function registered by the register_parser_extra(). Not implemented yet.

Function prototype: `def parse_function(addr, klogs)` where addr is a list of IP and port, klogs is a string with all panic logs.

Return value: True - success; False - fail.

```python
method start_receiving_logs(function)
```
Start listening to logs on specified IP/port. Blocking function.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[GNU GPLv2](https://choosealicense.com/licenses/gpl-2.0/)

