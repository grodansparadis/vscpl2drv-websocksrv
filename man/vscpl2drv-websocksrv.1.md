% vscpl2drv-tcpipsrv(1) VSCP Level II tcp/ip server Driver
% Åke Hedmann, the VSCP Project
% October 30, 2025

# NAME

vscpl2drv-websocksrv - VSCP Level II websocket server driver

# SYNOPSIS

vscpl2drv-websocksrv

# DESCRIPTION

The websocket driver is a level II driver and act as a websocket server for the [VSCP ws1 and ws2 websocket protocols](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_websocket). Users or IoT/m2m devices with different privileges and rights can connect to the exported interface and send/receive VSCP events. Typically this is a web based HMI or IoT/m2m device that uses the VSCP protocol to communicate. This makes it very easy to display data from the VSCP network in a web browser widget or graphical control panel.

The VSCP ws1 and ws2 websocket protocols are described [here](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_websocket).

With the simple interface the VSCP level II driver uses ([described here](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_driver_interfaces)) it is also possible to use it with other software as a component. 

## Configuration

The *configuration string* is the first configuration data that is read by the driver. The driver will, after it is read and parsed, ask the server for driver specific configuration data. This data is fetched with the same pattern for all drivers. Variables are formed by the driver name + some driver specific remote variable name. If this variable exist and contains data it will be used as configuration for the driver regardless of the content of the configuration string.

### Adding the driver to the VSCP daemon.

Add the driver to the vscpd configuration file (default location */etc/vscp/vscpd.conf*). THis entry looks the same for all level II drivers.

```xml
<driver enable="true" >
    <name>socketcan1</name>
    <path>/usr/lib/vscpl2drv_tcpiplink.so</path>
    <config>can</config>
    <guid>FF:FF:FF:FF:FF:FF:FF:FE:B8:27:EB:0A:11:02:00:00</guid>
</driver>
```

* **name** is the name of the driver. Set a name that has some meaning for you.
* **path** points to the location where the driver is installed.
* **config** is the configuration string. This string contains configuration  entries separated by semicolon.
* **guid** is the GUID that should be used to referee to this driver and devices handled by it. If you set a GUID (and you should) the two least significant digits should be set to zero. If absent or not set the VSCP daemon will set a GUID for you.

In the configuration example above the driver will fetch configuration data from the server from variables *socketcan1_interface*, *socketcan1_filter* and  *socketcan1_mask*

### Configuration string

```bash
interface
```

#### Interface

The parameter interface is the socketcan interface to use. Typically this is can0, can0, can1... Defaults is vcan0, the first virtual interface. If the remote variable **prefix**_interface is available it will be used instead of the configuration value. "**prefix**" is the name given to the driver in *vscpd.conf*

### Remote variables

The following configuration remote variables are defined

| Remote variable name | Type   | Description |
 | ------------- | ----   | -----------   |
 | **_interface**    | string | The socketcan interface to use. Typically this is “can0, can0, can1...” Defaults is vcan0 the first virtual interface. |
 | **_filter**       | string | Standard VSCP filter on string form. Used to filter what events that is received from the socketcan interface. If not give all events are received. |
 | **_mask**         | string | Standard VSCP mask in string form.  Used to filter what events that is received from the socketcan interface. If not give all events are received.   |
 | **config** | json | All of the above as a JSON object. |

#### Filter string form
1,0x0000,0x0006,ff:ff:ff:ff:ff:ff:ff:01:00:00:00:00:00:00:00:00 as priority,class,type,GUID

#### Mask string form
1,0x0000,0x0006,ff:ff:ff:ff:ff:ff:ff:01:00:00:00:00:00:00:00:00 as priority,class,type,GUID

---

There are many Level I/II/III drivers available in VSCP & Friends framework that can be used with both VSCP Works and the VSCP Daemon and added to that Level II and Level III drivers that can be used with the VSCP Daemon.

Level I drivers is documented [here](https://grodansparadis.gitbooks.io/the-vscp-daemon/level_i_drivers.html).

Level II drivers is documented [here](https://grodansparadis.gitbooks.io/the-vscp-daemon/level_ii_drivers.html)

Level III drivers is documented [here](https://grodansparadis.gitbooks.io/the-vscp-daemon/level_iii_drivers.html)

# SEE ALSO

`vscpd` (8).
`uvscpd` (8).
`vscpworks` (1).
`vscpcmd` (1).
`vscp-makepassword` (1).
`vscphelperlib` (1).

The VSCP project homepage is here <https://www.vscp.org>.

The [manual](https://grodansparadis.gitbooks.io/the-vscp-daemon) for vscpd contains full documentation. Other documentation can be found here <https://grodansparadis.gitbooks.io>.

The vscpd source code may be downloaded from <https://github.com/grodansparadis/vscp>. Source code for other system components of VSCP & Friends are here <https://github.com/grodansparadis>

# COPYRIGHT
Copyright 2000-2021 Åke Hedman, the VSCP Project - MIT license.




