
## Documentation for the vscpl2drv-websocksrv driver

**Document version:** ${/var/document-version} - ${/var/creation-time}
[HISTORY](./history.md)


![driver model](/images/xmap-vscpl2drv-websocksrv.png)

The websocket driver is a level II driver and act as a websocket server for the VSCP ws1 and ws2 websocket protocols. Users or IoT/m2m devices with different privileges and rights can connect to the exported interface and send/receive VSCP events. Typically this is a web based HMI or IoT/m2m device that uses the VSCP protocol to communicate. This makes it very easy to display data from the VSCP network in a web browser widget or graphical control panel.

It is also possible to serve static web content with the driver. This can be used to serve a simple web based HMI.

The VSCP ws1 and ws2 websocket protocols are described [here](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_websocket).

The level II driver is [described here](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_driver_interfaces). With the simple interface API the VSCP level II driver uses (described above) it is also easy to use it with other software as a component.

The connection can be secured with TLS/SSL as well as a simple user authentication mechanism.

* [Repository for the module](https://github.com/grodansparadis/${/var/driver-name})
* This manual is available [here](https://grodansparadis.github.io/${/var/driver-name})


## VSCP - the Very Simple Control Protocol (framework)

![VSCP logo](./images/logo_100.png)

VSCP is a free and open automation protocol for IoT and m2m devices. Visit [the VSCP site](https://www.vscp.org) for more information.

**VSCP is free.** Placed in the **public domain**. Free to use. Free to change. Free to do whatever you want to do with it. VSCP is not owned by anyone. VSCP will stay free and gratis forever.

The specification for the VSCP protocol is [here](https://grodansparadis.github.io/vscp-doc-spec/#/) 

VSCP documentation for various parts of the protocol/framework can be found [here](https://docs.vscp.org/).

If you use VSCP please consider contributing resources or time to the project ([https://github.com/sponsors/grodansparadis](https://github.com/sponsors/grodansparadis)).


## Document license

This document is licensed under [Creative Commons BY 4.0](https://creativecommons.org/licenses/by/4.0/) and can be freely copied, redistributed, remixed, transformed, built upon as long as you give credits to the author.


[filename](./bottom-copyright.md ':include')
