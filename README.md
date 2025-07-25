Calimero KNXnet/IP Server [![CI with Gradle](https://github.com/calimero-project/calimero-server/actions/workflows/gradle.yml/badge.svg)](https://github.com/calimero-project/calimero-server/actions/workflows/gradle.yml) [![](https://jitpack.io/v/calimero-project/calimero-server.svg)](https://jitpack.io/#calimero-project/calimero-server) [![](https://img.shields.io/badge/jitpack-master-brightgreen?label=JitPack)](https://jitpack.io/#calimero-project/calimero-server/master)
=========================

A KNXnet/IP server for running your own KNXnet/IP server in software. The minimum required runtime environment is [JDK 21](https://www.oracle.com/java/technologies/downloads/) (_java.base_).

* No KNXnet/IP server hardware required
* Turn a KNX interface into a KNXnet/IP server, e.g., KNX USB or KNX RF USB interfaces, EMI1/2 serial couplers 
* Use KNX IP Secure to secure your client-side KNX IP network traffic
* Intercept or proxy a KNXnet/IP connection, e.g., for monitoring/debugging purposes
* Set up a (secure) time-server for your KNX network
* Emulate/virtualize a KNX network


### Dependencies

The Calimero KNXnet/IP server requires `calimero-core` and `calimero-device`.
_Optional_ dependencies, required for serial communication:

* TP-UART / FT1.2: `serial-native` (with its JNI libraries), or `calimero-rxtx` for using any RXTX descendant/compatible library on your platform.
  If you run Java 22, you can also use `calimero-serial-ffm` to leverage the Foreign Function & Memory API.
* KNX USB or KNX RF USB: `calimero-usb` (and its transitive closure).

### Docker image

Pre-built Docker images for running the server are available on [Docker Hub](https://hub.docker.com/r/calimeroproject/knxserver). These snapshots might be [ahead of the latest release](https://github.com/calimero-project/calimero-server/issues/14) but in general not less stable than releases.

Supported Features
------------------

### Client-side KNXnet/IP & KNX IP Secure
Note that for KNX IP Secure a keyfile or an ETS keyring (*.knxkeys) is required, see [section below](#knx-ip-secure).

* Discovery and self-description
* Tunneling: UDP, TCP (& Unix domain sockets with KNX Tunneling v2)
* Routing
* Busmonitor (for KNX subnet interfaces that do not support a dedicated busmonitor mode, KNXnet/IP bus monitor connections are realized by converting cEMI L-Data to cEMI bus monitor messages)
* Local device management

### KNX subnet side (communication with the KNX bus)
* KNXnet/IP
* KNX IP
* KNX RF USB
* KNX USB
* KNX FT1.2 Protocol
* TP-UART

How-to & Examples
-----------------

Note, running gradle build (e.g., `./gradlew build`) will also create _build/distributions/calimero-server-*.tar/.zip_, which contains a directly executable script and all required dependencies.

### Start Server

*Before trying the examples below with a configuration, make sure the configuration is appropriate for your KNX setup!*

On the terminal, a running server instance can be stopped by `Ctrl+C` or typing "stop".

#### Using Gradle

    ./gradlew run --args resources/server-config.xml

#### Using Java

Make sure all required `jar` packages are available, and any referenced files in the folder `resources` are found (e.g., copy them into the current working directory)

~~~ sh
# Either, assuming all jar dependencies are located in the current working directory
java -cp "./*" io.calimero.server.Launcher server-config.xml

# Or, a minimal working example with explicit references to jars (adjust as required)
java -cp "calimero-server-3.0-SNAPSHOT.jar:calimero-core-3.0-SNAPSHOT.jar:calimero-device-3.0-SNAPSHOT.jar" io.calimero.server.Launcher server-config.xml
~~~


### Server Configuration

A working example of an XML server configuration can be found [here](https://github.com/calimero-project/calimero-server/blob/master/resources/server-config.xml).

Description of the supported XML elements and attributes:

* `<knxServer name="knx-server" friendlyName="My KNXnet/IP Server">` (required): specifies the server ID (for logging etc.) and the KNXnet/IP friendly name (for discovery & self-description)

	- `name="knx-server"`: Attribute to specify the internal name of the server (mainly for logging, naming, debugging purposes)
	- `friendlyName="My KNXnet/IP Server"`: Attribute to specify a custom name (max. 30 characters). Will be displayed in e.g. ETS.
	- `appData="/path/to/app/dir"` (optional): base directory to load/save server application data, by default this is the empty path. The path might start with _~_, expanded to the Java system property _"user.home"_. The server's interface object server (IOS) data is stored in this directory between restarts. The `<serviceContainer>` attributes `keyfile` and `keyring` are resolved against this directory if they contain a relative path.

* `<discovery listenNetIf="all" outgoingNetIf="all" activate="true"/>` (optional attributes): the network interfaces to listen for KNXnet/IP discovery requests, as well as the network interfaces to answer requests, e.g., `"all"`, `"any"`, or `"lo,eth0,eth1"`. The attribute `activate` allows to disable KNXnet/IP discovery & self-description. If disabled, any received discovery or descriptions request will be ignored.

* `<serviceContainer>` (1..*): specify a server service container, i.e., the client-side endpoint for a KNX subnet. Attributes: 
	- `activate`: enable/disable the service container, to load/ignore that container during server startup
	- `routing`: if `true` activate KNX IP routing, if `false` routing is disabled
	- `networkMonitoring`: serve tunneling connection on KNX busmonitor layer (set `true`) or deny such connection requests (set `false`)
	- `udpPort` (optional): UDP port of the control endpoint to listen for incoming connection requests of that service container, defaults to KNXnet/IP standard port "3671". Use different ports if more than one service container is configured.
	- `netif` (optional): network adapter for client communication, e.g., `"eth1"`; defaults to host default network adapter. Use `"any"` for the first available (non-loopback) network adapter depending on your OS network setup (or localhost setting). 
    - `reuseCtrlEP` (optional): use the KNXnet/IP control endpoint (UDP/IP) for tunneling connections, `false` by default. If reuse is enabled (set `true`), no list of additional KNX individual addresses is required (see below). Per the KNX standard, reuse is only possible if the control endpoint's individual address is not yet assigned to a connection, and if KNXnet/IP routing is not activated. This implies that by reusing the control endpoint, at most 1 connection can be established at a time to a service container.
    - `keyfile="~/.knx/keyfile"` (required for KNX IP Secure): path to a keyfile containing the KNX IP Secure keys, alternatively specify a `keyring`. See [below](#knx-ip-secure) for the keyfile layout.
    - `keyring="/path/to/keyring.knxkeys"` (required for KNX IP Secure): path to a keyring exported from ETS containing the KNX IP Secure keys. The _keyfile_ typically contains the password to decrypt the keyring, otherwise the server will try to query the keyring password from the system console during startup.
    - `securedServices` (optional): specify a set of required KNXnet/IP secure services. Supported values are a combination of `devmgmt`, `tunneling`, and `routing`. A value of `optional` configures secured services, but clients can also use unsecure communication. If this attribute is not used, by default the server requires KNXnet/IP secure services as supplied by a keyring/keyfile.

* `<knxAddress type="individual">7.1.0</knxAddress>`: the individual address of the service container (has to match the KNX subnet!)
    - `type="individual"`: indicates a device address.
    - `x.y.z`: Address of the service container, will be visible in e.g. ETS-tool. If routing is activated, requires a coupler/backbone address (`x.y.0` or `x.0.0`).
* `<disruptionBuffer expirationTimeout="30" udpPort="5555-5559" />`: When `disruptionBuffer` is activated, missed KNX subnet frames due to a disrupted client link will be replayed when the client connection is reestablished.
    - `expirationTimeout="30"`: Attribute allows to specify the time in seconds how long the server will keep frames before discarding them after a connection was disrupted.
    - `udpPort="5555-5559"`: The disruption buffer is only available for clients which connect via the specified (client-side) UDP port range. All other clients are ignored.

* `<routing>224.0.23.12</routing>` (optional): the multicast setup used by the service container for KNX IP (Secure) routing, defaults to the IP multicast address 224.0.23.12. (If the `routing` attribute of the service container is set to `false`, this setting has no effect.)  
Optional attributes for secure routing:
    - `latencyTolerance="1000"`: time window for accepting secure multicasts (in milliseconds), depends on the max. end-to-end network latency
* `<unixSocket>/path/to/unix/socket</unixSocket>` accept client connections over Unix domain sockets, server socket binds to the specified file-system path
* `<knxSubnet>` settings of the KNX subnet the service container shall communicate with. The `knxSubnet` element text contains identifiers specific to the KNX subnet interface type, i.e., IP address[:port] for IP-based interfaces, or USB interface name/ID for KNX USB interfaces, constructor arguments for user-supplied network links, .... Attributes:
    - `type`: interface type to the KNX subnet, one of:
      - `udp`: the KNX subnet is connected via a UDP KNXnet/IP tunneling connection
      - `tcp`: the KNX subnet is connected via a TCP KNXnet/IP tunneling connection
      - `knxip`: the KNX subnet is connected via KNX IP or KNXnet/IP routing
      - `usb`: connect to subnet via a USB device, if the device name/ID is left empty, the first USB device found will be used
      - `ft12`: use a FT1.2 protocol connection with EMI2 format (specify the `format` attribute for cEMI exchange format)
      - `tpuart`: use a TP-UART adapter to connect to a KNX TP1 network
      - `virtual`: run KNX subnet and enable the connection of virtual and real devices
      - `emulate`: emulates the behaviour of a KNX subnet for process communication. KNX datapoints may be specified in an accompanying datapoint XML file.  
                   If no datapoint file is configured, the emulation behavior is as follows: once a datapoint value is written to the subnet, it is added to the list of known datapoints, available for subsequent process communication. 
      - `user`: own programmed connections may be added here
    - `medium` (optional): KNX transmission medium, one of "tp1" (default), "pl110", "knxip", "rf"
	   - `tp1`: Twisted pair (transmission with 9600 Baud as specified in the KNX standard)
      - `pl110`: use power-line to connect
      - `knxip`: access via Ethernet
      - `rf`: Wireless connection via 868 MHz
    - `format` (optional): useful for knx interfaces which support different exchange formats; recognized values are "" (default), "baos", or "cemi"
    - `knxAddress` (optional): override the knx source address used in a frame dispatched to the knx subnet, used for knx interfaces which expect a specific address (e.g., "0.0.0")
    - `netif` (tunneling & KNX IP only, optional): network interface for tunneling or KNX IP communication with the KNX subnet
    - `useNat` (UDP tunneling only, optional): use network address translation (NAT)
    - `domainAddress` (open media only): domain address for power-line or RF transmission medium
    - `class` (user-supplied KNX subnet type only): class name of a user-supplied KNXNetworkLink to use for subnet communication

* `<datapoints ref="resources/datapointMap.xml" />` (only applies to subnet emulation, i.e., `type=emulate`): External file to describe the KNX datapoints to be used in the emulated network.
    - `ref`: relative path to XML file

* `<groupAddressFilter>`: Contains a (possibly empty) list of KNX group addresses, which represents the server group address filter applied to messages for that service container. An empty filter list does not filter any messages. Only messages with their group address in the filter list will be forwarded. 

* `<additionalAddresses>`: Contains a (possibly empty) list of KNX individual addresses, which are assigned to KNXnet/IP tunneling connections. An individual address has to match the KNX subnet (area, line), otherwise it will not be used! If no additional addresses are provided, the service container individual address is used, and the maximum of open tunneling connections at a time is limited to 1.

* `<tunnelingUsers>` (optional, only required for KNX IP secure tunneling if no keyring is used): contains a mapping of KNX IP Secure user IDs to permitted tunneling addresses.
	* `<user id="id">`: a user ID in the integer range [1..127], with `<knxAddress>` elements listing the permitted individual addresses assigned to client-side tunneling connections of that user.
		* `<knxAddress type="individual">x.y.z</knxAddress>`: additional address entry

* `<timeServer>`: Cyclically transmit date (DPT 11.001), time (DPT 10.001), or date+time (DPT 19.001) information on 
  the KNX subnet and server-side. The date/time datapoints are configured using `<datapoint stateBased="true" ...>` 
  elements. Time-server values are sent secured if the datapoint destination is in the keyring.

### Configuration Examples for KNX subnets

* Turn a PL110 USB interface into a KNXnet/IP server, the USB interface name matches 'busch-jaeger'  

	`<knxSubnet type="usb" medium="pl110" domainAddress="6f">busch-jaeger</knxSubnet>`

* Use the KNXnet/IP server to communicate with a KNX IP network

	`<knxSubnet type="knxip" netif="eth4">224.0.23.12</knxSubnet>`

* Load a user-supplied KNXNetworkLink class to communicate with the KNX subnet (the element text is parsed into constructor arguments of type String, using separators ',' and '|')

	`<knxSubnet type="user-supplied" class="my.knx.SubnetLink">o1,i2|i4</knxSubnet>`

* Provide a KNXnet/IP server for a KNX RF USB connection, using the USB vendor:product ID

	`<knxSubnet type="usb" medium="rf" domainAddress="000000004b01">0409:005a</knxSubnet>`

### <a id="knx-ip-secure"></a>KNX IP Secure 
Running the server with KNX IP Secure requires a keyring (*.knxkeys) exported from ETS, or a keyfile. A keyfile contains 

* a _group key_ if the server should use KNX IP Secure multicast communication
* a _device key_ and _user keys_ if the server should use KNX IP Secure unicast communication (tunneling on link-layer and busmonitor-layer, device management)

Example keyfile:

```
// group key is a 16 byte hex value 
group.key=BEEF5A1ADBEEF5A1ADBEEF5A1ADBEEF5
// device key is a 16 byte hex value
device.key=0102030405060708090a0b0c0d0e0f10
// for secure unicast, specify at least user 1 & 2 (max. 127); user 1 is used for management access
// user pwd or key, key is a 16 byte hex value (empty value means default setup key)
user[1].key=
user[2].key=d6da71bd89f7e8426250fe5657da900c
user[3].pwd=Joshua
user[4].key=...
```

Keyfile holding the keyring password:

```
keyring.pwd=Joshua
```

### Launcher Code

The KNXnet/IP server startup code is in `Launcher.java`, a Java `Runnable` which also loads the server configuration (use the `server-config.xml` configuration template located in the folder `resources`). The launcher expects a URI or file name pointing to the XML server configuration.
To run the KNXnet/IP server and gateway directly in Java code, see the implementation and Javadoc of `Launcher.java`.


Logging
-------

Calimero KNXnet/IP server uses the [System.Logger](https://docs.oracle.com/en/java/javase/19/docs/api/java.base/java/lang/System.Logger.html). Bind any desired logging frameworks of your choice.
