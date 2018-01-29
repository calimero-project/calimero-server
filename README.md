Calimero KNXnet/IP Server [![Build Status](https://travis-ci.org/calimero-project/calimero-server.svg?branch=master)](https://travis-ci.org/calimero-project/calimero-server)
=========================

A KNXnet/IP server for Java SE Embedded 8 (or Java SE 8). The minimum required runtime environment is 
the profile [compact1](http://www.oracle.com/technetwork/java/embedded/resources/tech/compact-profiles-overview-2157132.html).

* Run your own KNXnet/IP server in software (no KNXnet/IP hardware required)
* Turn a KNX interface into a KNXnet/IP server, e.g., KNX USB or KNX RF USB interfaces, EMI1/2 serial couplers 
* Intercept or proxy a KNXnet/IP connection, e.g., for monitoring/debugging purposes
* Emulate/virtualize a KNX network

Download
--------

~~~ sh
# Either using git
git clone https://github.com/calimero-project/calimero-server.git

# Or using hub
hub clone calimero-project/calimero-server
~~~

### Dependencies

The Calimero KNXnet/IP server requires `calimero-core`, `calimero-device`, and `slf4j-api`.

_Optional_ dependencies, required for communication over serial ports:

* Any of the native libraries in the `serial-native` repository, or `calimero-rxtx` for using RXTX or any RXTX descendant/compatible library already present on your platform. 
* For KNX USB or RF USB communication links, `calimero-core` depends on `org.usb4java:usb4java-javax` (and its transitive closure).

Supported Features
------------------

### Client-side KNXnet/IP
* Discovery and self-description
* Tunneling
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

### Configuration
* XML server configuration for startup
* KNX Interface Object Server during runtime, offering interface objects, e.g., Device Object, KNXnet/IP Parameter Object, cEMI Server Object, Group-Object Table Object

How-to & Examples
-----------------

With one of the following commands, the server should print a message that it expects a configuration file and quit:

#### Gradle

    ./gradlew run

#### Maven

~~~ sh
mvn exec:java
~~~

#### Java

Make sure all required `jar` packages are available.

~~~ sh
# Either, assuming all jar dependencies are located in the current working directory
java -cp "./*" tuwien.auto.calimero.server.Launcher

# Or, a minimal working example with explicit references to jars (adjust as required)
java -cp "calimero-server-2.4-SNAPSHOT.jar:calimero-core-2.4-SNAPSHOT.jar:calimero-device-2.4-SNAPSHOT.jar:slf4j-api-1.7.22.jar:slf4j-simple-1.7.22.jar" tuwien.auto.calimero.server.Launcher
~~~

### Start Server with Configuration

*Before trying the examples below with a configuration, make sure the configuration is appropriate for your KNX setup!*

Using Gradle

    ./gradlew run -Dexec.args=resources/server-config.xml

Using maven

~~~ sh
mvn exec:java -Dexec.args=resources/server-config.xml
~~~

Using Java (make sure any referenced files in the folder `resources` are found, or copy them into the current working directory).

~~~ sh
# Assumes all `jar` dependencies are located in the current working directory
java -cp "./*" tuwien.auto.calimero.server.Launcher server-config.xml
~~~

On the terminal, the running server instance can be stopped by typing "stop".


### Server Configuration

Elements and attributes of `server-config.xml`:

* `<knxServer name="knx-server" friendlyName="My KNXnet/IP Server">` (required): the server ID (for logging etc.) and the KNXnet/IP friendly name (for discovery & self-description)

	- `name="knx-server"`: Attribute to specify the internal name of the server (mainly for logging, naming, debugging purposes)
	- `friendlyName="My KNXnet/IP Server"`: Attribute to specify a custom name (max. 30 characters). Will be displayed in e.g. ETS-tool.

* `<propertyDefinitions ref="resources/properties.xml" />` It is possible to provide additional KNX property definitions through this tag. Specify properties in a file, e.g. 'properties.xml', and use the `ref` attribute to specify the URI/path to this file. The predefined properties may be explored in a user friendly way when opening the Calimero GUI.

* `<discovery listenNetIf="all" outgoingNetIf="all" activate="true"/>` (optional attributes): the network interfaces to listen for KNXnet/IP discovery requests, as well as the network interfaces to answer requests, e.g., `"all"`, `"any"`, or `"lo,eth0,eth1"`. The attribute `activate` allows to disable KNXnet/IP discovery & self-description. If disabled, any received discovery or descriptions request will be ignored.

* `<serviceContainer>` (1..*): specify a server service container, i.e., the client-side endpoint for a KNX subnet. Attributes: 
	- `activate`: enable/disable the service container, to load/ignore that container during server startup
	
	- `routing`: if `true` serve KNXnet/IP routing connections (the server KNX address defaults to 15.15.0), if `false` KNXnet/IP routing is disabled
	- `networkMonitoring`: serve tunneling connection on KNX busmonitor layer (set `true`) or deny such connection requests (set `false`)
	
	- `udpPort` (optional): UDP port of the control endpoint to listen for incoming connection requests of that service container, defaults to KNXnet/IP standard port "3671". Use different ports if more than one service container is deployed.
	
	-  `listenNetIf` (optional): network adapter to listen for connection requests, e.g., `"any"` or `"eth1"`, defaults to host default network adapter. `any` - the first available network adapter is chosen depending on your OS network setup (localhost setting). 

    - `reuseCtrlEP`: reuse the KNXnet/IP control endpoint (UDP/IP) for subsequent tunneling connections, i.e. no routing possible. If reuse is enabled (set `true`), no list of additional KNX individual addresses is required (see below). Per the KNX standard, reuse is only possible if the individual address is not yet assigned to a connection, and if KNXnet/IP routing is not activated. This implies that by reusing the control endpoint, at most 1 connection can be established at a time to a service container.
	

* `<knxAddress type="individual">7.1.1</knxAddress>`: the individual address of the service container (has to match the KNX subnet!)
    - `type="individual"`: indicates a device address.
    - `x.x.x`: Address of the service container if routing is disabled. Will be visible in e.g. ETS-tool.
    
* `<disruptionBuffer expirationTimeout="30" udpPort="5555-5559" />`: When `disruptionBuffer` is activated, missed KNX subnet frames due to a disrupted client link will be replayed when the client connection is reestablished.
    - `expirationTimeout="30"`: Attribute allows to specify the time in seconds how long the server will keep frames before discarding them after a connection was disrupted.
    - `udpPort="5555-5559"`: The disruption buffer is only available for clients which connect via the specified (client-side) UDP port range. All other clients are ignored.
    
* `<routingMcast>` (optional): the multicast group used by the service container for KNXnet/IP routing, defaults to the IP multicast address 224.0.23.12. If the `routing` attribute is set to `false`, this setting has no effect 
* `<knxSubnet>` settings of the KNX subnet the service container shall communicate with. The `knxSubnet` element text contains identifiers specific to the KNX subnet interface type, i.e., IP address[:port] for IP-based interfaces, or USB interface name/ID for KNX USB interfaces, constructor arguments for user-supplied network links, .... Attributes:
    - `type`: interface type to KNX subnet, one of "ip", "knxip", "usb", "ft12", "tpuart", "virtual", "emulate", "user-supplied"
      - `ip`: the KNX subnet is connected via a KNXnet/IP tunneling connection
      - `knxip`: the KNX subnet is connected via a KNXnet/IP routing connection
      - `usb`: connect to subnet via a USB device, if the device name/ID is left empty, the first USB device found will be used
      - `ft12`: use a FT1.2 protocol connection
      - `tpuart`: use a TP-UART adapter to connect to a KNX TP1 network
      - `virtual`: Run KNX subnet and enable the connection of virtual and real devices
      - `emulate`: Emulates the behaviour of a KNX subnet. Datapoints may be specified in an accompanying `dataPointMap.xml`.
      - `user-supplied`: Own programmed connections may be added here.
    - `medium` (optional): KNX transmission medium, one of "tp1" (default), "pl110", "knxip", "rf"
	   - `tp1`: Twisted pair (transmission with 9600 Baud as specified in the KNX standard)
      - `pl110`: use power-line to connect
      - `knxip`: access via Ethernet
      - `rf`: Wireless connection via 868 MHz
    - `listenNetIf` (KNX IP only): network interface for KNX IP communication with the KNX subnet
	  - `domainAddress` (open media only): domain address for power-line or RF transmission medium
	  - `class` (user-supplied KNX subnet type only): class name of a user-supplied KNXNetworkLink to use for subnet communication

* `<datapoints ref="resources/datapointMap.xml" />`: External file to describe the KNX datapoints to be specified. Only required with subnet emulation (`type=emulate`).
    - `ref`: relative path to xml-file

* `<groupAddressFilter>`: Contains a (possibly empty) list of KNX group addresses, which represents the server group address filter applied to messages for that service container. An empty filter list does not filter any messages. Only messages with their group address in the filter list will be forwarded. If you specify a filter, you probably also want to add the broadcast address `0/0/0`. 

* `<additionalAddresses>`: Contains a (possibly empty) list of KNX individual addresses, which are assigned to KNXnet/IP tunneling connections. An individual address has to match the KNX subnet (area, line), otherwise it will not be used! If no additional addresses are provided, the service container individual address is used, and the maximum of open tunneling connections at a time is limited to 1.


### Configuration Examples for KNX subnets

* Turn a PL110 USB interface into a KNXnet/IP server, the USB interface name matches 'busch-jaeger'  

	`<knxSubnet type="usb" medium="pl110" domainAddress="6f">busch-jaeger</knxSubnet>`

* Use the KNXnet/IP server to communicate with a KNX IP network

	`<knxSubnet type="knxip" listenNetIf="eth4">224.0.23.12</knxSubnet>`

* Load a user-supplied KNXNetworkLink class to communicate with the KNX subnet (the element text is parsed into constructor arguments of type String, using separators ',' and '|')

	`<knxSubnet type="user-supplied" class="my.knx.SubnetLink">o1,i2|i4</knxSubnet>`

* Provide a KNXnet/IP server for a KNX RF USB connection, using the USB vendor:product ID

	`<knxSubnet type="usb" medium="rf" domainAddress="000000004b01">0409:005a</knxSubnet>`

### Launcher Code

The KNXnet/IP server startup code is in `Launcher.java`, a Java `Runnable` which also loads the server configuration (use the `server-config.xml` configuration template located in the folder `resources`). The launcher expects a URI or file name pointing to the XML server configuration.
To run the KNXnet/IP server and gateway directly in Java code, see the implementation and Javadoc of `Launcher.java`.


Logging
-------

Calimero KNXnet/IP server uses the [Simple Logging Facade for Java (slf4j)](http://www.slf4j.org/). Bind any desired logging frameworks of your choice. The default gradle/maven dependency is the [Simple Logger](http://www.slf4j.org/api/org/slf4j/impl/SimpleLogger.html). It logs everything to standard output. The simple logger can be configured via the file `simplelogger.properties`, JVM system properties, or `java` command line options, e.g., `-Dorg.slf4j.simpleLogger.defaultLogLevel=warn`.



