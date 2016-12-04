/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2016 B. Malinowsky

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Linking this library statically or dynamically with other modules is
    making a combined work based on this library. Thus, the terms and
    conditions of the GNU General Public License cover the whole
    combination.

    As a special exception, the copyright holders of this library give you
    permission to link this library with independent modules to produce an
    executable, regardless of the license terms of these independent
    modules, and to copy and distribute the resulting executable under terms
    of your choice, provided that you also meet, for each linked independent
    module, the terms and conditions of the license of that module. An
    independent module is a module which is not derived from or based on
    this library. If you modify this library, you may extend this exception
    to your version of the library, but you are not obligated to do so. If
    you do not wish to do so, delete this exception statement from your
    version.
*/

package tuwien.auto.calimero.server.knxnetip;

import static tuwien.auto.calimero.device.ios.InterfaceObject.DEVICE_OBJECT;
import static tuwien.auto.calimero.device.ios.InterfaceObject.KNXNETIP_PARAMETER_OBJECT;

import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.function.Function;
import java.util.function.Supplier;

import org.slf4j.Logger;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DeviceDescriptor;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXIllegalStateException;
import tuwien.auto.calimero.Settings;
import tuwien.auto.calimero.cemi.CEMIDevMgmt;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KNXPropertyException;
import tuwien.auto.calimero.device.ios.PropertyEvent;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.knxnetip.Discoverer;
import tuwien.auto.calimero.knxnetip.KNXConnectionClosedException;
import tuwien.auto.calimero.knxnetip.KNXnetIPRouting;
import tuwien.auto.calimero.knxnetip.util.DeviceDIB;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.log.LogService.LogLevel;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;

/**
 * Provides server-side functionality of KNXnet/IP protocols.
 * <p>
 * This server implementation supports KNXnet/IP discovery and description, it accepts KNXnet/IP
 * tunneling connections on link layer and for bus monitoring, as well as KNXnet/IP device
 * management connections, and supports KNXnet/IP routing.
 * <p>
 * Services are configured for use by {@link ServiceContainer}s, which provide the server endpoints
 * and connectivity to KNX subnets.
 * <p>
 * A running server instance needs specific device and configuration data to answer search and
 * description requests during discovery and description, to accept connection requests, and so on.
 * Therefore, every KNXnet/IP server maintains an
 * interface object server (IOS). The IOS is initialized with basic information by adding KNX
 * properties, allowing the server to run properly. A user can access the IOS by calling
 * {@link #getInterfaceObjectServer()} to query or modify KNXnet/IP server properties, or
 * replace the IOS with another one by calling
 * {@link #setInterfaceObjectServer(InterfaceObjectServer)}.<br>
 * See the server constructor for the minimum set of default settings the IOS is initialized with.
 * Different services will update certain KNX properties in the IOS during runtime.
 * <p>
 * Note, that if data required by the server is not available in the IOS (e.g., due to deletion of
 * KNX properties by a user) or is not valid, the server will at first try to fall back on defaults
 * to fill in the missing data ensuring a minimum service, but finally might provide degraded
 * service only. It will, however, not always re-add or alter such properties in the IOS.
 * <p>
 * A server instance can be started ({@link #launch()}) and shut down ({@link #shutdown()})
 * repeatedly, without loosing server-global configuration settings.
 *
 * @author B. Malinowsky
 */
public class KNXnetIPServer
{
	// Notes:

	// Core specification:
	// In a routing server, raw and bus monitor connections shall not be supported.

	// If busmonitor tunneling is implemented, the server shall only support one
	// active connection per KNX subnetwork, and may not support any other KNXnet/IP
	// services for the subnetwork.
	// I support many data connections per subnetwork, but then no subsequent monitoring.
	// But if the first connection is monitoring, then don't allow any more connections
	// on that subnetwork.

	// NYI cEMI server in full transparent mode (server without an own Individual
	// Address), shall send back negative confirmation (Confirm Flag set to 1 in
	// L_Data.con, if corresponding L-data.req message has its source address set to 0.

	// NYI the following KNX properties are not used by now...
	// private static final int PID_SERVICE_CONTROL = 8;
	// private static final int PID_DEVICE_CONTROL = 14;

	// TODO limit routing indications to <= 50 messages per seconds as required by the KNX spec

	/*
	  KNX property default values
	  The following values are used to initialize the device objects and as fallback if
	  querying a property from the IOS fails to ensure minimum functionality.
	*/

	// Values used for device DIB

	// PID.FRIENDLY_NAME
	private static final byte[] defFriendlyName = new byte[] { 'C', 'a', 'l', 'i', 'm', 'e', 'r',
		'o', ' ', 'K', 'N', 'X', 'n', 'e', 't', '/', 'I', 'P', ' ', 's', 'e', 'r', 'v', 'e', 'r' };
	// PID.PROGMODE
	private static final int defDeviceStatus = 0;
	// PID.PROJECT_INSTALLATION_ID
	private static final int defProjectInstallationId = 0;
	// PID.SERIAL_NUMBER
	private static final byte[] defSerialNumber = new byte[6];
	// PID.KNX_INDIVIDUAL_ADDRESS
	// we use default KNX address for KNXnet/IP routers
	private static final IndividualAddress defKnxAddress = new IndividualAddress(0xff00);
	// PID.ROUTING_MULTICAST_ADDRESS
	static final InetAddress defRoutingMulticast;
	static {
		InetAddress a = null;
		try {
			a = InetAddress.getByName(Discoverer.SEARCH_MULTICAST);
		}
		catch (final UnknownHostException e) {}
		defRoutingMulticast = a;
	}

	// PID.MAC_ADDRESS
	// we set the actual MAC address per service container when we have the socket information
	private static final byte[] defMacAddress = new byte[6];

	// Values used for service families DIB

	// PID.KNXNETIP_DEVICE_CAPABILITIES
	// Bits LSB to MSB: 0 Device Management, 1 Tunneling, 2 Routing, 3 Remote Logging,
	// 4 Remote Configuration and Diagnosis, 5 Object Server
	private static final int defDeviceCaps = 1 + 2 + 4;

	// Values used for manufacturer data DIB

	// PID.MANUFACTURER_ID
	static final int defMfrId = 0;
	// PID.MANUFACTURER_DATA
	// one element is 4 bytes, value length has to be multiple of that
	// defaults to 'bm2011  '
	static final byte[] defMfrData = new byte[] { 'b', 'm', '2', '0', '1', '1', ' ', ' ' };

	// from init KNX properties

	// PID.DESCRIPTION
	private static final byte[] defDesc = new byte[] { 'J', '2', 'M', 'E', ' ', 'K', 'N', 'X', 'n',
		'e', 't', '/', 'I', 'P', ' ', 's', 'e', 'r', 'v', 'e', 'r' };

	// unmodifiable name assigned by user, used in getName() and logger
	private final String serverName;
	// server friendly name, matches PID.FRIENDLY_NAME property
	private final String friendlyName;

	final Logger logger;

	private boolean running;

	// Discovery and description

	private boolean runDiscovery;
	private LooperThread discovery;
	private NetworkInterface[] outgoingIf;
	private NetworkInterface[] discoveryIfs;

	// KNX endpoint and connection stuff

	// true to enable multicast loopback, false to disable loopback
	// used in KNXnet/IP Routing
	private boolean multicastLoopback = true;

	// list of ServiceContainer objects
	private final List<ServiceContainer> svcContainers = new ArrayList<>();

	private final Map<ServiceContainer, InterfaceObject> svcContToIfObj = new HashMap<>();

	// list of LooperThread objects running a control endpoint
	final List<LooperThread> controlEndpoints = new ArrayList<>();
	// list of LooperThread objects running a routing endpoint
	final List<LooperThread> routingEndpoints = new ArrayList<>();
	// list of DataEndpointServiceHandler objects
	final List<DataEndpointServiceHandler> dataConnections = new ArrayList<>();

	private InterfaceObjectServer ios;
	private static final int knxObject = KNXNETIP_PARAMETER_OBJECT;

	private static final int objectInstance = 1;

	private final EventListeners<ServerListener> listeners;

	/**
	 * Creates a new KNXnet/IP server instance.
	 * <p>
	 * During construction, the server creates its own Interface Object Server (IOS) and adds KNX
	 * properties with default values. Subsequent property changes can be done by calling
	 * {@link #getInterfaceObjectServer()}. Be aware that KNX properties added might change between
	 * implementations, as might their default property values. Added KNX properties with their
	 * initialized value in this implementation:
	 * <ul>
	 * <li>Device Object:
	 * <ul>
	 * <li>PID.MAX_APDULENGTH: 15</li>
	 * <li>PID.DESCRIPTION: 'J', '2', 'M', 'E', ' ', 'K', 'N', 'X', 'n', 'e', 't', '/', 'I', 'P',
	 * ' ', 's', 'e', 'r', 'v', 'e', 'r'</li>
	 * <li>PID.VERSION: Settings.getLibraryVersion()</li>
	 * <li>PID.FIRMWARE_REVISION: 1</li>
	 * <li>PID.SUBNET_ADDR: subnet address of PID.KNX_INDIVIDUAL_ADDRESS value</li>
	 * <li>PID.DEVICE_ADDR: device address of PID.KNX_INDIVIDUAL_ADDRESS value</li>
	 * </ul>
	 * </li>
	 * <li>KNXnet/IP Parameter Object:
	 * <ul>
	 * <li>PID.FRIENDLY_NAME: {@link #getFriendlyName()}</li>
	 * <li>PID.PROGMODE: 0</li>
	 * <li>PID.PROJECT_INSTALLATION_ID: 0</li>
	 * <li>PID.SERIAL_NUMBER: 0</li>
	 * <li>PID.KNX_INDIVIDUAL_ADDRESS: 0.0.0</li>
	 * <li>PID.ROUTING_MULTICAST_ADDRESS : {@link KNXnetIPRouting#DEFAULT_MULTICAST}</li>
	 * <li>PID.MAC_ADDRESS: default local host network interface MAC address or 0</li>
	 * <li>PID.CURRENT_IP_ADDRESS: default local host IP</li>
	 * <li>PID.SYSTEM_SETUP_MULTICAST_ADDRESS: {@link Discoverer#SEARCH_MULTICAST}</li>
	 * <li>PID.KNXNETIP_DEVICE_CAPABILITIES: 7 (Device Management, Tunneling, Routing)</li>
	 * <li>PID.MANUFACTURER_ID: 0</li>
	 * <li>PID.MANUFACTURER_DATA: 'b', 'm', '2', '0', '1', '1', ' ', ' ' ' '</li>
	 * <li>PID.KNXNETIP_ROUTING_CAPABILITIES: 0</li>
	 * <li>PID.KNXNETIP_DEVICE_STATE: 0</li>
	 * <li>PID.IP_CAPABILITIES: 0</li>
	 * <li>PID.IP_ASSIGNMENT_METHOD: 1</li>
	 * <li>PID.CURRENT_IP_ASSIGNMENT_METHOD: 1</li>
	 * <li>PID.MSG_TRANSMIT_TO_IP: 0</li>
	 * <li>PID.MSG_TRANSMIT_TO_KNX: 0</li>
	 * </ul>
	 * </li>
	 * </ul>
	 */
	public KNXnetIPServer()
	{
		this("calimero-server", "");
	}

	/**
	 * Creates a new KNXnet/IP server instance and assigns a user-defined server name.
	 * <p>
	 * The <code>localName</code> argument is user-chosen to locally identify the server instance
	 * and also used for local naming purposes, e.g., the logger name.<br>
	 * The <code>friendlyName</code> argument is stored in the KNX property
	 * {@link tuwien.auto.calimero.mgmt.PropertyAccess.PID#FRIENDLY_NAME} in the Interface Object
	 * Server during initialization. It identifies the server instance to clients of this server,
	 * and is used, e.g., in responses during server discovery.<br>
	 * See also {@link #KNXnetIPServer()} for a list of KNX properties initialized by this server.
	 *
	 * @param localName name of this server as shown to the owner/user of this server
	 * @param friendlyName a friendly, descriptive name for this server, consisting of ISO-8859-1
	 *        characters only, with string length &lt; 30 characters, <code>friendlyName</code> might
	 *        be null or of length 0 to use defaults
	 */
	public KNXnetIPServer(final String localName, final String friendlyName)
	{
		serverName = localName;
		final byte[] nameData = friendlyName == null || friendlyName.length() == 0
				? defFriendlyName : friendlyName.getBytes();
		try {
			this.friendlyName = new String(nameData, "ISO-8859-1");
		}
		catch (final UnsupportedEncodingException e) {
			// ISO 8859-1 support is mandatory on every Java platform
			throw new Error("missing ISO 8859-1 charset, " + e.getMessage());
		}
		logger = LogService.getLogger("calimero.server." + getName());
		listeners = new EventListeners<>(logger);

		try {
			initBasicServerProperties();
		}
		catch (final KNXException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Creates a new KNXnet/IP server instance, assigns a user-defined server name, adds the
	 * supplied service containers, and sets the discovery service.
	 * <p>
	 * The assigned server name is stored in the KNX property
	 * {@link tuwien.auto.calimero.mgmt.PropertyAccess.PID#FRIENDLY_NAME} in the Interface Object
	 * Server during initialization.<br>
	 * See {@link #KNXnetIPServer()} for a list of initialized KNX properties.
	 *
	 * @param serverName both the local and friendly name of this server instance, see
	 *        {@link #KNXnetIPServer(String, String)}
	 * @param serviceContainers list holding {@link ServiceContainer} entries to be hosted by this
	 *        server
	 * @see #KNXnetIPServer(String, String)
	 */
	public KNXnetIPServer(final String serverName, final List<ServiceContainer> serviceContainers)
	{
		this(serverName, serverName);
		for (final Iterator<ServiceContainer> i = serviceContainers.iterator(); i.hasNext();) {
			final ServiceContainer sc = i.next();
			addServiceContainer(sc);
		}
	}

	/**
	 * Adds the service container to the list of service containers hosted by this server.
	 * <p>
	 * A service container <code>sc</code> is only added if the server does not already contain a
	 * service container with <code>sc.getName()</code>.<br>
	 * If the server is in launched mode, an added service container is published to clients by
	 * starting a control endpoint for it.
	 *
	 * @param sc the service container to add
	 * @return <code>true</code> if the service container was added successfully, <code>false</code>
	 *         otherwise
	 */
	public final boolean addServiceContainer(final ServiceContainer sc)
	{
		synchronized (svcContainers) {
			if (findContainer(sc.getName()) != null) {
				logger.warn("service container \"" + sc.getName() + "\" already exists in server");
				return false;
			}
			// add new KNXnet/IP parameter object for this service container
			final InterfaceObjectServer io = getInterfaceObjectServer();
			io.addInterfaceObject(knxObject);
			final InterfaceObject[] objects = io.getInterfaceObjects();
			svcContToIfObj.put(sc, objects[objects.length - 1]);
			// init the parameter object
			svcContainers.add(sc);
			try {
				initKNXnetIpParameterObject(svcContainers.size(), sc);
			}
			catch (final KNXPropertyException e) {
				e.printStackTrace();
			}
			synchronized (this) {
				if (running)
					startControlEndpoint(sc);
			}
		}
		fireServiceContainerAdded(sc);
		return true;
	}

	/**
	 * Removes the service container from the list of service containers hosted by this server.
	 * <p>
	 * If no such container is found, the method simply returns.<br>
	 * If the server is in launched mode, the control endpoint associated with that service
	 * container is removed and no further available to clients.
	 *
	 * @param sc the service container to remove
	 */
	public final void removeServiceContainer(final ServiceContainer sc)
	{
		if (sc == null)
			return;
		synchronized (svcContainers) {
			// stop service, if we are already launched
			synchronized (this) {
				if (running) {
					stopControlEndpoint(sc);
				}
			}
			final boolean removed = svcContainers.remove(sc);
			if (removed)
				getInterfaceObjectServer().removeInterfaceObject(svcContToIfObj.get(sc));
		}
		fireServiceContainerRemoved(sc);
	}

	/**
	 * Returns all service containers currently hosted by this server.
	 * <p>
	 *
	 * @return a new ServiceContainer array holding the service containers with the array size equal
	 *         to the number of service containers (i.e., can be an empty array)
	 */
	public ServiceContainer[] getServiceContainers()
	{
		synchronized (svcContainers) {
			return svcContainers.toArray(new ServiceContainer[svcContainers.size()]);
		}
	}

	/**
	 * Sets a new Interface Object Server for this server, replacing any previously set Interface
	 * Object Server instance.
	 * <p>
	 *
	 * @param server the Interface Object Server
	 */
	public final void setInterfaceObjectServer(final InterfaceObjectServer server)
	{
		if (server == null)
			throw new IllegalArgumentException("there must exist an IOS");
		synchronized (listeners) {
			listeners.fire(l -> {
				ios.removeServerListener(l);
				server.addServerListener(l);
			});
			ios = server;
		}
	}

	/**
	 * Returns the Interface Object Server currently set (and used) by this server.
	 * <p>
	 *
	 * @return the server IOS instance
	 */
	public final InterfaceObjectServer getInterfaceObjectServer()
	{
		// synchronize on listeners since add/remove listener and setIOS also do
		synchronized (listeners) {
			return ios;
		}
	}

	/**
	 * Adds the specified event listener <code>l</code> to receive events from this KNXnet/IP
	 * server.
	 * <p>
	 * If <code>l</code> was already added as listener, no action is performed.
	 *
	 * @param l the listener to add
	 */
	public void addServerListener(final ServerListener l)
	{
		listeners.add(l);
		ios.addServerListener(l);
	}

	/**
	 * Removes the specified event listener <code>l</code>, so it does no longer receive events from
	 * this KNXnet/IP server.
	 * <p>
	 * If <code>l</code> was not added in the first place, no action is performed.
	 *
	 * @param l the listener to remove
	 */
	public void removeServerListener(final ServerListener l)
	{
		listeners.remove(l);
		ios.removeServerListener(l);
	}

	/**
	 * Option for KNXnet/IP server runtime behavior: enable (<code>true</code>) or disable (
	 * <code>false</code>) KNXnet/IP routing packet loopback on multicast sockets.
	 * <p>
	 * This setting depends both on application-specific requirements, e.g., whether sent packets
	 * should be received on the local host, and operating system socket behavior. <br>
	 * Use this option key with {@link #setOption(String, String)}.
	 */
	public static final String OPTION_ROUTING_LOOPBACK = "routing.loopback";

	/**
	 * Option for KNXnet/IP server runtime behavior: enable (<code>true</code>) or disable (
	 * <code>false</code>) the KNXnet/IP discovery and self-description service.
	 * <p>
	 * According to the KNX specification, discovery and self-description is mandatory. Therefore,
	 * this option is enabled by default.<br>
	 * Use this option key with {@link #setOption(String, String)}.
	 */
	public static final String OPTION_DISCOVERY_DESCRIPTION = "discoveryDescription";

	/**
	 * Option for KNXnet/IP server discovery endpoint: specify the network interfaces to listen on.
	 * <p>
	 * The value format is (with &lt;if&gt; being an interface name as shown by the system):
	 * <code>["all"|&lt;if&gt;{,&lt;if&gt;}]</code>. Supplying "all" will try to use all network
	 * interfaces found on the host. This setting is queried on start of the discovery server.<br>
	 * Use this option key with {@link #setOption(String, String)}.
	 */
	public static final String OPTION_DISCOVERY_INTERFACES = "discovery.interfaces";

	/**
	 * Option for KNXnet/IP server discovery endpoint: specify the network interfaces to listen on.
	 * <p>
	 * The value format is (with &lt;if&gt; being an interface name as shown by the system):
	 * <code>["all"|&lt;if&gt;{,&lt;if&gt;}]</code>. Supplying "all" will try to use all network
	 * interfaces found on the host. This setting is queried on start of the discovery server.<br>
	 * Use this option key with {@link #setOption(String, String)}.
	 */
	public static final String OPTION_OUTGOING_INTERFACE = "discovery.outoingInterface";

	synchronized String getOption(final String optionKey)
	{
		if (OPTION_DISCOVERY_DESCRIPTION.equals(optionKey)) {
			return Boolean.toString(runDiscovery);
		}
		if (OPTION_ROUTING_LOOPBACK.equals(optionKey)) {
			return Boolean.toString(multicastLoopback);
		}
		if (OPTION_DISCOVERY_INTERFACES.equals(optionKey)) {
			return join(discoveryIfs, NetworkInterface::getName, ",");
		}
		if (OPTION_OUTGOING_INTERFACE.equals(optionKey)) {
			return join(outgoingIf, NetworkInterface::getName, ",");
		}
		logger.warn("option \"" + optionKey + "\" not supported or unknown");
		throw new KNXIllegalArgumentException("unknown KNXnet/IP server option " + optionKey);
	}

	/**
	 * Sets or modifies KNXnet/IP server behavior.
	 * <p>
	 *
	 * @param optionKey the server option key to identify the option to set or modify
	 * @param value the corresponding option value, possibly replacing any previously set value
	 */
	public synchronized void setOption(final String optionKey, final String value)
	{
		if (OPTION_DISCOVERY_DESCRIPTION.equals(optionKey)) {
			runDiscovery = Boolean.valueOf(value).booleanValue();
			stopDiscoveryService();
			if (runDiscovery && running)
				startDiscoveryService(outgoingIf, discoveryIfs, 9);
		}
		else if (OPTION_ROUTING_LOOPBACK.equals(optionKey)) {
			multicastLoopback = Boolean.valueOf(value).booleanValue();
		}
		else if (OPTION_DISCOVERY_INTERFACES.equals(optionKey)) {
			discoveryIfs = parseNetworkInterfaces(optionKey, value);
		}
		else if (OPTION_OUTGOING_INTERFACE.equals(optionKey)) {
			outgoingIf = parseNetworkInterfaces(optionKey, value);
		}
		else
			logger.warn("option \"" + optionKey + "\" not supported or unknown");
	}

	private NetworkInterface[] parseNetworkInterfaces(final String optionKey, final String value)
	{
		if (value == null)
			return null;
		else if (value.equals("all"))
			return new NetworkInterface[0];
		final List<NetworkInterface> l = new ArrayList<>();
		int i = 0;
		for (int k = value.indexOf(','); i < value.length(); k = value.indexOf(',', i)) {
			k = k == -1 ? value.length() : k;
			final String ifname = value.substring(i, k).trim();
			i = k + 1;
			final NetworkInterface ni = getNetworkInterfaceByName(optionKey, ifname);
			if (ni != null)
				l.add(ni);
		}
		return l.toArray(new NetworkInterface[l.size()]);
	}

	private NetworkInterface getNetworkInterfaceByName(final String option, final String ifname)
	{
		if (ifname == null || ifname.equals("any") || ifname.equals("default"))
			return null;
		try {
			final NetworkInterface nif = NetworkInterface.getByName(ifname);
			if (nif != null)
				return nif;
			logger.error("option " + option + ": no network interface with name '" + ifname + "'");
		}
		catch (final SocketException e) {
			logger.error("option " + option + " for interface " + ifname, e);
		}
		return null;
	}

	private static <T> String join(final T[] array, final Function<T, ?>  f, final String sep)
	{
		if (array == null)
			return "default";
		final StringBuffer sb = new StringBuffer();
		Arrays.stream(array).forEach(ni -> sb.append(f.apply(ni)).append(sep));
		return sb.toString();
	}

	/**
	 * Launches this server to run its services.
	 * <p>
	 * Depending on server configuration and method parameters, the discovery service, routing
	 * service, and the control endpoint services as determined by the added service containers are
	 * started.<br>
	 * If this server is already running, this method returns immediately.
	 *
	 * @throws KNXIllegalStateException on no service containers available in this server
	 */
	public synchronized void launch()
	{
		if (running)
			return;
		if (svcContainers.isEmpty())
			throw new KNXIllegalStateException(serverName + " has no service containers added");
		logger.info("launch KNXnet/IP server \'{}\'", getFriendlyName());
		startDiscoveryService(outgoingIf, discoveryIfs, 9);

		for (final Iterator<ServiceContainer> i = svcContainers.iterator(); i.hasNext();) {
			final ServiceContainer sc = i.next();
			startControlEndpoint(sc);
		}
		running = true;
	}

	/**
	 * Shuts down a running server.
	 * <p>
	 * If the server is not in running state, this method returns immediately.<br>
	 * Before initiating shutdown, all registered server listeners are notified. All open server
	 * connections are closed following connection protocol, and services are terminated.<br>
	 * Server configuration settings and Interface Object Server properties are not reset.
	 */
	public synchronized void shutdown()
	{
		if (!running)
			return;
		fireShutdown();

		stopDiscoveryService();

		for (final Iterator<LooperThread> i = controlEndpoints.iterator(); i.hasNext();) {
			final LooperThread t = i.next();
			t.quit();
		}
		controlEndpoints.clear();
		for (final Iterator<LooperThread> i = routingEndpoints.iterator(); i.hasNext();) {
			final LooperThread t = i.next();
			t.quit();
		}
		routingEndpoints.clear();
		running = false;
	}

	/**
	 * Returns the server name initialized during server construction and used for logging.
	 * <p>
	 *
	 * @return initially used server name as string
	 */
	public String getName()
	{
		return serverName;
	}

	/**
	 * Returns the friendly name of this server.
	 * <p>
	 * This is the friendly server name value as returned by KNX property PID.FRIENDLY_NAME in the
	 * Interface Object Server. If that property does not exist or has an empty name set, a server
	 * default name is returned.
	 *
	 * @return server name as string
	 */
	public String getFriendlyName()
	{
		return friendlyName;
	}

	private void onPropertyValueChanged(final PropertyEvent pe)
	{
		if (pe.getPropertyId() == PID.QUEUE_OVERFLOW_TO_KNX) {
			final ServiceContainer sc = findContainer(pe.getInterfaceObject());
			// multicast routing lost message
			final LooperThread t = findRoutingLooperThread(sc);
			if (t == null)
				return;
			try {
				final byte[] data = pe.getNewData();
				final int lost = toInt(data);
				if (lost == 0)
					return;
				int state = 0;
				try {
					final int oi = objectInstance(findContainer(pe.getInterfaceObject()));
					final byte[] stateData = ios.getProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, oi,
							PID.KNXNETIP_DEVICE_STATE, 1, 1);
					state = stateData[0] & 0xff;
				}
				catch (final KNXPropertyException e) {
					logger.warn("on querying device state for sending routing lost message", e);
				}

				final RoutingService svc = (RoutingService) t.getLooper();
				svc.sendRoutingLostMessage(lost, state);
			}
			catch (final KNXConnectionClosedException e) {
				logger.error("sending routing lost message notification", e);
			}
		}
	}

	private void initBasicServerProperties() throws KNXFormatException, KNXPropertyException
	{
		if (ios == null)
			ios = new InterfaceObjectServer(false);
		ios.addServerListener(this::onPropertyValueChanged);

		// initialize interface device object properties

		// max APDU length is in range [15 .. 254]
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.MAX_APDULENGTH, 1, 1, new byte[] { 0, (byte) 254 });
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.DESCRIPTION, 1, defDesc.length, defDesc);

		final String[] sver = split(Settings.getLibraryVersion(), ". -");
		int last = 0;
		try {
			last = sver.length > 2 ? Integer.parseInt(sver[2]) : 0;
		}
		catch (final NumberFormatException e) {}
		final int ver = Integer.parseInt(sver[0]) << 12 | Integer.parseInt(sver[1]) << 6 | last;
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.VERSION, 1, 1, new byte[] {
			(byte) (ver >>> 8), (byte) (ver & 0xff) });

		// revision counting is not aligned with library version for now
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.FIRMWARE_REVISION, 1, 1, new byte[] { 1 });

		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.DEVICE_DESCRIPTOR, 1, 1,
				DeviceDescriptor.DD0.TYPE_091A.toByteArray());

		// requested by ETS during its interface discovery
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.DOMAIN_ADDRESS, 1, 1, new byte[] { 0x0, 0x0 });

		//
		// set properties used in device DIB for search response during discovery
		//
		// device status is not in programming mode
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.PROGMODE, 1, 1, new byte[] { defDeviceStatus });
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.SERIAL_NUMBER, 1, 1, defSerialNumber);
		// server KNX device address, since we don't know about routing at this time
		// address is always 0.0.0; might be updated later or by routing configuration
		final byte[] device = new IndividualAddress(0).toByteArray();
		// equal to PID.KNX_INDIVIDUAL_ADDRESS
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.SUBNET_ADDRESS, 1, 1, new byte[] { device[0] });
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.DEVICE_ADDRESS, 1, 1, new byte[] { device[1] });

		//
		// set properties used in manufacturer data DIB for discovery self description
		//
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.MANUFACTURER_ID, 1, 1, bytesFromWord(defMfrId));
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.MANUFACTURER_DATA, 1, defMfrData.length / 4, defMfrData);

		// set default medium to TP1 (Bit 1 set)
		ios.setProperty(InterfaceObject.CEMI_SERVER_OBJECT, objectInstance, PID.MEDIUM_TYPE, 1, 1, new byte[] { 0, 2 });
	}

	// precondition: we have an IOS instance
	private void initKNXnetIpParameterObject(final int objectInstance,
		final ServiceContainer endpoint) throws KNXPropertyException
	{
		if (ios == null)
			throw new KNXIllegalStateException("KNXnet/IP server has no IOS");

		// reset transmit counter to 0
		// those two are 4 byte unsigned
		ios.setProperty(knxObject, objectInstance, PID.MSG_TRANSMIT_TO_IP, 1, 1, new byte[4]);
		ios.setProperty(knxObject, objectInstance, PID.MSG_TRANSMIT_TO_KNX, 1, 1, new byte[4]);

		//
		// set properties used in device DIB for search response during discovery
		//
		// friendly name property entry is an array of 30 characters
		final byte[] data = new byte[30];
		System.arraycopy(friendlyName.getBytes(), 0, data, 0, friendlyName.length());
		ios.setProperty(knxObject, objectInstance, PID.FRIENDLY_NAME, 1, data.length, data);
		ios.setProperty(knxObject, objectInstance, PID.PROJECT_INSTALLATION_ID, 1, 1,
				bytesFromWord(defProjectInstallationId));
		// server KNX device address, since we don't know about routing at this time
		// address is always 0.0.0, but is updated in setRoutingConfiguration
		final byte[] device = new IndividualAddress(0).toByteArray();
		ios.setProperty(knxObject, objectInstance, PID.KNX_INDIVIDUAL_ADDRESS, 1, 1, device);

		ios.setProperty(knxObject, objectInstance, PID.MAC_ADDRESS, 1, 1, defMacAddress);

		// routing stuff
		if (endpoint instanceof RoutingEndpoint)
			setRoutingConfiguration((RoutingEndpoint) endpoint, objectInstance);
		else
			resetRoutingConfiguration(objectInstance);
		// 100 ms is the default busy wait time
		ios.setProperty(knxObject, objectInstance, PID.ROUTING_BUSY_WAIT_TIME, 1, 1, bytesFromWord(100));

		// ip and setup multicast
		final byte[] ip = endpoint.getControlEndpoint().getAddress().getAddress();
		ios.setProperty(knxObject, objectInstance, PID.CURRENT_IP_ADDRESS, 1, 1, ip);
		ios.setProperty(knxObject, objectInstance, PID.SYSTEM_SETUP_MULTICAST_ADDRESS, 1, 1,
				defRoutingMulticast.getAddress());

		//
		// set properties used in service families DIB for description
		//
		ios.setProperty(knxObject, objectInstance, PID.KNXNETIP_DEVICE_CAPABILITIES, 1, 1,
				bytesFromWord(defDeviceCaps));

		//
		// set properties used in manufacturer data DIB for discovery self description
		//
		final byte[] zero = new byte[1];
		// we don't indicate any capabilities here, since executing the respective tasks
		// is either done in the gateway (and, therefore, the property is set by the
		// gateway) or by the user, who has to care about it on its own
		ios.setProperty(knxObject, objectInstance, PID.KNXNETIP_ROUTING_CAPABILITIES, 1, 1, zero);
		ios.setProperty(knxObject, objectInstance, PID.KNXNETIP_DEVICE_STATE, 1, 1, zero);

		ios.setProperty(knxObject, objectInstance, PID.IP_CAPABILITIES, 1, 1, zero);
		ios.setProperty(knxObject, objectInstance, PID.IP_ASSIGNMENT_METHOD, 1, 1, new byte[] { 1 });
		ios.setProperty(knxObject, objectInstance, PID.CURRENT_IP_ASSIGNMENT_METHOD, 1, 1, new byte[] { 1 });
	}

	private void setRoutingConfiguration(final RoutingEndpoint endpoint, final int objectInstance)
		throws KNXPropertyException
	{
		final InetAddress multicastAddr = endpoint.getRoutingMulticastAddress();
		// final NetworkInterface netIf = endpoint.getRoutingInterface();

		InetAddress mcast = null;
		try {
			if (multicastAddr != null)
				mcast = multicastAddr;
			else {
				byte[] data = null;
				try {
					data = ios.getProperty(knxObject, objectInstance, PID.ROUTING_MULTICAST_ADDRESS, 1, 1);
				}
				catch (final KNXPropertyException e) {
					logger.warn("no routing multicast address property value", e);
				}
				if (data == null || Arrays.equals(new byte[4], data))
					mcast = defRoutingMulticast;
				else
					mcast = InetAddress.getByAddress(data);

				if (!KNXnetIPRouting.isValidRoutingMulticast(mcast)) {
					final String s = mcast + " is not a valid routing multicast address";
					logger.error(s);
					throw new KNXPropertyException(s, CEMIDevMgmt.ErrorCodes.UNSPECIFIED_ERROR);
				}
			}
		}
		catch (final UnknownHostException e) {
			// possible data corruption in IOS
			final String s = "routing multicast property value is no IP address!";
			logger.error(s, e);
			throw new KNXPropertyException(s, CEMIDevMgmt.ErrorCodes.UNSPECIFIED_ERROR);
		}
		ios.setProperty(knxObject, objectInstance, PID.ROUTING_MULTICAST_ADDRESS, 1, 1, mcast.getAddress());

		matchRoutingServerDeviceAddress(objectInstance, true);
	}

	private void resetRoutingConfiguration(final int objectInstance)
	{
		// routing multicast shall be set 0 if no routing service offered
		try {
			ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance,
					PID.ROUTING_MULTICAST_ADDRESS, 1, 1, new byte[4]);
		}
		catch (final KNXPropertyException e) {
			logger.warn("could not reset routing multicast address");
		}
		matchRoutingServerDeviceAddress(objectInstance, false);
	}

	private void matchRoutingServerDeviceAddress(final int objectInstance,
		final boolean routingSupported)
	{
		// try to match server device address to routing capabilities
		// we do this only if default server device address is 0 or 0xff00
		try {
			final KNXAddress device = new IndividualAddress(ios.getProperty(knxObject,
					objectInstance, PID.KNX_INDIVIDUAL_ADDRESS, 1, 1));
			if (routingSupported && device.getRawAddress() == 0)
				ios.setProperty(knxObject, objectInstance, PID.KNX_INDIVIDUAL_ADDRESS, 1, 1,
						defKnxAddress.toByteArray());
			else if (!routingSupported && device.equals(defKnxAddress))
				ios.setProperty(knxObject, objectInstance, PID.KNX_INDIVIDUAL_ADDRESS, 1, 1,
						new IndividualAddress(0).toByteArray());
			else if (!routingSupported && device.getRawAddress() == 0)
				ios.setProperty(knxObject, objectInstance, PID.KNX_INDIVIDUAL_ADDRESS, 1, 1, svcContainers
						.get(svcContainers.size() - 1).getMediumSettings().getDeviceAddress().toByteArray());
		}
		catch (final KNXPropertyException e) {
			logger.warn("matching server device address to routing capabilities, " + e.getMessage());
		}
	}

	int objectInstance(final ServiceContainer sc)
	{
		final ServiceContainer[] sca = getServiceContainers();
		for (int i = 0; i < sca.length; i++) {
			if (sca[i] == sc) {
				return i + 1;
			}
		}
		throw new KNXIllegalStateException("service container \"" + sc.getName() + "\" not found");
	}

	// returns a property element value as integer, or the supplied default on error
	int getProperty(final int objectType, final int objectInstance, final int propertyId, final int elements,
		final int def)
	{
		try {
			return toInt(ios.getProperty(objectType, objectInstance, propertyId, 1, elements));
		}
		catch (final KNXPropertyException e) {
			return def;
		}
	}

	DeviceDIB createDeviceDIB(final ServiceContainer sc)
	{
		byte[] name;
		try {
			// friendly name property entry is an array of 30 characters
			name = ios.getProperty(knxObject, objectInstance(sc), PID.FRIENDLY_NAME, 1, 30);
		}
		catch (final KNXPropertyException e) {
			name = new byte[30];
			System.arraycopy(defFriendlyName, 0, name, 0, defFriendlyName.length);
		}
		final StringBuffer sb = new StringBuffer(30);
		for (int i = 0; i < name.length && name[i] > 0; ++i)
			sb.append((char) (name[i] & 0xff));
		final String friendly = sb.toString();

		final int deviceStatus = getProperty(DEVICE_OBJECT, objectInstance, PID.PROGMODE, 1, defDeviceStatus);
		final int projectInstallationId = getProperty(knxObject, objectInstance(sc), PID.PROJECT_INSTALLATION_ID, 1,
				defProjectInstallationId);

		byte[] serialNumber = defSerialNumber;
		try {
			serialNumber = ios.getProperty(DEVICE_OBJECT, objectInstance, PID.SERIAL_NUMBER, 1, 1);
		}
		catch (final KNXPropertyException e) {}

		IndividualAddress knxAddress = defKnxAddress;
		try {
			knxAddress = new IndividualAddress(ios.getProperty(knxObject, objectInstance(sc),
					PID.KNX_INDIVIDUAL_ADDRESS, 1, 1));
		}
		catch (final KNXPropertyException e) {}

		InetAddress mcast = defRoutingMulticast;
		try {
			mcast = InetAddress.getByAddress(ios.getProperty(knxObject, objectInstance(sc),
					PID.ROUTING_MULTICAST_ADDRESS, 1, 1));
		}
		catch (final UnknownHostException e) {}
		catch (final KNXPropertyException e) {}

		byte[] macAddress = defMacAddress;
		try {
			macAddress = ios.getProperty(knxObject, objectInstance(sc), PID.MAC_ADDRESS, 1, 1);
		}
		catch (final KNXPropertyException e) {}

		return new DeviceDIB(friendly, deviceStatus, projectInstallationId, sc.getMediumSettings().getMedium(),
				knxAddress, serialNumber, mcast, macAddress);
	}

	ServiceFamiliesDIB createServiceFamiliesDIB(final ServiceContainer sc)
	{
		// we get a 2 byte value
		final int caps = getProperty(knxObject, objectInstance(sc), PID.KNXNETIP_DEVICE_CAPABILITIES, 1, defDeviceCaps);

		// service family 'core' is skipped here since not used in capabilities bitset
		final int[] services = new int[] { ServiceFamiliesDIB.DEVICE_MANAGEMENT,
			ServiceFamiliesDIB.TUNNELING, ServiceFamiliesDIB.ROUTING,
			ServiceFamiliesDIB.REMOTE_LOGGING, ServiceFamiliesDIB.REMOTE_CONFIGURATION_DIAGNOSIS,
			ServiceFamiliesDIB.OBJECT_SERVER };

		final int[] tmp = new int[services.length + 1];
		// now unconditionally add service family 'core'
		tmp[0] = ServiceFamiliesDIB.CORE;
		int count = 1;
		for (int i = 0; i < 6; ++i)
			if ((caps >> i & 0x1) == 1)
				tmp[count++] = services[i];

		final int[] supported = new int[count];
		final int[] versions = new int[count];
		for (int i = 0; i < count; i++) {
			supported[i] = tmp[i];
			versions[i] = 1;
		}
		return new ServiceFamiliesDIB(supported, versions);
	}

	private void startDiscoveryService(final NetworkInterface[] outgoing,
		final NetworkInterface[] listen, final int retryAttempts)
	{
		synchronized (this) {
			if (!runDiscovery)
				return;
		}
		final Supplier<ServiceLooper> builder = () -> new DiscoveryService(this, outgoing, listen);
		final LooperThread t = new LooperThread(this, null, serverName + " discovery endpoint", retryAttempts, builder);
		discovery = t;
		discovery.start();
	}

	private void stopDiscoveryService()
	{
		final LooperThread d = discovery;
		discovery = null;
		if (d != null)
			d.quit();
	}

	private void startControlEndpoint(final ServiceContainer sc)
	{
		final Supplier<ServiceLooper> builder = () -> new ControlEndpointService(this, sc);
		final LooperThread t = new LooperThread(this, sc, serverName + " control endpoint " + sc.getName(), 9, builder);
		controlEndpoints.add(t);
		t.start();
		if (sc instanceof RoutingEndpoint)
			startRoutingService(sc, (RoutingEndpoint) sc);
	}

	private void stopControlEndpoint(final ServiceContainer sc)
	{
		LooperThread remove = null;
		for (final Iterator<LooperThread> i = controlEndpoints.iterator(); i.hasNext();) {
			final LooperThread t = i.next();
			final ControlEndpointService ces = (ControlEndpointService) t.getLooper();
			if (ces.getServiceContainer() == sc) {
				t.quit();
				remove = t;
				break;
			}
		}
		controlEndpoints.remove(remove);
		if (sc instanceof RoutingEndpoint)
			stopRoutingService(sc);
	}

	private void startRoutingService(final ServiceContainer sc, final RoutingEndpoint endpoint)
	{
		final InetAddress mcast = endpoint.getRoutingMulticastAddress();
		final Supplier<ServiceLooper> builder = () -> new RoutingService(this, sc, endpoint.getRoutingInterface(),
				mcast, multicastLoopback);
		final LooperThread t = new LooperThread(this, sc, serverName + " routing service " + mcast.getHostAddress(), 9,
				builder);
		routingEndpoints.add(t);
		t.start();
	}

	private void stopRoutingService(final ServiceContainer sc)
	{
		final LooperThread t = findRoutingLooperThread(sc);
		if (t == null)
			return;
		t.quit();
		routingEndpoints.remove(t);
	}

	private LooperThread findRoutingLooperThread(final ServiceContainer sc)
	{
		for (final Iterator<LooperThread> i = routingEndpoints.iterator(); i.hasNext();) {
			final LooperThread t = i.next();
			final RoutingService svc = (RoutingService) t.getLooper();
			if (svc.getServiceContainer() == sc)
				return t;
		}
		return null;
	}

	private ServiceContainer findContainer(final String svcContName)
	{
		for (final Iterator<ServiceContainer> i = svcContainers.iterator(); i.hasNext();) {
			final ServiceContainer sc = i.next();
			if (sc.getName().compareTo(svcContName) == 0)
				return sc;
		}
		return null;
	}

	private ServiceContainer findContainer(final InterfaceObject io)
	{
		for (final Iterator<ServiceContainer> i = svcContToIfObj.keySet().iterator(); i.hasNext();) {
			final Object svcCont = i.next();
			if (svcContToIfObj.get(svcCont) == io)
				return (ServiceContainer) svcCont;
		}
		return null;
	}

	void closeDataConnections(final ServiceContainer sc)
	{
		final HPAI ep = sc.getControlEndpoint();
		if (ep.getPort() == 0) {
			logger.warn("service container with ephemeral port, "
					+ "ignore closing data connections of " + sc.getName());
			return;
		}
		logger.info("closing all data connections of " + sc.getName());
		final SocketAddress addr = new InetSocketAddress(ep.getAddress(), ep.getPort());

		// Note the indirect access to this list:
		// h.close() invokes the control endpoint callback, which removes the data
		// connection from the list, hence we create our local copy to avoid
		// concurrent modifications
		final DataEndpointServiceHandler[] handlerList = dataConnections
				.toArray(new DataEndpointServiceHandler[dataConnections.size()]);
		for (int i = 0; i < handlerList.length; i++) {
			final DataEndpointServiceHandler h = handlerList[i];
			if (h.getCtrlSocketAddress().equals(addr))
				h.close(CloseEvent.SERVER_REQUEST, "quit service container", LogLevel.INFO, null);
		}
	}

	final EventListeners<ServerListener> listeners()
	{
		return listeners;
	}

	private void fireServiceContainerAdded(final ServiceContainer sc)
	{
		final ServiceContainerEvent sce = new ServiceContainerEvent(this,
				ServiceContainerEvent.ADDED_TO_SERVER, sc);
		fireOnServiceContainerChange(sce);
	}

	private void fireServiceContainerRemoved(final ServiceContainer sc)
	{
		final ServiceContainerEvent sce = new ServiceContainerEvent(this,
				ServiceContainerEvent.REMOVED_FROM_SERVER, sc);
		fireOnServiceContainerChange(sce);
	}

	void fireOnServiceContainerChange(final ServiceContainerEvent sce)
	{
		listeners.fire(l -> l.onServiceContainerChange(sce));
	}

	private void fireShutdown()
	{
		final ShutdownEvent se = new ShutdownEvent(this, CloseEvent.USER_REQUEST, "user shutdown");
		listeners.fire(l -> l.onShutdown(se));
	}

	private static String[] split(final String text, final String delim)
	{
		final StringTokenizer st = new StringTokenizer(text, delim);
		final String[] tokens = new String[st.countTokens()];
		for (int i = 0; i < tokens.length; ++i)
			tokens[i] = st.nextToken();
		return tokens;
	}

	static int toInt(final byte[] data)
	{
		if (data.length == 1)
			return data[0] & 0xff;
		if (data.length == 2)
			return (data[0] & 0xff) << 8 | data[1] & 0xff;
		return (data[0] & 0xff) << 24 | (data[1] & 0xff) << 16 | (data[2] & 0xff) << 8 | data[3]
				& 0xff;
	}

	private static byte[] bytesFromWord(final int word)
	{
		return new byte[] { (byte) (word >> 8), (byte) word };
	}
}
