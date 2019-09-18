/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2019 B. Malinowsky

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

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

import org.slf4j.Logger;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DeviceDescriptor;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KnxRuntimeException;
import tuwien.auto.calimero.KnxSecureException;
import tuwien.auto.calimero.Settings;
import tuwien.auto.calimero.cemi.CEMIDevMgmt;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KnxPropertyException;
import tuwien.auto.calimero.device.ios.PropertyEvent;
import tuwien.auto.calimero.dptxlator.DPTXlator2ByteUnsigned;
import tuwien.auto.calimero.dptxlator.DPTXlator8BitUnsigned;
import tuwien.auto.calimero.dptxlator.PropertyTypes;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.knxnetip.Discoverer;
import tuwien.auto.calimero.knxnetip.KNXConnectionClosedException;
import tuwien.auto.calimero.knxnetip.KNXnetIPRouting;
import tuwien.auto.calimero.knxnetip.util.DeviceDIB;
import tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.link.medium.PLSettings;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.mgmt.Description;
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
 * {@link #setInterfaceObjectServer(InterfaceObjectServer)}.
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
		'o', ' ', 'K', 'N', 'X', ' ', 'I', 'P', ' ', 's', 'e', 'r', 'v', 'e', 'r' };
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
	private static final byte[] defDesc = defFriendlyName;

	// unmodifiable name assigned by user, used in getName() and logger
	private final String serverName;
	// server friendly name, matches PID.FRIENDLY_NAME property
	private final String friendlyName;

	final Logger logger;

	private boolean running;
	private boolean inShutdown;

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

	private InterfaceObjectServer ios;
	private static final int knxObject = KNXNETIP_PARAMETER_OBJECT;

	private static final int objectInstance = 1;

	private final EventListeners<ServerListener> listeners;

	public final Set<ServiceContainer> udpOnly = new HashSet<>();

	/**
	 * Creates a new KNXnet/IP server instance and assigns a user-defined server name.
	 * <p>
	 * The <code>localName</code> argument is user-chosen to locally identify the server instance and also used for
	 * local naming purposes, e.g., the logger name.<br>
	 * The <code>friendlyName</code> argument is stored in the KNX property
	 * {@link tuwien.auto.calimero.mgmt.PropertyAccess.PID#FRIENDLY_NAME} in the Interface Object Server during
	 * initialization. It identifies the server instance to clients of this server, and is used, e.g., in responses
	 * during server discovery.<br>
	 * During construction, the server creates its own Interface Object Server (IOS) and adds KNX properties with
	 * default values. Subsequent property changes can be done by calling {@link #getInterfaceObjectServer()}. Be aware
	 * that KNX properties added might change between implementations, as might their default property values.
	 *
	 * @param localName name of this server as shown to the owner/user of this server
	 * @param friendlyName a friendly, descriptive name used for discovery and description, consisting of
	 *        ISO-8859-1 characters only, with string length &lt; 30 characters, <code>friendlyName</code> might be of
	 *        length 0
	 */
	public KNXnetIPServer(final String localName, final String friendlyName)
	{
		serverName = localName;
		if (!Charset.forName("ISO-8859-1").newEncoder().canEncode(friendlyName))
			throw new IllegalArgumentException("Cannot encode '" + friendlyName + "' using ISO-8859-1 charset");
		this.friendlyName = friendlyName;
		logger = LogService.getLogger("calimero.server." + getName());
		listeners = new EventListeners<>(logger);

		logger.info("{} (v{}) \'{}\'", new String(defFriendlyName, StandardCharsets.ISO_8859_1),
				Settings.getLibraryVersion(), friendlyName);
		initBasicServerProperties();
	}

	/**
	 * Creates a new KNXnet/IP server instance, assigns a user-defined server name, adds the
	 * supplied service containers, and sets the discovery service.
	 * <p>
	 * The assigned server name is stored in the KNX property
	 * {@link tuwien.auto.calimero.mgmt.PropertyAccess.PID#FRIENDLY_NAME} in the Interface Object
	 * Server during initialization.<br>
	 * See {@link #KNXnetIPServer(String, String)} for a list of initialized KNX properties.
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
	 * A service container <code>sc</code> is only added if the server does not already contain a service container with
	 * <code>sc.getName()</code>.<br>
	 * If the server is in launched mode, an added service container is published to clients by starting a control
	 * endpoint for it.
	 *
	 * @param sc the service container to add
	 * @return <code>true</code> if the service container was added successfully, <code>false</code> otherwise
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
			svcContainers.add(sc);

			if (svcContainers.size() == 1) {
				final byte[] device = sc.getMediumSettings().getDeviceAddress().toByteArray();
				setProperty(DEVICE_OBJECT, objectInstance, PID.SUBNET_ADDRESS, device[0]);
				setProperty(DEVICE_OBJECT, objectInstance, PID.DEVICE_ADDRESS, device[1]);
			}
			final int medium = sc.getMediumSettings().getMedium();
			setProperty(InterfaceObject.CEMI_SERVER_OBJECT, 1, PID.MEDIUM_TYPE, (byte) 0, (byte) medium);
			if (medium == KNXMediumSettings.MEDIUM_PL110)
				setProperty(DEVICE_OBJECT, objectInstance, PID.DOMAIN_ADDRESS, ((PLSettings) sc.getMediumSettings()).getDomainAddress());

			initKNXnetIpParameterObject(svcContainers.size(), sc);

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
				startDiscoveryService(outgoingIf, discoveryIfs, -1);
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

	public void configureSecurity(final ServiceContainer sc, final Map<String, byte[]> keys, final int securedServices) {
		int secure = 0;

		final int objectInstance = objectInstance(sc);
		final int objIndex = svcContToIfObj.get(sc).getIndex();

		// if we setup secure unicast services, we need at least device authentication
		if (keys.containsKey("device.key")) {
			secure = (1 << ServiceFamiliesDIB.DEVICE_MANAGEMENT) | (1 << ServiceFamiliesDIB.TUNNELING);

			ios.setDescription(new Description(objIndex, KNXNETIP_PARAMETER_OBJECT, SecureSession.pidDeviceAuth, 0,
					PropertyTypes.PDT_GENERIC_16, false, 1, 1, 0, 0), true);
			setProperty(knxObject, objectInstance, SecureSession.pidDeviceAuth, keys.get("device.key"));

			final ByteArrayOutputStream baos = new ByteArrayOutputStream();
			for (int user = 1; keys.containsKey("user." + user); user++) {
				final byte[] userPwdHash = keys.get("user." + user);
				baos.write(userPwdHash.length == 0 ? SecureSession.emptyPwdHash : userPwdHash, 0, 16);
			}
			ios.setDescription(new Description(objIndex, KNXNETIP_PARAMETER_OBJECT, SecureSession.pidUserPwdHashes, 0,
					PropertyTypes.PDT_GENERIC_16, false, 2, 127, 0, 0), true);
			final byte[] userPwdHashes = baos.toByteArray();
			final int users = userPwdHashes.length / 16;
			if (users == 0)
				throw new KnxSecureException("user 1 is mandatory, but not configured");
			ios.setProperty(knxObject, objectInstance, SecureSession.pidUserPwdHashes, 1, users, userPwdHashes);
		}

		final byte[] groupKey = keys.get("group.key");
		if (sc instanceof RoutingServiceContainer && groupKey != null) {
			secure |= (1 << ServiceFamiliesDIB.ROUTING);

			try {
				final int pidGroupKey = 91;
				ios.setDescription(new Description(objIndex, knxObject, pidGroupKey, 0, PropertyTypes.PDT_GENERIC_16,
						false, 1, 1, 0, 0), true);
				setProperty(knxObject, objectInstance, pidGroupKey, groupKey);

				// DPT 7.002
				final DPTXlator2ByteUnsigned t = new DPTXlator2ByteUnsigned(DPTXlator2ByteUnsigned.DPT_TIMEPERIOD);
				t.setTimePeriod(((RoutingServiceContainer) sc).latencyTolerance().toMillis());
				ios.setDescription(new Description(objIndex, knxObject, SecureSession.pidLatencyTolerance, 0,
						PropertyTypes.PDT_UNSIGNED_INT, false, 1, 1, 3, 0), true);
				setProperty(knxObject, objectInstance, SecureSession.pidLatencyTolerance, t.getData());

				final DPTXlator8BitUnsigned scaling = new DPTXlator8BitUnsigned(DPTXlator8BitUnsigned.DPT_SCALING);
				scaling.setValue(10);
				ios.setDescription(new Description(objIndex, knxObject, SecureSession.pidSyncLatencyTolerance, 0,
						PropertyTypes.PDT_SCALING, false, 1, 1, 3, 0), true);
				setProperty(knxObject, objectInstance, SecureSession.pidSyncLatencyTolerance, scaling.getData());
			}
			catch (final KNXFormatException e) {
				throw new KnxRuntimeException("configure secure routing", e);
			}
		}

		if (secure != 0) {
			final byte[] caps = getProperty(knxObject, objectInstance, PID.KNXNETIP_DEVICE_CAPABILITIES,
					bytesFromWord(defDeviceCaps));
			caps[1] |= 64;
			setProperty(knxObject, objectInstance, PID.KNXNETIP_DEVICE_CAPABILITIES, caps);
		}

		secure &= securedServices;

		ios.setDescription(new Description(objIndex, knxObject, SecureSession.pidSecuredServices, 0,
				PropertyTypes.PDT_FUNCTION, true, 1, 1, 3, 2), true);
		setProperty(knxObject, objectInstance, SecureSession.pidSecuredServices, (byte) 0, (byte) secure);
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
		final StringBuilder sb = new StringBuilder();
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
	 */
	public synchronized void launch()
	{
		if (running)
			return;

		startDiscoveryService(outgoingIf, discoveryIfs, -1);
		svcContainers.forEach(this::startControlEndpoint);
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
		if (!running || inShutdown)
			return;
		inShutdown = true;
		fireShutdown();

		stopDiscoveryService();

		controlEndpoints.forEach(LooperThread::quit);
		controlEndpoints.clear();

		routingEndpoints.forEach(LooperThread::quit);
		routingEndpoints.clear();

		inShutdown = false;
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

	public Map<Integer, DataEndpoint> dataConnections(final ServiceContainer serviceContainer) {
		for (final LooperThread looperThread : controlEndpoints) {
			final Optional<ServiceLooper> looper = looperThread.looper();
			if (looper.isPresent()) {
				final ControlEndpointService ces = (ControlEndpointService) looper.get();
				if (ces.getServiceContainer() == serviceContainer)
					return Collections.unmodifiableMap(ces.connections());
			}
		}
		return Map.of();
	}

	private int lastOverflowToKnx = 0;

	private void onPropertyValueChanged(final PropertyEvent pe)
	{
		if (pe.getPropertyId() == PID.QUEUE_OVERFLOW_TO_KNX) {
			final byte[] data = pe.getNewData();
			final int overflow = toInt(data);
			if (overflow == 0)
				return;
			final int lost = (overflow - lastOverflowToKnx) & 0xffff;
			lastOverflowToKnx = overflow;
			if (lost == 0)
				return;
			final ServiceContainer sc = findContainer(pe.getInterfaceObject());
			// multicast routing lost message
			findRoutingLooperThread(sc).flatMap(t -> t.looper()).ifPresent(l -> sendRoutingLostMessage(l, sc, lost));
		}
		else if (pe.getInterfaceObject().getType() == InterfaceObject.ROUTER_OBJECT) {
			if (pe.getPropertyId() == PID.MEDIUM_STATUS) {
				final var svcCont = findContainer(pe.getInterfaceObject());
				final var active = (pe.getNewData()[0] & 0x01) == 0x00; // 0x01: communication impossible
				findControlEndpoint(svcCont).ifPresent(ep -> ep.mediumConnectionStatusChanged(active));
			}
		}
	}

	private void sendRoutingLostMessage(final ServiceLooper svc, final ServiceContainer sc, final int lost) {
		final int oi = objectInstance(sc);
		final int state = getProperty(KNXNETIP_PARAMETER_OBJECT, oi, PID.KNXNETIP_DEVICE_STATE, 1, 0);
		try {
			((RoutingService) svc).sendRoutingLostMessage(lost, state);
		}
		catch (final KNXConnectionClosedException e) {
			logger.error("sending routing lost message notification", e);
		}
	}

	private void initBasicServerProperties() throws KnxPropertyException
	{
		if (ios == null)
			ios = new InterfaceObjectServer(false);
		ios.addServerListener(this::onPropertyValueChanged);

		// initialize interface device object properties

		// max APDU length is in range [15 .. 254]
		setProperty(DEVICE_OBJECT, objectInstance, PID.MAX_APDULENGTH, new byte[] { 0, (byte) 15 });
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.DESCRIPTION, 1, defDesc.length, defDesc);

		final String[] sver = Settings.getLibraryVersion().split("\\.| |-", 0);
		final int ver = Integer.parseInt(sver[0]) << 6 | Integer.parseInt(sver[1]);
		setProperty(DEVICE_OBJECT, objectInstance, PID.VERSION, new byte[] { (byte) (ver >>> 8), (byte) (ver & 0xff) });

		// revision counting is not aligned with library version for now
		setProperty(DEVICE_OBJECT, objectInstance, PID.FIRMWARE_REVISION, new byte[] { 1 });

		setProperty(DEVICE_OBJECT, objectInstance, PID.DEVICE_DESCRIPTOR, DeviceDescriptor.DD0.TYPE_091A.toByteArray());

		//
		// set properties used in device DIB for search response during discovery
		//
		// device status is not in programming mode
		setProperty(DEVICE_OBJECT, objectInstance, PID.PROGMODE, new byte[] { defDeviceStatus });
		setProperty(DEVICE_OBJECT, objectInstance, PID.SERIAL_NUMBER, defSerialNumber);
		// server KNX device address, since we don't know about routing at this time
		// address is always 15.15.0; might be updated later or by routing configuration
		final byte[] device = defKnxAddress.toByteArray();
		// equal to PID.KNX_INDIVIDUAL_ADDRESS
		setProperty(DEVICE_OBJECT, objectInstance, PID.SUBNET_ADDRESS, device[0]);
		setProperty(DEVICE_OBJECT, objectInstance, PID.DEVICE_ADDRESS, device[1]);

		//
		// set properties used in manufacturer data DIB for discovery self description
		//
		setProperty(DEVICE_OBJECT, objectInstance, PID.MANUFACTURER_ID, bytesFromWord(defMfrId));
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.MANUFACTURER_DATA, 1, defMfrData.length / 4, defMfrData);
	}

	// precondition: we have an IOS instance
	private void initKNXnetIpParameterObject(final int objectInstance, final ServiceContainer endpoint)
		throws KnxPropertyException
	{
		if (ios == null)
			throw new IllegalStateException("KNXnet/IP server has no IOS");

		// reset transmit counter to 0
		// those two are 4 byte unsigned
		setProperty(knxObject, objectInstance, PID.MSG_TRANSMIT_TO_IP, new byte[4]);
		setProperty(knxObject, objectInstance, PID.MSG_TRANSMIT_TO_KNX, new byte[4]);

		//
		// set properties used in device DIB for search response during discovery
		//
		// friendly name property entry is an array of 30 characters
		final byte[] data = Arrays.copyOf(friendlyName.getBytes(Charset.forName("ISO-8859-1")), 30);
		ios.setProperty(knxObject, objectInstance, PID.FRIENDLY_NAME, 1, data.length, data);
		setProperty(knxObject, objectInstance, PID.PROJECT_INSTALLATION_ID, bytesFromWord(defProjectInstallationId));
		final byte[] addr = endpoint.getMediumSettings().getDeviceAddress().toByteArray();
		setProperty(knxObject, objectInstance, PID.KNX_INDIVIDUAL_ADDRESS, addr);
		setProperty(knxObject, objectInstance, PID.MAC_ADDRESS, new byte[6]);

		// routing stuff
		if (endpoint instanceof RoutingServiceContainer)
			setRoutingConfiguration((RoutingServiceContainer) endpoint, objectInstance);
		else
			resetRoutingConfiguration(objectInstance);
		// 100 ms is the default busy wait time
		setProperty(knxObject, objectInstance, PID.ROUTING_BUSY_WAIT_TIME, bytesFromWord(100));

		// ip and setup multicast
		final byte[] ip = endpoint.getControlEndpoint().getAddress().getAddress();
		setProperty(knxObject, objectInstance, PID.CURRENT_IP_ADDRESS, ip);
		setProperty(knxObject, objectInstance, PID.SYSTEM_SETUP_MULTICAST_ADDRESS, defRoutingMulticast.getAddress());

		//
		// set properties used in service families DIB for description
		//

		// if service container doesn't support routing, don't show it in device capabilities
		int deviceCaps = defDeviceCaps;
		if (!(endpoint instanceof RoutingServiceContainer))
			deviceCaps = defDeviceCaps - 4;
		setProperty(knxObject, objectInstance, PID.KNXNETIP_DEVICE_CAPABILITIES, bytesFromWord(deviceCaps));

		//
		// set properties used in manufacturer data DIB for discovery self description
		//
		final byte[] zero = new byte[1];
		// we don't indicate any capabilities here, since executing the respective tasks
		// is either done in the gateway (and, therefore, the property is set by the
		// gateway) or by the user, who has to care about it on its own
		setProperty(knxObject, objectInstance, PID.KNXNETIP_ROUTING_CAPABILITIES, zero);
		setProperty(knxObject, objectInstance, PID.KNXNETIP_DEVICE_STATE, zero);

		setProperty(knxObject, objectInstance, PID.IP_CAPABILITIES, zero);
		setProperty(knxObject, objectInstance, PID.IP_ASSIGNMENT_METHOD, new byte[] { 1 });
		setProperty(knxObject, objectInstance, PID.CURRENT_IP_ASSIGNMENT_METHOD, new byte[] { 1 });
	}

	private void setRoutingConfiguration(final RoutingServiceContainer endpoint, final int objectInstance)
		throws KnxPropertyException
	{
		final InetAddress multicastAddr = endpoint.routingMulticastAddress();

		InetAddress mcast = null;
		try {
			if (multicastAddr != null)
				mcast = multicastAddr;
			else {
				final byte[] data = getProperty(knxObject, objectInstance, PID.ROUTING_MULTICAST_ADDRESS, null);
				if (data == null || Arrays.equals(new byte[4], data))
					mcast = defRoutingMulticast;
				else
					mcast = InetAddress.getByAddress(data);

				if (!KNXnetIPRouting.isValidRoutingMulticast(mcast))
					throw new KnxPropertyException(mcast + " is not a valid routing multicast address",
							CEMIDevMgmt.ErrorCodes.UNSPECIFIED_ERROR);
			}
		}
		catch (final UnknownHostException e) {
			// possible data corruption in IOS
			throw new KnxPropertyException("routing multicast property value is no IP address",
					CEMIDevMgmt.ErrorCodes.UNSPECIFIED_ERROR);
		}
		setProperty(knxObject, objectInstance, PID.ROUTING_MULTICAST_ADDRESS, mcast.getAddress());
	}

	private void resetRoutingConfiguration(final int objectInstance)
	{
		setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance, PID.ROUTING_MULTICAST_ADDRESS, new byte[4]);
	}

	int objectInstance(final ServiceContainer sc)
	{
		final ServiceContainer[] sca = getServiceContainers();
		for (int i = 0; i < sca.length; i++) {
			if (sca[i] == sc) {
				return i + 1;
			}
		}
		throw new IllegalStateException("service container \"" + sc.getName() + "\" not found");
	}

	// returns a property element value as integer, or the supplied default on error
	int getProperty(final int objectType, final int objectInstance, final int propertyId, final int elements,
		final int def)
	{
		try {
			return toInt(ios.getProperty(objectType, objectInstance, propertyId, 1, elements));
		}
		catch (final KnxPropertyException e) {
			return def;
		}
	}

	// returns the current number of property elements, or 0 if property is not found
	int getPropertyElems(final int objectType, final int objectInstance, final int propertyId)
	{
		try {
			return toInt(ios.getProperty(objectType, objectInstance, propertyId, 0, 1));
		}
		catch (final KnxPropertyException e) {}
		return 0;
	}

	byte[] getProperty(final int objectType, final int objectInstance, final int propertyId, final byte[] defaultData)
	{
		try {
			return ios.getProperty(objectType, objectInstance, propertyId, 1, 1);
		}
		catch (final KnxPropertyException e) {
			return defaultData;
		}
	}

	void setProperty(final int objectType, final int objectInstance, final int propertyId, final byte... data)
	{
		ios.setProperty(objectType, objectInstance, propertyId, 1, 1, data);
	}

	DeviceDIB createDeviceDIB(final ServiceContainer sc)
	{
		byte[] name;
		try {
			// friendly name property entry is an array of 30 characters
			name = ios.getProperty(knxObject, objectInstance(sc), PID.FRIENDLY_NAME, 1, 30);
		}
		catch (final KnxPropertyException e) {
			name = new byte[30];
			System.arraycopy(defFriendlyName, 0, name, 0, defFriendlyName.length);
		}
		final StringBuilder sb = new StringBuilder(30);
		for (int i = 0; i < name.length && name[i] > 0; ++i)
			sb.append((char) (name[i] & 0xff));
		final String friendly = sb.toString();

		final int deviceStatus = getProperty(DEVICE_OBJECT, objectInstance, PID.PROGMODE, 1, defDeviceStatus);
		final int projectInstallationId = getProperty(knxObject, objectInstance(sc), PID.PROJECT_INSTALLATION_ID, 1,
				defProjectInstallationId);

		final byte[] serialNumber = getProperty(DEVICE_OBJECT, objectInstance, PID.SERIAL_NUMBER, defSerialNumber);
		final IndividualAddress knxAddress = new IndividualAddress(
				getProperty(knxObject, objectInstance(sc), PID.KNX_INDIVIDUAL_ADDRESS, defKnxAddress.toByteArray()));
		InetAddress mcast = defRoutingMulticast;
		try {
			mcast = InetAddress
					.getByAddress(ios.getProperty(knxObject, objectInstance(sc), PID.ROUTING_MULTICAST_ADDRESS, 1, 1));
		}
		catch (UnknownHostException | KnxPropertyException e) {}
		final byte[] macAddress = getProperty(knxObject, objectInstance(sc), PID.MAC_ADDRESS, new byte[6]);

		return new DeviceDIB(friendly, deviceStatus, projectInstallationId, sc.getMediumSettings().getMedium(),
				knxAddress, serialNumber, mcast, macAddress);
	}

	ServiceFamiliesDIB createServiceFamiliesDIB(final ServiceContainer sc, final boolean extended)
	{
		// we get a 2 byte value
		final int v = getProperty(knxObject, objectInstance(sc), PID.KNXNETIP_DEVICE_CAPABILITIES, 1, defDeviceCaps);
		// shift caps left one bit because svc family KNXnet/IP Core is always set and left out by default
		final int caps = (v << 1) | 1;
		final int[] services = { ServiceFamiliesDIB.CORE, ServiceFamiliesDIB.DEVICE_MANAGEMENT,
			ServiceFamiliesDIB.TUNNELING, ServiceFamiliesDIB.ROUTING, ServiceFamiliesDIB.REMOTE_LOGGING,
			ServiceFamiliesDIB.REMOTE_CONFIGURATION_DIAGNOSIS, ServiceFamiliesDIB.OBJECT_SERVER,
			ServiceFamiliesDIB.Security };
		final int coreVersion = udpOnly.contains(sc) ? 1 : 2;
		final int[] serviceVersion = { coreVersion, 2, 2, 2, 0, 0, 0, 1 };

		final int[] tmp = new int[services.length];
		final int[] tmpVersion = new int[tmp.length];
		int count = 0;
		for (int i = 0; i < services.length; ++i) {
			final int familyId = services[i];
			if (!extended && familyId > ServiceFamiliesDIB.OBJECT_SERVER)
				break;
			if ((caps >> i & 0x1) == 1) {
				tmp[count] = familyId;
				tmpVersion[count++] = serviceVersion[i];
			}
		}

		final int[] supported = new int[count];
		final int[] versions = new int[count];
		for (int i = 0; i < count; i++) {
			supported[i] = tmp[i];
			versions[i] = tmpVersion[i];
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
		final LooperThread t = new LooperThread(this, serverName + " discovery endpoint", retryAttempts, builder);
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
		if (!sc.isActivated())
			return;
		final Supplier<ServiceLooper> builder = () -> new ControlEndpointService(this, sc);
		final LooperThread t = new LooperThread(this, serverName + " control endpoint " + sc.getName(), -1, builder);
		controlEndpoints.add(t);
		t.start();
		if (sc instanceof RoutingServiceContainer)
			startRoutingService((RoutingServiceContainer) sc);
	}

	private void stopControlEndpoint(final ServiceContainer sc)
	{
		for (final Iterator<LooperThread> i = controlEndpoints.iterator(); i.hasNext();) {
			final LooperThread t = i.next();
			if (t.looper().filter(l -> ((ControlEndpointService) l).getServiceContainer() == sc).isPresent()) {
				t.quit();
				i.remove();
				break;
			}
		}
		findRoutingLooperThread(sc).ifPresent(this::stopRoutingService);
	}

	private void startRoutingService(final RoutingServiceContainer sc)
	{
		final InetAddress mcast = sc.routingMulticastAddress();
		final LooperThread t = new LooperThread(this, serverName + " routing service " + mcast.getHostAddress(), -1,
				() -> new RoutingService(this, sc, mcast, multicastLoopback));
		routingEndpoints.add(t);
		t.start();
	}

	private void stopRoutingService(final LooperThread t)
	{
		t.quit();
		routingEndpoints.remove(t);
	}

	private Optional<LooperThread> findRoutingLooperThread(final ServiceContainer sc)
	{
		final Predicate<ServiceLooper> belongsToSvcCont = svc -> ((RoutingService) svc).getServiceContainer() == sc;
		return routingEndpoints.stream().filter(ep -> ep.looper().filter(belongsToSvcCont).isPresent()).findFirst();
	}

	private Optional<ControlEndpointService> findControlEndpoint(final ServiceContainer sc) {
		return controlEndpoints.stream().map(LooperThread::looper).flatMap(Optional::stream)
				.map(ControlEndpointService.class::cast).filter(sc::equals).findFirst();
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
		final var objects = getInterfaceObjectServer().getInterfaceObjects();
		int svcContainerIdx = 0;
		for (int i = 0; i < io.getIndex(); i++) {
			if (objects[i].getType() == io.getType())
				svcContainerIdx++;
		}
		return svcContainers.get(svcContainerIdx);
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

	static int toInt(final byte[] data) {
		if (data.length == 1)
			return data[0] & 0xff;
		if (data.length == 2)
			return (data[0] & 0xff) << 8 | (data[1] & 0xff);
		return (data[0] & 0xff) << 24 | (data[1] & 0xff) << 16 | (data[2] & 0xff) << 8 | (data[3] & 0xff);
	}

	private static byte[] bytesFromWord(final int word)
	{
		return new byte[] { (byte) (word >> 8), (byte) word };
	}
}
