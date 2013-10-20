/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2011 B. Malinowsky

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
*/

package tuwien.auto.calimero.server.knxnetip;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Collections;
import java.util.Enumeration;
import java.util.EventListener;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.Settings;
import tuwien.auto.calimero.cemi.CEMIDevMgmt;
import tuwien.auto.calimero.exception.KNXException;
import tuwien.auto.calimero.exception.KNXFormatException;
import tuwien.auto.calimero.exception.KNXIllegalArgumentException;
import tuwien.auto.calimero.exception.KNXIllegalStateException;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.internal.UdpSocketLooper;
import tuwien.auto.calimero.knxnetip.Discoverer;
import tuwien.auto.calimero.knxnetip.KNXConnectionClosedException;
import tuwien.auto.calimero.knxnetip.KNXnetIPConnection;
import tuwien.auto.calimero.knxnetip.KNXnetIPDevMgmt;
import tuwien.auto.calimero.knxnetip.KNXnetIPRouting;
import tuwien.auto.calimero.knxnetip.KNXnetIPTunnel;
import tuwien.auto.calimero.knxnetip.servicetype.ConnectRequest;
import tuwien.auto.calimero.knxnetip.servicetype.ConnectResponse;
import tuwien.auto.calimero.knxnetip.servicetype.ConnectionstateRequest;
import tuwien.auto.calimero.knxnetip.servicetype.ConnectionstateResponse;
import tuwien.auto.calimero.knxnetip.servicetype.DescriptionRequest;
import tuwien.auto.calimero.knxnetip.servicetype.DescriptionResponse;
import tuwien.auto.calimero.knxnetip.servicetype.DisconnectRequest;
import tuwien.auto.calimero.knxnetip.servicetype.DisconnectResponse;
import tuwien.auto.calimero.knxnetip.servicetype.ErrorCodes;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.knxnetip.servicetype.PacketHelper;
import tuwien.auto.calimero.knxnetip.servicetype.RoutingLostMessage;
import tuwien.auto.calimero.knxnetip.servicetype.SearchRequest;
import tuwien.auto.calimero.knxnetip.servicetype.SearchResponse;
import tuwien.auto.calimero.knxnetip.util.CRD;
import tuwien.auto.calimero.knxnetip.util.DeviceDIB;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.knxnetip.util.ManufacturerDIB;
import tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB;
import tuwien.auto.calimero.knxnetip.util.TunnelCRD;
import tuwien.auto.calimero.knxnetip.util.TunnelCRI;
import tuwien.auto.calimero.log.LogLevel;
import tuwien.auto.calimero.log.LogManager;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.server.InterfaceObject;
import tuwien.auto.calimero.server.InterfaceObjectServer;
import tuwien.auto.calimero.server.InterfaceObjectServerListener;
import tuwien.auto.calimero.server.KNXPropertyException;
import tuwien.auto.calimero.server.PropertyEvent;
import tuwien.auto.calimero.server.knxnetip.DataEndpointServiceHandler.ServiceCallback;

/**
 * Provides server-side functionality of KNXnet/IP protocols.
 * <p>
 * This server implementation supports KNXnet/IP discovery and description, it accepts
 * KNXnet/IP tunneling connections on link layer and for bus monitoring, as well as
 * KNXnet/IP device management connections, and supports KNXnet/IP routing.
 * <p>
 * Services are configured for use by {@link ServiceContainer}s, which provide the server
 * endpoints and connectivity to KNX subnets.
 * <p>
 * A running server instance needs specific device and configuration data to answer search
 * and description requests during discovery and description, to accept connection
 * requests, and so on. Therefore, during construction of a KNXnet/IP server, every
 * instance creates its own default interface object server (IOS). The IOS is initialized
 * with basic information by adding KNX properties, allowing the server to run properly. A
 * user can subsequently get the IOS by calling {@link #getInterfaceObjectServer()} to
 * query or modify the initial set of server properties, or replace the IOS with another
 * one by calling {@link #setInterfaceObjectServer(InterfaceObjectServer)}.<br>
 * See the server constructor for a list with the default settings of an IOS during
 * initialization.<br>
 * Different services are allowed to alter certain KNX properties in the set IOS.
 * <p>
 * Note, that if data required by the server is not available in the IOS (e.g., due to
 * deletion of KNX properties by a user) or is not valid, the server will at first try to
 * fall back on defaults to fill in the missing data ensuring a minimum service, but
 * finally might provide degraded service only. It will, however, not add or alter such
 * properties in the IOS.
 * <p>
 * A server instance can be started ({@link #launch()} and shut down ( {@link #shutdown()}
 * ) repeatedly, without loosing server-global configuration settings.
 * <p>
 * The following properties are modified while the server is running:<br>
 * 
 * @author B. Malinowsky
 */
public class KNXnetIPServer
{
	// dev v0.4
	
	// Notes:

	// Core specification:
	// In a routing server, raw and bus monitor connections shall not be supported.
	// I will see for a workaround.

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
	//private static final int PID_SERVICE_CONTROL = 8;
	//private static final int PID_DEVICE_CONTROL = 14;

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
	private static final InetAddress defRoutingMulticast;
	static {
		InetAddress a = null;
		try {
			a = InetAddress.getByName(Discoverer.SEARCH_MULTICAST);
		}
		catch (final UnknownHostException e) {}
		defRoutingMulticast = a;
	}

	private static final InetAddress systemSetupMulticast = defRoutingMulticast;
	
	// PID.MAC_ADDRESS
	private static final byte[] defMacAddress;
	static {
		final byte[] mac = new byte[6];
		// getHardwareAddress is not supported on ME CDC
		//try {
		//	mac = NetworkInterface.getByInetAddress(InetAddress.getLocalHost())
		//		.getHardwareAddress();
		//}
		//catch (final SocketException e) {}
		//catch (final UnknownHostException e) {}
		defMacAddress = mac;
	}

	
	// Values used for service families DIB

	// PID.KNXNETIP_DEVICE_CAPABILITIES
	// Bits LSB to MSB: 0 Device Management, 1 Tunneling, 2 Routing, 3 Remote Logging,
	// 4 Remote Configuration and Diagnosis, 5 Object Server
	private static final int defDeviceCaps = 1 + 2 + 4;

	// Values used for manufacturer data DIB

	// PID.MANUFACTURER_ID
	private static final int defMfrId = 0;
	// PID.MANUFACTURER_DATA
	// one element is 4 bytes, value length has to be multiple of that
	// defaults to 'bm2011  '
	private static final byte[] defMfrData = new byte[] { 'b', 'm', '2',
		'0', '1', '1', ' ', ' ' };

	// from init KNX properties

	// PID.DESCRIPTION
	private static final byte[] defDesc = new byte[] { 'J', '2', 'M', 'E', ' ', 'K', 'N', 'X', 'n',
		'e', 't', '/', 'I', 'P', ' ', 's', 'e', 'r', 'v', 'e', 'r' };

	// unmodifiable name assigned by user, used in getName() and logger
	private final String name;
	// server friendly name, matches PID.FRIENDLY_NAME property
	private final String friendlyName;

	private final LogService logger;

	private boolean running;

	
	
	// Discovery and description
	
	private boolean runDiscovery;
	private LooperThread discovery;
	private NetworkInterface outgoingIf;
	private NetworkInterface[] discoveryIfs = null;
	
	
	// KNX endpoint and connection stuff
	
	// true to enable multicast loopback, false to disable loopback
	// used in KNXnet/IP Routing
	private boolean multicastLoopback = true;

	// list of ServiceContainer objects
	private final List svcContainers = new ArrayList();

	private final Map svcContToIfObj = new HashMap();

	// list of LooperThread objects running a control endpoint
	private final List controlEndpoints = new ArrayList();
	// list of LooperThread objects running a routing endpoint
	private final List routingEndpoints = new ArrayList();
	// list of DataEndpointServiceHandler objects
	private final List dataConnections = new ArrayList();
	
	private final List usedKnxAddresses = new ArrayList();
	// If the server assigns its own KNX individual address to a connection, no
	// management (using tunneling or from the KNX subnet) shall be allowed.
	// This flag maintains the current state, access is synchronized on
	// the variable usedKnxAddresses.
	private int activeMgmtConnections;

	// overall maximum allowed is 0xff
	private static final int MAX_CHANNEL_ID = 255;
	private final BitSet channelIds = new BitSet(MAX_CHANNEL_ID);
	private int lastChannelId;

	private InterfaceObjectServer ios;
	private static final int devObject = InterfaceObject.DEVICE_OBJECT;
	private static final int knxObject = InterfaceObject.KNXNETIP_PARAMETER_OBJECT;

	// The object instance determines which instance of an object type the server
	// will query for properties. Always defaults to 1.
	private final int objectInstance = 1;

	private final EventListeners listeners = new EventListeners();

	/**
	 * Creates a new KNXnet/IP server instance.
	 * <p>
	 * During construction, the server creates its own Interface Object Server (IOS) and adds KNX
	 * properties with default values. Subsequent property changes can be done by calling
	 * {@link #getInterfaceObjectServer()}. Be aware that KNX properties added might change between
	 * implementations, as might their default property values. Added KNX properties with their
	 * initialized value in this implementation:
	 * <ul>
	 * <li>Device Object:</li>
	 * <ul>
	 * <li>PID.MAX_APDULENGTH: 15</li>
	 * <li>PID.DESCRIPTION: 'J', '2', 'M', 'E', ' ', 'K', 'N', 'X', 'n', 'e', 't', '/', 'I', 'P',
	 * ' ', 's', 'e', 'r', 'v', 'e', 'r'</li>
	 * <li>PID.VERSION: Settings.getLibraryVersion()</li>
	 * <li>PID.FIRMWARE_REVISION: 1</li>
	 * <li>PID.SUBNET_ADDR: subnet address of PID.KNX_INDIVIDUAL_ADDRESS value</li>
	 * <li>PID.DEVICE_ADDR: device address of PID.KNX_INDIVIDUAL_ADDRESS value</li>
	 * </ul>
	 * <li>KNXnet/IP Parameter Object:</li>
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
	 * </ul>
	 */
	public KNXnetIPServer()
	{
		this("Calimero 2/NG", "");
	}

	/**
	 * Creates a new KNXnet/IP server instance and assigns a user-defined server name.
	 * <p>
	 * The <code>localName</code> argument is user-chosen to locally identify the server
	 * instance and also used for local naming purposes, e.g., the logger name.<br>
	 * The <code>friendlyName</code> argument is stored in the KNX property
	 * {@link tuwien.auto.calimero.mgmt.PropertyAccess.PID#FRIENDLY_NAME} in the Interface
	 * Object Server during initialization. It identifies the server instance to clients
	 * of this server, and is used, e.g., in responses during server discovery.<br>
	 * See also {@link #KNXnetIPServer()} for a list of KNX properties initialized by this
	 * server.
	 * 
	 * @param localName name of this server as shown to the owner/user of this server
	 * @param friendlyName a friendly, descriptive name for this server, consisting of
	 *        ISO-8859-1 characters only, with string length < 30 characters,
	 *        <code>friendlyName</code> might be null or of length 0 to use defaults
	 */
	public KNXnetIPServer(final String localName, final String friendlyName)
	{
		name = localName;
		final byte[] nameData = friendlyName == null || friendlyName.length() == 0
				? defFriendlyName : friendlyName.getBytes();
		try {
			this.friendlyName = new String(nameData, "ISO-8859-1");
		}
		catch (final UnsupportedEncodingException e) {
			// ISO 8859-1 support is mandatory on every Java platform
			throw new Error("missing ISO 8859-1 charset, " + e.getMessage());
		}
		logger = LogManager.getManager().getLogService(getName());

		try {
			initBasicServerProperties();
		}
		catch (final KNXException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Creates a new KNXnet/IP server instance, assigns a user-defined server name, adds
	 * the supplied service containers, and sets the discovery service.
	 * <p>
	 * The assigned server name is stored in the KNX property
	 * {@link tuwien.auto.calimero.mgmt.PropertyAccess.PID#FRIENDLY_NAME} in the Interface
	 * Object Server during initialization.<br>
	 * See {@link #KNXnetIPServer()} for a list of initialized KNX properties.
	 * 
	 * @param serverName both the local and friendly name of this server instance, see
	 *        {@link #KNXnetIPServer(String, String)}
	 * @param serviceContainers list holding {@link ServiceContainer} entries to be hosted
	 *        by this server
	 * @see #KNXnetIPServer(String, String)
	 */
	public KNXnetIPServer(final String serverName, final List serviceContainers)
	{
		this(serverName, serverName);
		for (final Iterator i = serviceContainers.iterator(); i.hasNext();) {
			final ServiceContainer sc = (ServiceContainer) i.next();
			addServiceContainer(sc);
		}
	}

	/**
	 * Adds the service container to the list of service containers hosted by this server.
	 * <p>
	 * A service container <code>sc</code> is only added if the server does not already
	 * contain a service container with <code>sc.getName()</code>.<br>
	 * If the server is in launched mode, an added service container is published to
	 * clients by starting a control endpoint for it.
	 * 
	 * @param sc the service container to add
	 * @return <code>true</code> if the service container was added successfully,
	 *         <code>false</code> otherwise
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
			final RoutingEndpoint ep = sc instanceof RoutingEndpoint ? (RoutingEndpoint) sc : null;
			try {
				initKNXnetIpParameterObject(svcContainers.size() + 1, ep);
			}
			catch (final KNXPropertyException e) {
				e.printStackTrace();
			}
			svcContainers.add(sc);
			synchronized (this) {
				if (running)
					startControlEndpoint(sc);
			}
		}
		fireServiceContainerAdded(sc);
		return true;
	}

	/**
	 * Removes the service container from the list of service containers hosted by this
	 * server.
	 * <p>
	 * If no such container is found, the method simply returns.<br>
	 * If the server is in launched mode, the control endpoint associated with that
	 * service container is removed and no further available to clients.
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
				getInterfaceObjectServer().removeInterfaceObject(
						(InterfaceObject) svcContToIfObj.get(sc));
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
			return (ServiceContainer[]) svcContainers.toArray(new ServiceContainer[svcContainers
					.size()]);
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
			final EventListener[] l = listeners.listeners();
			for (int i = 0; i < l.length; i++)
				ios.removeServerListener((ServerListener) l[i]);
			ios = server;
			if (ios != null)
				for (int i = 0; i < l.length; i++)
					ios.addServerListener((ServerListener) l[i]);
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
	 * Option for KNXnet/IP server discovery endpoint: specify the network interfaces to listen on.<br>
	 * The value format is (with &lt;if&gt; being an interface name as shown by the system):
	 * <code>["all"|&lt;if&gt;{,&lt;if&gt;}]</code>. Supplying "all" will try to use all network
	 * interfaces found on the host. This setting is queried on start of the discovery server.<br>
	 * Use this option key with {@link #setOption(String, String)}.
	 */
	public static final String OPTION_DISCOVERY_INTERFACES = "discovery.interfaces";

	/**
	 * Option for KNXnet/IP server discovery endpoint: specify the network interfaces to listen on.<br>
	 * The value format is (with &lt;if&gt; being an interface name as shown by the system):
	 * <code>["all"|&lt;if&gt;{,&lt;if&gt;}]</code>. Supplying "all" will try to use all network
	 * interfaces found on the host. This setting is queried on start of the discovery server.<br>
	 * Use this option key with {@link #setOption(String, String)}.
	 */
	public static final String OPTION_OUTGOING_INTERFACE = "discovery.outoingInterface";
	
	// ??? unused by now, make public if useful, also correctly synchronize setOption then
	synchronized String getOption(final String optionKey)
	{
		if (OPTION_DISCOVERY_DESCRIPTION.equals(optionKey)) {
			return Boolean.toString(runDiscovery);
		}
		if (OPTION_ROUTING_LOOPBACK.equals(optionKey)) {
			return Boolean.toString(multicastLoopback);
		}
		if (OPTION_DISCOVERY_INTERFACES.equals(optionKey)) {
			if (discoveryIfs == null)
				return "all";
			final StringBuffer sb = new StringBuffer();
			for (int i = 0; i < discoveryIfs.length; i++) {
				final NetworkInterface ni = discoveryIfs[i];
				sb.append(ni.getName()).append(",");
			}
			return sb.toString();
		}
		if (OPTION_OUTGOING_INTERFACE.equals(optionKey)) {
			if (outgoingIf == null)
				return "default";
			return outgoingIf.getName();
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
	public void setOption(final String optionKey, final String value)
	{
		if (OPTION_DISCOVERY_DESCRIPTION.equals(optionKey)) {
			synchronized (this) {
				runDiscovery = Boolean.valueOf(value).booleanValue();
				stopDiscoveryService();
				if (runDiscovery && running)
					startDiscoveryService(outgoingIf, discoveryIfs, 9);
			}
		}
		else if (OPTION_ROUTING_LOOPBACK.equals(optionKey)) {
			multicastLoopback = Boolean.valueOf(value).booleanValue();
		}
		else if (OPTION_DISCOVERY_INTERFACES.equals(optionKey)) {
			if (value.equals("all"))
				discoveryIfs = null;
			else {
				final List l = new ArrayList();
				int i = 0;
				for (int k = value.indexOf(','); i < value.length(); k = value.indexOf(',', i)) {
					k = k == -1 ? value.length() : k;
					final String name = value.substring(i, k).trim();
					i = k + 1;
					try {
						final NetworkInterface ni = NetworkInterface.getByName(name);
						if (ni != null)
							l.add(ni);
						else
							logger.error("option " + optionKey + ": no interface of name " + name,
									null);
					}
					catch (final SocketException e) {
						logger.error("option " + optionKey + " for interface " + name, e);
					}
				}
				discoveryIfs = (NetworkInterface[]) l.toArray(new NetworkInterface[l.size()]);
			}
		}
		else if (OPTION_OUTGOING_INTERFACE.equals(optionKey)) {
			try {
				outgoingIf = value.equals("default") ? null : NetworkInterface.getByName(value);
			}
			catch (final SocketException e) {
				logger.error("option " + optionKey + " for interface " + name, e);
			}
		}
		else
			logger.warn("option \"" + optionKey + "\" not supported or unknown");
	}

	/**
	 * Launches this server to run its services.
	 * <p>
	 * Depending on server configuration and method parameters, the discovery service,
	 * routing service, and the control endpoint services as determined by the added
	 * service containers are started.<br>
	 * If this server is already running, this method returns immediately.
	 * 
	 * @throws KNXIllegalStateException on no service containers available in this server
	 */
	public synchronized void launch()
	{
		if (running)
			return;
		if (svcContainers.isEmpty())
			throw new KNXIllegalStateException(name + " has no service containers added");
		logger.info("launch KNXnet/IP server " + getFriendlyName());
		startDiscoveryService(outgoingIf, discoveryIfs, 9);

		for (final Iterator i = svcContainers.iterator(); i.hasNext();) {
			final ServiceContainer sc = (ServiceContainer) i.next();
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

		for (final Iterator i = controlEndpoints.iterator(); i.hasNext();) {
			final LooperThread t = (LooperThread) i.next();
			t.quit();
		}
		controlEndpoints.clear();
		for (final Iterator i = routingEndpoints.iterator(); i.hasNext();) {
			final LooperThread t = (LooperThread) i.next();
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
		return name;
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

	private class IosListener implements InterfaceObjectServerListener
	{
		IosListener()
		{}

		public void onPropertyValueChanged(final PropertyEvent pe)
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
						final byte[] stateData = ios.getProperty(
								InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance,
								PID.KNXNETIP_DEVICE_STATE, 1, 1);
						state = stateData[0] & 0xff;
					}
					catch (final KNXPropertyException e) {
						logger.warn("on querying device state for sending "
								+ "routing lost message", e);
					}

					final RoutingLostMessage msg = new RoutingLostMessage(lost, state);
					final RoutingService svc = (RoutingService) t.getLooper();
					svc.r.send(msg);
				}
				catch (final KNXConnectionClosedException e) {
					logger.error("sending routing lost message notification", e);
				}
			}
		}
	}

	private void initBasicServerProperties() throws KNXFormatException, KNXPropertyException
	{
		if (ios == null)
			ios = new InterfaceObjectServer(false);
		ios.addServerListener(new IosListener());

		// initialize interface device object properties

		// TODO check what's max value for long frames (and actually enforce it ;)
		ios.setProperty(devObject, objectInstance, PID.MAX_APDULENGTH, 1, 1, new byte[] { 0, 15 });
		ios.setProperty(devObject, objectInstance, PID.DESCRIPTION, 1, defDesc.length, defDesc);

		final String[] sver = split(Settings.getLibraryVersion(), ". -");
		final int ver = Integer.parseInt(sver[0]) << 12 | Integer.parseInt(sver[1]) << 6
				| Integer.parseInt(sver[2]);
		ios.setProperty(devObject, objectInstance, PID.VERSION, 1, 1, new byte[] {
			(byte) (ver >>> 8), (byte) (ver & 0xff) });

		// revision counting is not aligned with library version for now
		ios.setProperty(devObject, objectInstance, PID.FIRMWARE_REVISION, 1, 1, new byte[] { 1 });

		//
		// set properties used in device DIB for search response during discovery
		//
		// device status is not in programming mode
		ios.setProperty(devObject, objectInstance, PID.PROGMODE, 1, 1,
				new byte[] { defDeviceStatus });
		ios.setProperty(devObject, objectInstance, PID.SERIAL_NUMBER, 1, 1, defSerialNumber);
		// server KNX device address, since we don't know about routing at this time
		// address is always 0.0.0; might be updated later or by routing configuration
		final byte[] device = new IndividualAddress(0).toByteArray();

		// equal to PID.KNX_INDIVIDUAL_ADDRESS
		ios.setProperty(devObject, objectInstance, PID.SUBNET_ADDRESS, 1, 1,
				new byte[] { device[0] });
		ios.setProperty(devObject, objectInstance, PID.DEVICE_ADDRESS, 1, 1,
				new byte[] { device[1] });

		//
		// set properties used in manufacturer data DIB for discovery self description
		//
		ios.setProperty(devObject, objectInstance, PID.MANUFACTURER_ID, 1, 1,
				bytesFromWord(defMfrId));
		ios.setProperty(devObject, objectInstance, PID.MANUFACTURER_DATA, 1, defMfrData.length / 4,
				defMfrData);

		// set default medium to TP1 (Bit 1 set)
		ios.setProperty(InterfaceObject.CEMI_SERVER_OBJECT, objectInstance, PID.MEDIUM_TYPE, 1, 1,
				new byte[] { 0, 2 });
	}

	// precondition: we have an IOS instance
	private void initKNXnetIpParameterObject(final int objectInstance,
		final RoutingEndpoint endpoint) throws KNXPropertyException
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
		if (endpoint != null)
			setRoutingConfiguration(endpoint);
		else
			resetRoutingConfiguration();

		// ip and setup multicast
		byte[] ip = new byte[4];
		try {
			ip = InetAddress.getLocalHost().getAddress();
		}
		catch (final UnknownHostException e) {}
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
		ios.setProperty(knxObject, objectInstance, PID.CURRENT_IP_ASSIGNMENT_METHOD, 1, 1,
				new byte[] { 1 });
	}

	private void setRoutingConfiguration(final RoutingEndpoint endpoint)
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
					data = ios.getProperty(knxObject, 1, PID.ROUTING_MULTICAST_ADDRESS, 1, 1);
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
			logger.fatal(s, e);
			throw new KNXPropertyException(s, CEMIDevMgmt.ErrorCodes.UNSPECIFIED_ERROR);
		}
		ios.setProperty(knxObject, 1, PID.ROUTING_MULTICAST_ADDRESS, 1, 1, mcast.getAddress());

		matchRoutingServerDeviceAddress(objectInstance, true);
	}

	private void resetRoutingConfiguration()
	{
		// routing multicast shall be set 0 if no routing service offered
		try {
			ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
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
		}
		catch (final KNXPropertyException ignore) {
			logger.warn("error matching server device address to routing capabilities ");
		}
	}

	// returns a property element value as integer, or the supplied default on error
	private int getProperty(final int objectType, final int propertyId, final int elements,
		final int def)
	{
		try {
			return toInt(ios.getProperty(objectType, objectInstance, propertyId, 1, elements));
		}
		catch (final KNXPropertyException e) {
			return def;
		}
	}
	
	private DeviceDIB createDeviceDIB(final ServiceContainer sc)
	{
		byte[] name;
		try {
			// friendly name property entry is an array of 30 characters
			name = ios.getProperty(knxObject, objectInstance, PID.FRIENDLY_NAME, 1, 30);
		}
		catch (final KNXPropertyException e) {
			name = new byte[30];
			System.arraycopy(defFriendlyName, 0, name, 0, defFriendlyName.length);
		}
		final StringBuffer sb = new StringBuffer(30);
		for (int i = 0; i < name.length && name[i] > 0; ++i)
			sb.append((char) (name[i] & 0xff));
		final String friendly = sb.toString();

		final int deviceStatus = getProperty(devObject, PID.PROGMODE, 1, defDeviceStatus);
		final int projectInstallationId = getProperty(knxObject, PID.PROJECT_INSTALLATION_ID, 1,
				defProjectInstallationId);

		byte[] serialNumber = defSerialNumber;
		try {
			serialNumber = ios.getProperty(devObject, objectInstance, PID.SERIAL_NUMBER, 1, 1);
		}
		catch (final KNXPropertyException e1) {}

		IndividualAddress knxAddress = defKnxAddress;
		try {
			knxAddress = new IndividualAddress(ios.getProperty(knxObject, objectInstance,
					PID.KNX_INDIVIDUAL_ADDRESS, 1, 1));
		}
		catch (final KNXPropertyException e1) {}

		InetAddress mcast = defRoutingMulticast;
		try {
			mcast = InetAddress.getByAddress(ios.getProperty(knxObject, objectInstance,
					PID.ROUTING_MULTICAST_ADDRESS, 1, 1));
		}
		catch (final UnknownHostException e) {}
		catch (final KNXPropertyException e) {}

		byte[] macAddress = defMacAddress;
		try {
			macAddress = ios.getProperty(knxObject, objectInstance, PID.MAC_ADDRESS, 1, 1);
		}
		catch (final KNXPropertyException e) {}

		return new DeviceDIB(friendly, deviceStatus, projectInstallationId, sc.getKNXMedium(),
				knxAddress, serialNumber, mcast, macAddress);
	}

	private ServiceFamiliesDIB createServiceFamiliesDIB()
	{
		// we get a 2 byte value
		final int caps = getProperty(knxObject, PID.KNXNETIP_DEVICE_CAPABILITIES, 1, defDeviceCaps);

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

	private ManufacturerDIB createManufacturerDIB()
	{
		final int mfrId = getProperty(InterfaceObject.DEVICE_OBJECT, PID.MANUFACTURER_ID, 1,
				defMfrId);
		byte[] data = defMfrData;
		try {
			final int elems = toInt(ios.getProperty(InterfaceObject.DEVICE_OBJECT, 1,
					PID.MANUFACTURER_DATA, 0, 1));
			data = ios.getProperty(InterfaceObject.DEVICE_OBJECT, 1, PID.MANUFACTURER_DATA, 1,
					elems);
		}
		catch (final KNXPropertyException e) {}
		return new ManufacturerDIB(mfrId, data);
	}

	private void startDiscoveryService(final NetworkInterface outgoing,
		final NetworkInterface[] netIfs, final int retryAttempts)
	{
		if (runDiscovery) {
			final Builder builder = new Builder(outgoing, netIfs);
			final LooperThread t = new LooperThread(name + "/KNXnet/IP discovery endpoint",
					retryAttempts, builder);
			discovery = t;
			discovery.start();
		}
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
		final LooperThread t = new LooperThread(name + "/" + sc.getName() + " control endpoint", 9,
				new Builder(true, sc, null));
		controlEndpoints.add(t);
		t.start();
		if (sc instanceof RoutingEndpoint)
			startRoutingService(sc, (RoutingEndpoint) sc);
	}

	private void stopControlEndpoint(final ServiceContainer sc)
	{
		LooperThread remove = null;
		for (final Iterator i = controlEndpoints.iterator(); i.hasNext();) {
			final LooperThread t = (LooperThread) i.next();
			final ControlEndpointService ces = (ControlEndpointService) t.getLooper();
			if (ces.svcCont == sc) {
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
		final Builder builder = new Builder(sc, endpoint.getRoutingInterface(), mcast,
				multicastLoopback);
		final LooperThread t = new LooperThread(
				name + "/routing service " + mcast.getHostAddress(), 9, builder);
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
		for (final Iterator i = routingEndpoints.iterator(); i.hasNext();) {
			final LooperThread t = (LooperThread) i.next();
			final RoutingService svc = (RoutingService) t.getLooper();
			if (svc.getServiceContainer() == sc)
				return t;
		}
		return null;
	}

	private ServiceContainer findContainer(final String svcContName)
	{
		for (final Iterator i = svcContainers.iterator(); i.hasNext();) {
			final ServiceContainer sc = (ServiceContainer) i.next();
			if (sc.getName().compareTo(svcContName) == 0)
				return sc;
		}
		return null;
	}

	private ServiceContainer findContainer(final InterfaceObject io)
	{
		for (final Iterator i = svcContToIfObj.keySet().iterator(); i.hasNext();) {
			final Object svcCont = i.next();
			if (svcContToIfObj.get(svcCont) == io)
				return (ServiceContainer) svcCont;
		}
		return null;
	}

	private int assignChannelId()
	{
		// Try to assign the new channel id by counting up from the last assigned channel
		// id. We do this to eventually assign the overall usable range of ids, and to
		// avoid excessive assignment of the low channel ids only.
		// We do not assign channel id 0.
		synchronized (channelIds) {
			int id = channelIds.nextClearBit(lastChannelId + 1);
			if (id == MAX_CHANNEL_ID + 1)
				id = channelIds.nextClearBit(1);
			// if all 255 ids are in use, no more connections are possible
			if (id == MAX_CHANNEL_ID + 1)
				return 0;
			channelIds.set(id);
			lastChannelId = id;
		}
		return lastChannelId;
	}

	private void freeChannelId(final int channelId)
	{
		synchronized (channelIds) {
			channelIds.clear(channelId);
		}
	}

	private boolean matchesSubnet(final IndividualAddress addr, final IndividualAddress subnetMask)
	{
		if (subnetMask == null)
			return true;
		if (subnetMask.getArea() == addr.getArea()) {
			// if we represent an area coupler, line is 0
			if (subnetMask.getLine() == 0 || subnetMask.getLine() == addr.getLine()) {
				// address does match the mask
				return true;
			}
		}
		return false;
	}

	// null return means no address available
	private IndividualAddress assignDeviceAddress(final IndividualAddress forSubnet)
	{
		// we assign our own KNX server device address iff:
		// - no unused additional addresses are available
		// - we don't run KNXnet/IP routing

		try {
			byte[] data = ios.getProperty(knxObject, objectInstance,
					PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 0, 1);
			final int elems = (data[0] & 0xff) << 8 | data[1] & 0xff;
			for (int i = 0; i < elems; ++i) {
				data = ios.getProperty(knxObject, objectInstance,
						PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, i + 1, 1);
				final IndividualAddress addr = new IndividualAddress(data);
				if (matchesSubnet(addr, forSubnet))
					if (checkAndSetDeviceAddress(addr, false))
						return addr;
			}
		}
		catch (final KNXPropertyException e) {
			logger.warn(e.getMessage());
		}
		// there are no free addresses, or no additional address at all
		logger.info("no additional individual addresses available");

		if (!routingEndpoints.isEmpty()) {
			logger.warn("KNXnet/IP routing active, can not assign server device address");
			return null;
		}

		final byte[] data;
		try {
			data = ios.getProperty(knxObject, objectInstance, PID.KNX_INDIVIDUAL_ADDRESS, 1, 1);
		}
		catch (final KNXPropertyException e) {
			logger.error("no server device address stored in interface object server!");
			return null;
		}
		final IndividualAddress addr = new IndividualAddress(data);
		if (matchesSubnet(addr, forSubnet))
			if (checkAndSetDeviceAddress(addr, true))
				return addr;

		logger.warn("server device address already assigned to data connection");
		return null;
	}

	private boolean checkAndSetDeviceAddress(final IndividualAddress device,
		final boolean isServerAddress)
	{
		synchronized (usedKnxAddresses) {
			if (isServerAddress && activeMgmtConnections > 0) {
				logger.warn("active management connection, "
						+ "can not assign server device address");
				return false;
			}
			if (usedKnxAddresses.contains(device))
				return false;
			final String s = isServerAddress ? "assigning server device address "
					: "assigning additional individual address ";
			logger.info(s + device);
			usedKnxAddresses.add(device);
			return true;
		}
	}
	
	private void freeDeviceAddress(final IndividualAddress device)
	{
		synchronized (usedKnxAddresses) {
			usedKnxAddresses.remove(device);
		}
	}

	private void closeDataConnections(final ServiceContainer sc)
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
		final DataEndpointServiceHandler[] handlerList = (DataEndpointServiceHandler[]) dataConnections
				.toArray(new DataEndpointServiceHandler[dataConnections.size()]);
		for (int i = 0; i < handlerList.length; i++) {
			final DataEndpointServiceHandler h = handlerList[i];
			if (h.getCtrlSocketAddress().equals(addr))
				h.close(CloseEvent.SERVER_REQUEST, "quit service container", LogLevel.INFO, null);
		}
	}

	private boolean checkVersion(final KNXnetIPHeader h)
	{
		final boolean ok = h.getVersion() == KNXnetIPConnection.KNXNETIP_VERSION_10;
		if (!ok)
			logger.warn("KNXnet/IP " + (h.getVersion() >> 4) + "." + (h.getVersion() & 0xf) + " "
					+ ErrorCodes.getErrorMessage(ErrorCodes.VERSION_NOT_SUPPORTED));
		return ok;
	}

	private void fireRoutingServiceStarted(final ServiceContainer sc, final KNXnetIPRouting r)
	{
		final ServiceContainerEvent sce = new ServiceContainerEvent(this,
				ServiceContainerEvent.ROUTING_SVC_STARTED, sc, r);
		fireOnServiceContainerChange(sce);
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

	private void fireOnServiceContainerChange(final ServiceContainerEvent sce)
	{
		final EventListener[] el = listeners.listeners();
		for (int i = 0; i < el.length; i++) {
			final ServerListener l = (ServerListener) el[i];
			try {
				l.onServiceContainerChange(sce);
			}
			catch (final RuntimeException e) {
				removeServerListener(l);
				logger.error("removed event listener", e);
			}
		}
	}

	private void fireResetRequest(final String endpointName, final InetSocketAddress ctrlEndpoint)
	{
		final ShutdownEvent se = new ShutdownEvent(this, endpointName, ctrlEndpoint);
		final EventListener[] el = listeners.listeners();
		for (int i = 0; i < el.length; i++) {
			final ServerListener l = (ServerListener) el[i];
			try {
				l.onResetRequest(se);
			}
			catch (final RuntimeException e) {
				removeServerListener(l);
				logger.error("removed event listener", e);
			}
		}
	}

	private void fireShutdown()
	{
		final ShutdownEvent se = new ShutdownEvent(this, CloseEvent.USER_REQUEST, "user shutdown");
		final EventListener[] el = listeners.listeners();
		for (int i = 0; i < el.length; i++) {
			final ServerListener l = (ServerListener) el[i];
			try {
				l.onShutdown(se);
			}
			catch (final RuntimeException e) {
				removeServerListener(l);
				logger.error("removed event listener", e);
			}
		}
	}

	private static String[] split(final String text, final String delim)
	{
		final StringTokenizer st = new StringTokenizer(text, delim);
		final String[] tokens = new String[st.countTokens()];
		for (int i = 0; i < tokens.length; ++i)
			tokens[i] = st.nextToken();
		return tokens;
	}

	private static int toInt(final byte[] data)
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

	private abstract class ServiceLoop extends UdpSocketLooper implements Runnable
	{
		boolean useNat;

		ServiceLoop(final DatagramSocket socket, final int receiveBufferSize,
			final int socketTimeout)
		{
			super(socket, true, receiveBufferSize, socketTimeout, 0);
		}

		public void run()
		{
			try {
				loop();
				cleanup(LogLevel.INFO, null);
			}
			catch (final IOException e) {
				cleanup(LogLevel.ERROR, e);
			}
			catch (final RuntimeException e) {
				final SocketAddress addr = s != null && !s.isClosed() ? s.getLocalSocketAddress()
						: null;
				final String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getName();
				final StackTraceElement[] trace = e.getStackTrace();
				final String frame = trace.length > 0 ? trace[0].toString() : "frame n/a";
				logger.fatal("runtime exception in service loop " + addr + ": " + msg + " ["
						+ frame + "]");
				cleanup(LogLevel.ERROR, e);
			}
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.internal.UdpSocketLooper#onReceive(byte[], int, int)
		 */
		public void onReceive(final InetSocketAddress source, final byte[] data, final int offset,
			final int length) throws IOException
		{
			try {
				final KNXnetIPHeader h = new KNXnetIPHeader(data, offset);
				if (!sanitize(h, length))
					return;
				if (!handleServiceType(h, data, offset + h.getStructLength(), source.getAddress(),
						source.getPort())) {
					final int svc = h.getServiceType();
					logger.warn("received unknown frame (service type 0x"
							+ Integer.toHexString(svc) + ") - ignored");
				}
			}
			catch (final KNXFormatException e) {
				// if available log bad item, too
				if (e.getItem() != null) {
					logger.warn("received invalid frame, item " + e.getItem(), e);
				}
				else {
					logger.warn("received invalid frame", e);
				}
			}
		}

		protected void onTimeout()
		{
			logger.error("socket timeout - ignored, but should not happen");
		}

		abstract boolean handleServiceType(KNXnetIPHeader h, byte[] data, int offset,
			InetAddress src, int port) throws KNXFormatException, IOException;

		void cleanup(final LogLevel level, final Throwable t)
		{
			logger.log(level, Thread.currentThread().getName() + " cleanup", t);
		}

		DatagramSocket getSocket()
		{
			return s;
		}

		// logEndpointType: 0 = don't log, 1 = ctrl endpt, 2 = data endpt
		InetSocketAddress createResponseAddress(final HPAI endpoint, final InetAddress senderHost,
			final int senderPort, final int logEndpointType)
		{
			final InetAddress resIP = endpoint.getAddress();
			final int resPort = endpoint.getPort();
			// in NAT aware mode, if the data EP is incomplete or left
			// empty, we fall back to the IP address and port of the sender
			final InetSocketAddress addr;
			final String type = logEndpointType == 1 ? "control" : logEndpointType == 2 ? "data"
					: "";
			// if we once decided on NAT aware communication, we will stick to it,
			// regardless whether subsequent HPAIs contain useful information
			if (useNat)
				addr = new InetSocketAddress(senderHost, senderPort);
			else if (resIP.isAnyLocalAddress() || resPort == 0) {
				addr = new InetSocketAddress(senderHost, senderPort);
				useNat = true;
				if (logEndpointType != 0)
					logger.info("NAT aware: using " + addr + " for client response " + type
							+ " endpoint");
			}
			else {
				addr = new InetSocketAddress(resIP, resPort);
				if (logEndpointType != 0)
					logger.trace("using client-assigned response " + type + " endpoint " + addr);
			}
			return addr;
		}

		private boolean sanitize(final KNXnetIPHeader h, final int length)
		{
			if (h.getTotalLength() > length)
				logger.warn("received frame length does not match - ignored");
			else if (h.getServiceType() == 0)
				// check service type for 0 (invalid type),
				// so unused service types of us can stay 0 by default
				logger.warn("received frame with service type 0 - ignored");
			else
				return true;
			return false;
		}
	}

	private final class Builder
	{
		// discovery = 1, routing = 2, control endpoint = 3, data endpoint = 4
		private final int service;

		// routing arguments
		private final NetworkInterface send;
		private final NetworkInterface[] ni;
		private final InetAddress mc;
		// control arguments
		private final ServiceContainer sc;
		private boolean loopback;
		// data endpoint arguments
		private final DataEndpointService conn;

		// discovery
		Builder(final NetworkInterface outgoing, final NetworkInterface[] netIfs)
		{
			service = 1;
			send = outgoing;
			ni = netIfs;
			mc = null;
			sc = null;
			conn = null;
		}

		// routing
		Builder(final ServiceContainer svcCont, final NetworkInterface netIf,
			final InetAddress multicast, final boolean enableLoopback)
		{
			service = 2;
			send = null;
			ni = new NetworkInterface[] { netIf };
			mc = multicast;
			loopback = enableLoopback;
			sc = svcCont;
			conn = null;
		}

		Builder(final boolean ctrlEndpoint, final ServiceContainer ctrl,
			final DataEndpointService svc)
		{
			this.service = ctrlEndpoint ? 3 : 4;
			sc = ctrl;
			send = null;
			ni = null;
			mc = null;
			conn = svc;
		}

		ServiceLoop create()
		{
			try {
				switch (service) {
				case 1:
					return new DiscoveryService(send, ni);
				case 2:
					return new RoutingService(sc, ni[0], mc, loopback);
				case 3:
					return new ControlEndpointService(sc);
				case 4:
					return conn;
				default:
					break;
				}
			}
			catch (final Exception e) {
				logger.warn("initialization of service failed", e);
			}
			return null;
		}
	}

	// interrupt policy: cleanup and exit
	private class LooperThread extends Thread
	{
		private final int maxRetries;
		private volatile boolean quit;

		private final Builder builder;
		private volatile ServiceLoop looper;

		// maxRetries: -1: always retry, 0 none, 1: at most one retry, ...
		LooperThread(final String serviceName, final int retryAttempts, final Builder serviceBuilder)
		{
			super(serviceName);
			setDaemon(true);
			maxRetries = retryAttempts >= -1 ? retryAttempts : 0;
			builder = serviceBuilder;
		}

		public void run()
		{
			final int inc = maxRetries == -1 ? 0 : 1;
			// when we enter the loop we do not count the very first attempt as a retry
			int retries = -1;
			while (!quit) {
				retries += inc;
				if (retries > maxRetries) {
					quit = true;
					break;
				}
				looper = builder.create();
				if (looper != null) {
					// reset for the next reconnection attempt
					retries = 0;
					logger.info(super.getName() + " is up and running");
					looper.run();
					cleanup(LogLevel.INFO, null);
				}
				else if (retries == -1 || retries < maxRetries) {
					final int wait = 10;
					logger.info("retry to start " + super.getName() + " in " + wait + " seconds");
					try {
						sleep(wait * 1000);
					}
					catch (final InterruptedException e) {
						quit();
					}
				}
				else {
					logger.error("error setting up " + super.getName());
					if (builder.sc != null)
						closeDataConnections(builder.sc);
				}
			}
		}

		synchronized ServiceLoop getLooper()
		{
			return looper;
		}

		void quit()
		{
			quit = true;
			interrupt();
			// we also call quit() for looper, since interrupt will get ignored on non-
			// interruptible sockets
			final ServiceLoop l = getLooper();
			if (l != null)
				l.quit();
			else
				// only call cleanup if l is null, otherwise cleanup is called in run()
				cleanup(LogLevel.INFO, null);
		}

		void cleanup(final LogLevel level, final Throwable t)
		{
			logger.log(level, super.getName() + " closed", t);
		}
	}

	private final class DiscoveryService extends ServiceLoop
	{
		private DiscoveryService(final NetworkInterface outgoing, final NetworkInterface[] joinOn)
			throws IOException
		{
			super(null, 512, 0);
			s = createSocket(outgoing, joinOn);
		}

		private MulticastSocket createSocket(final NetworkInterface outgoing,
			final NetworkInterface[] joinOn) throws IOException
		{
			final String p = System.getProperties().getProperty("java.net.preferIPv4Stack");
			logger.trace("network stack uses IPv4 addresses: " + (p == null ? "unknown" : p));
			final MulticastSocket s;
			try {
				s = new MulticastSocket(Discoverer.SEARCH_PORT);
			}
			catch (final IOException e) {
				logger.error("failed to create discovery socket for " + name, e);
				throw e;
			}

			// send out beyond local network
			try {
				s.setTimeToLive(64);
			}
			catch (final IOException ignore) {}

			// on Windows platforms, the IP_MULTICAST_LOOP option applies to the
			// datagram receive path, whereas on Unix platforms, it applies to
			// the send path; therefore, leave loopback enabled (as by default)
//			try {
//				s.setLoopbackMode(false);
//			}
//			catch (final SocketException ignore) {}

			try {
				if (outgoing != null)
					s.setNetworkInterface(outgoing);
			}
			catch (final SocketException e) {
				logger.error("setting outgoing network interface to " + outgoing.getName());
				s.close();
				throw e;
			}
			try {
				joinOnInterfaces(s, joinOn);
			}
			catch (final IOException e) {
				s.close();
				throw e;
			}
			return s;
		}

		// supply null for joinOn to join on all found network interfaces
		private void joinOnInterfaces(final MulticastSocket s, final NetworkInterface[] joinOn)
			throws IOException
		{
			final SocketAddress group = new InetSocketAddress(systemSetupMulticast, 0);
			final List nifs = joinOn != null ? Arrays.asList(joinOn) : Collections
					.list(NetworkInterface.getNetworkInterfaces());
			final StringBuffer found = new StringBuffer();

			// we try to bind to all requested interfaces. Only if that completely fails, we throw
			// the first caught exception
			IOException thrown = null;
			boolean joinedAny = false;
			for (final Iterator i = nifs.iterator(); i.hasNext();) {
				final NetworkInterface ni = (NetworkInterface) i.next();
				found.append(" ").append(ni.getName()).append(" [");
				for (final Enumeration addrs = ni.getInetAddresses(); addrs.hasMoreElements();) {
					final InetAddress addr = (InetAddress) addrs.nextElement();
					if (addr instanceof Inet4Address) {
						found.append(addr.getHostAddress());
						try {
							s.joinGroup(group, ni);
							joinedAny = true;
							logger.info("KNXnet/IP discovery listens on interface " + ni.getName());
						}
						catch (final IOException e) {
							if (thrown == null)
								thrown = e;
							logger.error("KNXnet/IP discovery could not join interface "
									+ ni.getName(), e);
						}
						break;
					}
				}
				found.append("],");
			}
			logger.trace("found network interfaces" + found);
			if (!joinedAny)
				throw thrown;
		}

		boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset,
			final InetAddress src, final int port) throws KNXFormatException, IOException
		{
			final int svc = h.getServiceType();
			if (svc == KNXnetIPHeader.SEARCH_REQ) {
				// A request for TCP communication or a request using an unsupported
				// protocol version should result in a host protocol type error.
				// But since there is no status field in the search response,
				// we log and ignore such requests.

				if (!checkVersion(h))
					return true;
				final SearchRequest sr = new SearchRequest(data, offset);
				if (sr.getEndpoint().getHostProtocol() != HPAI.IPV4_UDP) {
					logger.warn("search requests have protocol support for UDP/IP only");
					return true;
				}

				final ServiceFamiliesDIB svcFamilies = createServiceFamiliesDIB();
				// for discovery, we do not remember previous NAT decisions
				useNat = false;
				final SocketAddress addr = createResponseAddress(sr.getEndpoint(), src, port, 1);
				for (final Iterator i = controlEndpoints.iterator(); i.hasNext();) {
					final LooperThread t = (LooperThread) i.next();
					final ControlEndpointService ces = (ControlEndpointService) t.getLooper();
					final ServiceContainer sc = ces.getServiceContainer();
					if (sc.isActivated()) {
						// we create our own HPAI from the actual socket, since
						// the service container might have opted for ephemeral port use
						final HPAI hpai = new HPAI(sc.getControlEndpoint().getHostProtocol(),
								(InetSocketAddress) ces.getSocket().getLocalSocketAddress());
						final DeviceDIB device = createDeviceDIB(sc);
						final byte[] buf = PacketHelper.toPacket(new SearchResponse(hpai, device,
								svcFamilies));
						final DatagramPacket p = new DatagramPacket(buf, buf.length, addr);
						logger.trace("sending search response containing " + sc.getName() + " to "
								+ addr);
						sendOnInterfaces(p);
					}
				}
				return true;
			}
			// other requests are rejected with error
			return false;
		}

		private void sendOnInterfaces(final DatagramPacket p) throws SocketException, IOException
		{
			final Enumeration nifs = NetworkInterface.getNetworkInterfaces();
			while (nifs.hasMoreElements()) {
				final NetworkInterface nif = (NetworkInterface) nifs.nextElement();
				// we can't use isUp or supportsMulticast on the interface with Java v1.4
				if (nif.getInetAddresses().hasMoreElements()) {
					try {
						((MulticastSocket) s).setNetworkInterface(nif);
						logger.trace("send discovery response on interface " + nif.getName()
								+ " or " + nif.getDisplayName());
						s.send(p);
					}
					catch (final SocketException e) {
						logger.info("failure sending on interface " + nif.getName() + " or "
								+ nif.getDisplayName());
					}
				}
			}
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.internal.UdpSocketLooper#quit()
		 */
		public void quit()
		{
			try {
				((MulticastSocket) s).leaveGroup(new InetSocketAddress(systemSetupMulticast, 0),
						null);
			}
			catch (final IOException ignore) {}
			super.quit();
		}
	}

	private final class RoutingService extends ServiceLoop
	{
		private final class RoutingServiceHandler extends KNXnetIPRouting
		{
			private RoutingServiceHandler(final NetworkInterface netIf, final InetAddress mcGroup,
				final boolean enableLoopback) throws KNXException
			{
				super(mcGroup);
				init(netIf, enableLoopback, false);
			}

			// forwarder for RoutingService dispatch, called from handleServiceType
			protected boolean handleServiceType(final KNXnetIPHeader h, final byte[] data,
				final int offset, final InetAddress src, final int port) throws KNXFormatException,
				IOException
			{
				return super.handleServiceType(h, data, offset, src, port);
			}

			public String getName()
			{
				return "KNXnet/IP routing service on " + ctrlEndpt.getAddress().getHostAddress();
			}

			DatagramSocket getLocalDataSocket()
			{
				return socket;
			}

			public void send(final RoutingLostMessage lost) throws KNXConnectionClosedException
			{
				final int state = getState();
				if (state == CLOSED) {
					logger.warn("send invoked on closed connection - aborted");
					throw new KNXConnectionClosedException("connection closed");
				}
				if (state < 0) {
					logger.error("send invoked in error state " + state + " - aborted");
					throw new KNXIllegalStateException("in error state, send aborted");
				}
				try {
					final byte[] buf = PacketHelper.toPacket(lost);
					final DatagramPacket p = new DatagramPacket(buf, buf.length,
							dataEndpt.getAddress(), dataEndpt.getPort());
					logger.info("sending lost message info");
					socket.send(p);
					setState(OK);
				}
				catch (final InterruptedIOException e) {
					close(CloseEvent.USER_REQUEST, "interrupted", LogLevel.WARN, e);
					Thread.currentThread().interrupt();
					throw new KNXConnectionClosedException("interrupted connection got closed");
				}
				catch (final IOException e) {
					close(CloseEvent.INTERNAL, "communication failure", LogLevel.ERROR, e);
					throw new KNXConnectionClosedException("connection closed");
				}
			}
		}

		private final RoutingServiceHandler r;
		private final ServiceContainer svcCont;

		private RoutingService(final ServiceContainer sc, final NetworkInterface netIf,
			final InetAddress mcGroup, final boolean enableLoopback) throws KNXException
		{
			super(null, 512, 0);
			svcCont = sc;
			r = new RoutingServiceHandler(netIf, mcGroup, enableLoopback);
			s = r.getLocalDataSocket();
			fireRoutingServiceStarted(svcCont, r);
		}

		ServiceContainer getServiceContainer()
		{
			return svcCont;
		}

		boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset,
			final InetAddress src, final int port) throws KNXFormatException, IOException
		{
			return r.handleServiceType(h, data, offset, src, port);
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.internal.UdpSocketLooper#quit()
		 */
		public void quit()
		{
			r.close();
			super.quit();
		}
	}

	private final class ControlEndpointService extends ServiceLoop implements ServiceCallback
	{
		private final ServiceContainer svcCont;
		private boolean activeMonitorConnection;

		private ControlEndpointService(final ServiceContainer sc) throws SocketException
		{
			super(null, 512, 0);
			svcCont = sc;
			s = createSocket();
		}

		// a data connection created over this endpoint was closed
		public void connectionClosed(final DataEndpointServiceHandler h,
			final IndividualAddress device)
		{
			dataConnections.remove(h);
			// free knx address and channel id we assigned to the connection
			freeDeviceAddress(device);
			freeChannelId(h.getChannelId());

			// we can always safely reset monitor connection flag
			activeMonitorConnection = false;

			if (h.isDeviceMgmt())
				synchronized (usedKnxAddresses) {
					--activeMgmtConnections;
				}
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.server.knxnetip.DataEndpointServiceHandler.ServiceCallback
		 * #resetRequest(tuwien.auto.calimero.server.knxnetip.DataEndpointServiceHandler)
		 */
		public void resetRequest(final DataEndpointServiceHandler h)
		{
			final InetSocketAddress ctrlEndpoint = null;
			fireResetRequest(h.getName(), ctrlEndpoint);
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.internal.UdpSocketLooper#quit()
		 */
		public void quit()
		{
			// we close our data connections only, if we were intentionally closed,
			// (and not always in cleanup() )
			closeDataConnections(svcCont);
			super.quit();
		}

		ServiceContainer getServiceContainer()
		{
			return svcCont;
		}

		boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset,
			final InetAddress src, final int port) throws KNXFormatException, IOException
		{
			final int svc = h.getServiceType();
			if (svc == KNXnetIPHeader.DESCRIPTION_REQ) {
				if (!checkVersion(h))
					return true;
				final DescriptionRequest dr = new DescriptionRequest(data, offset);
				if (dr.getEndpoint().getHostProtocol() != HPAI.IPV4_UDP) {
					logger.warn("description request: protocol support for UDP/IP only");
					return true;
				}
				final DeviceDIB device = createDeviceDIB(svcCont);
				final ServiceFamiliesDIB svcFamilies = createServiceFamiliesDIB();
				final ManufacturerDIB mfr = createManufacturerDIB();
				final byte[] buf = PacketHelper.toPacket(new DescriptionResponse(device,
						svcFamilies, mfr));
				final DatagramPacket p = new DatagramPacket(buf, buf.length, createResponseAddress(
						dr.getEndpoint(), src, port, 1));
				s.send(p);
			}
			else if (svc == KNXnetIPHeader.CONNECT_REQ) {
				final ConnectRequest req = new ConnectRequest(data, offset);
				int status = ErrorCodes.NO_ERROR;

				if (req.getDataEndpoint().getHostProtocol() != HPAI.IPV4_UDP) {
					logger.warn("connect request: only connection support for UDP/IP");
					status = ErrorCodes.HOST_PROTOCOL_TYPE;
				}
				else if (!checkVersion(h))
					status = ErrorCodes.VERSION_NOT_SUPPORTED;

				int channelId = 0;
				if (status == ErrorCodes.NO_ERROR) {
					channelId = assignChannelId();
					if (channelId == 0)
						status = ErrorCodes.NO_MORE_CONNECTIONS;
				}
				final InetSocketAddress dataEndpt = createResponseAddress(req.getDataEndpoint(),
						src, port, 2);
				byte[] buf = null;

				if (status == ErrorCodes.NO_ERROR) {
					logger.info(svcCont.getName()
							+ ": setup data endpoint for connection request from " + dataEndpt);
					final InetSocketAddress ctrlEndpt = createResponseAddress(
							req.getControlEndpoint(), src, port, 1);
					final Object[] init = initNewConnection(req, ctrlEndpt, dataEndpt, channelId);
					status = ((Integer) init[0]).intValue();
					if (status == ErrorCodes.NO_ERROR)
						buf = PacketHelper.toPacket(new ConnectResponse(channelId, status,
								(HPAI) init[1], (CRD) init[2]));
				}
				if (buf == null) {
					freeChannelId(channelId);
					buf = PacketHelper.toPacket(new ConnectResponse(status));
					logger.warn("no data endpoint for connection with " + dataEndpt + ", "
							+ ErrorCodes.getErrorMessage(status));
				}
				final DatagramPacket p = new DatagramPacket(buf, buf.length, dataEndpt);
				s.send(p);
			}
			else if (svc == KNXnetIPHeader.CONNECT_RES)
				logger.warn("received connect response - ignored");
			else if (svc == KNXnetIPHeader.DISCONNECT_REQ) {
				final DisconnectRequest dr = new DisconnectRequest(data, offset);
				// find connection based on channel id
				final int channelId = dr.getChannelID();
				final KNXnetIPConnection conn = findConnection(channelId);

				// requests with wrong channel ID are ignored (conforming to spec)
				if (conn == null) {
					logger.warn("received disconnect request with unknown channel id "
							+ dr.getChannelID() + " - ignored");
					return true;
				}

				// According to specification, a control endpoint is allowed to change
				// during an established connection, but it's not recommended; if the
				// sender control endpoint differs from our connection control endpoint,
				// issue a warning
				final InetSocketAddress ctrlEndpt = conn.getRemoteAddress();
				if (!ctrlEndpt.getAddress().equals(src) || ctrlEndpt.getPort() != port) {
					logger.warn("disconnect request: sender control endpoint changed " + "from "
							+ ctrlEndpt + " to " + src + ", not recommended");
				}
				final byte[] buf = PacketHelper.toPacket(new DisconnectResponse(channelId,
						ErrorCodes.NO_ERROR));
				final DatagramPacket p = new DatagramPacket(buf, buf.length,
						ctrlEndpt.getAddress(), ctrlEndpt.getPort());
				try {
					s.send(p);
				}
				catch (final IOException e) {
					logger.error("communication failure", e);
				}
				finally {
					((DataEndpointServiceHandler) conn).cleanup(CloseEvent.CLIENT_REQUEST,
							"client request", LogLevel.INFO, null);
				}
			}
			else if (svc == KNXnetIPHeader.DISCONNECT_RES) {
				final DisconnectResponse res = new DisconnectResponse(data, offset);
				if (res.getStatus() != ErrorCodes.NO_ERROR)
					logger.warn("received disconnect response status 0x"
							+ Integer.toHexString(res.getStatus()) + " ("
							+ ErrorCodes.getErrorMessage(res.getStatus()) + ")");
				// finalize closing
			}
			else if (svc == KNXnetIPHeader.CONNECTIONSTATE_REQ) {
				final ConnectionstateRequest csr = new ConnectionstateRequest(data, offset);
				int status = checkVersion(h) ? ErrorCodes.NO_ERROR
						: ErrorCodes.VERSION_NOT_SUPPORTED;
				if (status == ErrorCodes.NO_ERROR
						&& csr.getControlEndpoint().getHostProtocol() != HPAI.IPV4_UDP)
					status = ErrorCodes.HOST_PROTOCOL_TYPE;

				final KNXnetIPConnection c = findConnection(csr.getChannelID());
				if (status == ErrorCodes.NO_ERROR && c == null)
					status = ErrorCodes.CONNECTION_ID;

				if (status == ErrorCodes.NO_ERROR) {
					logger.trace("received connection state request from " + c.getRemoteAddress()
							+ " for channel " + csr.getChannelID());
					((DataEndpointServiceHandler) c).updateLastMsgTimestamp();
				}
				else
					logger.warn("received invalid connection state request: "
							+ ErrorCodes.getErrorMessage(status));

				// At this point, if we know about an error with the data connection,
				// set status to ErrorCodes.DATA_CONNECTION; if we know about problems
				// with the KNX subnet, set status to ErrorCodes.KNX_CONNECTION.
				// if (some connection error)
				// status = ErrorCodes.DATA_CONNECTION;
				// if (some subnet problem)
				// status = ErrorCodes.KNX_CONNECTION;

				final byte[] buf = PacketHelper.toPacket(new ConnectionstateResponse(csr
						.getChannelID(), status));
				final DatagramPacket p = new DatagramPacket(buf, buf.length, createResponseAddress(
						csr.getControlEndpoint(), src, port, 0));
				s.send(p);
			}
			else if (svc == KNXnetIPHeader.CONNECTIONSTATE_RES)
				logger.warn("received connection state response - ignored");
			else {
				DataEndpointServiceHandler sh = null;
				try {
					// to get the channel id, we are just interested in connection header
					// which has the same layout for request and ack
					final int channelId = PacketHelper.getEmptyServiceRequest(h, data, offset)
							.getChannelID();
					sh = findConnection(channelId);
				}
				catch (final KNXFormatException e) {}
				if (sh != null)
					return sh.handleDataServiceType(h, data, offset);
				return false;
			}
			return true;
		}

		private DatagramSocket createSocket() throws SocketException
		{
			DatagramSocket s;
			final HPAI ep = svcCont.getControlEndpoint();
			try {
				s = new DatagramSocket(null);
				// if we use the KNXnet/IP default port, we have to enable address reuse
				// for a successful bind
				if (ep.getPort() == KNXnetIPConnection.DEFAULT_PORT)
					s.setReuseAddress(true);
				s.bind(new InetSocketAddress(ep.getAddress(), ep.getPort()));
				logger.trace("created socket on " + s.getLocalSocketAddress());
			}
			catch (final SocketException e) {
				logger.error("socket creation failed for "
						+ new InetSocketAddress(ep.getAddress(), ep.getPort()), e);
				throw e;
			}
			return s;
		}

		// returns Object[] = { Integer(status), localEndpt, CRD }
		// CRD and localEndpt might be null if status != NO_ERROR
		private Object[] initNewConnection(final ConnectRequest req,
			final InetSocketAddress ctrlEndpt, final InetSocketAddress dataEndpt,
			final int channelId)
		{
			final Object[] ret = new Object[3];
			ret[0] = new Integer(ErrorCodes.NO_ERROR);

			boolean tunnel = true;
			boolean busmonitor = false;
			IndividualAddress device = null;

			final int connType = req.getCRI().getConnectionType();
			if (connType == KNXnetIPTunnel.TUNNEL_CONNECTION) {
				final int knxLayer = ((TunnelCRI) req.getCRI()).getKNXLayer();
				if (knxLayer != KNXnetIPTunnel.LINK_LAYER
						&& knxLayer != KNXnetIPTunnel.BUSMONITOR_LAYER)
					return new Object[] { new Integer(ErrorCodes.TUNNELING_LAYER) };

				busmonitor = knxLayer == KNXnetIPTunnel.BUSMONITOR_LAYER;
				if (busmonitor) {
					// check if service container has busmonitor allowed
					if (!svcCont.isNetworkMonitoringAllowed())
						return new Object[] { new Integer(ErrorCodes.TUNNELING_LAYER) };

					// KNX specification says that if tunneling on busmonitor is
					// supported, only one tunneling connection is allowed per subnetwork,
					// i.e., if there are any active link-layer connections, we don't
					// allow tunneling on busmonitor.
					for (final Iterator i = dataConnections.iterator(); i.hasNext();) {
						final DataEndpointServiceHandler h = (DataEndpointServiceHandler) i.next();
						if (h.getCtrlSocketAddress().equals(s.getLocalSocketAddress())) {
							logger.warn("active tunneling on link-layer connections, "
									+ "tunneling on busmonitor currently not allowed");
							return new Object[] { new Integer(ErrorCodes.NO_MORE_CONNECTIONS) };
						}
					}
				}
				else {
					// KNX specification says that if tunneling on busmonitor is
					// supported, only one tunneling connection is allowed per subnetwork,
					// i.e., if there is an active bus monitor connection, we don't
					// allow any other tunneling connections.
					if (activeMonitorConnection) {
						logger.warn("active tunneling on busmonitor connection, "
								+ "no more connections allowed");
						return new Object[] { new Integer(ErrorCodes.NO_MORE_CONNECTIONS) };
					}
				}

				device = assignDeviceAddress(svcCont.getSubnetAddress());
				if (device == null)
					return new Object[] { new Integer(ErrorCodes.NO_MORE_CONNECTIONS) };
				ret[2] = new TunnelCRD(device);
			}
			else if (connType == KNXnetIPDevMgmt.DEVICE_MGMT_CONNECTION) {
				// At first, check if we are allowed to open mgmt connection at all; if
				// server assigned its own device address, we have to reject the request
				synchronized (usedKnxAddresses) {
					try {
						if (usedKnxAddresses.contains(new IndividualAddress(ios.getProperty(
								knxObject, objectInstance, PID.KNX_INDIVIDUAL_ADDRESS, 1, 1)))) {
							logger.warn("server assigned its own device address, "
									+ "no management connections allowed at this time");
							return new Object[] { new Integer(ErrorCodes.CONNECTION_TYPE) };
						}
					}
					catch (final KNXPropertyException e) {
						// if no such property, the user deleted it,
						// and we simply allow the connection
					}
					++activeMgmtConnections;
				}

				tunnel = false;
				ret[2] = CRD.createResponse(KNXnetIPDevMgmt.DEVICE_MGMT_CONNECTION, null);
			}
			else
				return new Object[] { new Integer(ErrorCodes.CONNECTION_TYPE) };

			ServiceLoop svcLoop = null;
			ServiceCallback cb = null;
			final boolean useThisCtrlEp = svcCont.reuseControlEndpoint();

			if (useThisCtrlEp) {
				svcLoop = this;
				cb = this;
			}
			else {
				try {
					final DataEndpointService looper = new DataEndpointService(this, s);
					cb = looper;
					svcLoop = looper;
				}
				catch (final SocketException e) {
					// if thread did not initialize properly, we get null returned
					// we don't have any better error than NO_MORE_CONNECTIONS for this
					return new Object[] { new Integer(ErrorCodes.NO_MORE_CONNECTIONS) };
				}
			}

			// we always create our own HPAI from the socket, since the service container
			// might have opted for ephemeral port use
			ret[1] = new HPAI(svcCont.getControlEndpoint().getHostProtocol(),
					(InetSocketAddress) svcLoop.getSocket().getLocalSocketAddress());
			final DataEndpointServiceHandler sh = new DataEndpointServiceHandler(cb, s,
					svcLoop.getSocket(), ctrlEndpt, dataEndpt, channelId, device, tunnel,
					busmonitor, useNat);

			final boolean accept = acceptConnection(sh, device);
			if (!accept) {
				sh.close();
				return new Object[] { new Integer(ErrorCodes.NO_MORE_CONNECTIONS) };
			}
			dataConnections.add(sh);
			activeMonitorConnection = busmonitor;
			if (!useThisCtrlEp) {
				((DataEndpointService) svcLoop).svcHandler = sh;
				new LooperThread(name + "/" + svcCont.getName() + " data endpoint", 0, new Builder(
						false, null, (DataEndpointService) svcLoop)).start();
			}
			return ret;
		}

		private boolean acceptConnection(final KNXnetIPConnection conn, final IndividualAddress addr)
		{
			final EventListener[] el = listeners.listeners();
			for (int i = 0; i < el.length; i++) {
				final ServerListener l = (ServerListener) el[i];
				if (!l.acceptDataConnection(conn, addr))
					return false;
			}
			return true;
		}

		private DataEndpointServiceHandler findConnection(final int channelId)
		{
			for (final Iterator i = dataConnections.iterator(); i.hasNext();) {
				final DataEndpointServiceHandler c = (DataEndpointServiceHandler) i.next();
				if (c.getChannelId() == channelId)
					return c;
			}
			return null;
		}
	}

	private final class DataEndpointService extends ServiceLoop implements ServiceCallback
	{
		// KNX receive timeout in seconds
		private static final int MAX_RECEIVE_INTERVAL = 120;

		private DataEndpointServiceHandler svcHandler;
		private final ServiceCallback callback;

		DataEndpointService(final ServiceCallback callback, final DatagramSocket localCtrlEndpt)
			throws SocketException
		{
			super(new DatagramSocket(0, localCtrlEndpt.getLocalAddress()), 512,
					MAX_RECEIVE_INTERVAL * 1000);
			this.callback = callback;
			logger.info("created socket on " + s.getLocalSocketAddress());
		}

		public void connectionClosed(final DataEndpointServiceHandler h,
			final IndividualAddress assigned)
		{
			quit();
			callback.connectionClosed(h, assigned);
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.server.knxnetip.DataEndpointServiceHandler.ServiceCallback
		 * #resetRequest(tuwien.auto.calimero.server.knxnetip.DataEndpointServiceHandler)
		 */
		public void resetRequest(final DataEndpointServiceHandler h)
		{
			final InetSocketAddress ctrlEndpoint = null;
			fireResetRequest(h.getName(), ctrlEndpoint);
		}

		protected void onTimeout()
		{
			// at first check if control endpoint received a connection-state request in
			// the meantime and updated the last msg timestamp
			final long now = System.currentTimeMillis();
			if (now - svcHandler.getLastMsgTimestamp() >= MAX_RECEIVE_INTERVAL * 1000)
				svcHandler.close(CloseEvent.SERVER_REQUEST, "server connection timeout",
						LogLevel.WARN, null);
			else
				setTimeout();
		}

		void cleanup(final LogLevel level, final Throwable t)
		{
			if (t != null)
				svcHandler.cleanup(CloseEvent.INTERNAL, "communication failure", level, t);
		};

		/**
		 * @param src
		 * @param port
		 */
		boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset,
			final InetAddress src, final int port) throws KNXFormatException, IOException
		{
			try {
				return svcHandler.handleDataServiceType(h, data, offset);
			}
			finally {
				setTimeout();
			}
		}

		private void setTimeout()
		{
			// don't allow timeout 0, otherwise socket will have infinite timeout
			final long elapsed = System.currentTimeMillis() - svcHandler.getLastMsgTimestamp();
			final int timeout = Math.max((int) (MAX_RECEIVE_INTERVAL * 1000 - elapsed), 250);
			try {
				s.setSoTimeout(timeout);
			}
			catch (final SocketException e) {}
		}
	}
}
