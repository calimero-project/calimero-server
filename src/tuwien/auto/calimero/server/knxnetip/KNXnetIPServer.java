/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2022 B. Malinowsky

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
import static tuwien.auto.calimero.knxnetip.KNXnetIPRouting.DefaultMulticast;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Supplier;

import org.slf4j.Logger;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DeviceDescriptor.DD0;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KnxRuntimeException;
import tuwien.auto.calimero.ReturnCode;
import tuwien.auto.calimero.Settings;
import tuwien.auto.calimero.datapoint.Datapoint;
import tuwien.auto.calimero.device.BaseKnxDevice;
import tuwien.auto.calimero.device.KnxDevice;
import tuwien.auto.calimero.device.KnxDeviceServiceLogic;
import tuwien.auto.calimero.device.ServiceResult;
import tuwien.auto.calimero.device.ios.DeviceObject;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KnxPropertyException;
import tuwien.auto.calimero.device.ios.KnxipParameterObject;
import tuwien.auto.calimero.device.ios.PropertyEvent;
import tuwien.auto.calimero.dptxlator.DPTXlator;
import tuwien.auto.calimero.dptxlator.DPTXlator2ByteUnsigned;
import tuwien.auto.calimero.dptxlator.DPTXlator8BitUnsigned;
import tuwien.auto.calimero.dptxlator.PropertyTypes;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.knxnetip.KNXConnectionClosedException;
import tuwien.auto.calimero.knxnetip.util.DeviceDIB;
import tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB;
import tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB.ServiceFamily;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.link.medium.PLSettings;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.Destination;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.secure.KnxSecureException;
import tuwien.auto.calimero.server.ServerConfiguration;

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
 * {@link #getInterfaceObjectServer()} to query or modify KNXnet/IP server properties.
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
	// PID.PROJECT_INSTALLATION_ID
	private static final int defProjectInstallationId = 0;
	// PID.KNX_INDIVIDUAL_ADDRESS
	// we use default KNX address for KNXnet/IP routers
	private static final IndividualAddress defKnxAddress = new IndividualAddress(0xff00);

	// Values used for service families DIB

	// PID.KNXNETIP_DEVICE_CAPABILITIES
	// Bits LSB to MSB: 0 Device Management, 1 Tunneling, 2 Routing, 3 Remote Logging,
	// 4 Remote Configuration and Diagnosis, 5 Object Server
	private static final int defDeviceCaps = 1 + 2 + 4;

	// Values used for manufacturer data DIB

	// from init KNX properties

	// unmodifiable name assigned by user, used in getName() and logger
	private final String serverName;
	// server friendly name, matches PID.FRIENDLY_NAME property
	private final String friendlyName;

	final Logger logger;

	private boolean running;
	private boolean inShutdown;

	// Discovery and description

	private boolean runDiscovery;
	private LooperTask discovery;
	private NetworkInterface[] outgoingIf;
	private NetworkInterface[] discoveryIfs;

	// KNX endpoint and connection stuff

	// true to enable multicast loopback, false to disable loopback
	// used in KNXnet/IP Routing
	private boolean multicastLoopback = true;

	class Endpoint {
		final ServiceContainer serviceContainer;
		final KnxipParameterObject knxipParameters;
		private final LooperTask controlEndpoint;
		private volatile LooperTask routingEndpoint;

		Endpoint(final ServiceContainer sc, final KnxipParameterObject knxipParameters, final LooperTask controlEndpoint) {
			serviceContainer = sc;
			this.knxipParameters = knxipParameters;
			this.controlEndpoint = controlEndpoint;
		}

		Optional<ControlEndpointService> controlEndpoint() {
			return controlEndpoint.looper().map(ControlEndpointService.class::cast);
		}

		Optional<RoutingService> routingEndpoint() {
			return Optional.ofNullable(routingEndpoint).flatMap(LooperTask::looper).map(RoutingService.class::cast);
		}

		void start() {
			if (!serviceContainer.isActivated())
				return;
			LooperTask.scheduleWithRetry(controlEndpoint);
			if (serviceContainer instanceof RoutingServiceContainer) {
				final var routingContainer = (RoutingServiceContainer) serviceContainer;
				final var mcast = knxipParameters.inetAddress(PropertyAccess.PID.ROUTING_MULTICAST_ADDRESS);
				routingEndpoint = new LooperTask(KNXnetIPServer.this,
						// TODO mcast address might change
						serverName + " routing service " + mcast.getHostAddress(), -1,
						() -> new RoutingService(KNXnetIPServer.this, routingContainer, multicastLoopback));
				LooperTask.scheduleWithRetry(routingEndpoint);
			}
		}

		void stop() {
			controlEndpoint.quit();
			final var routing = routingEndpoint;
			if (routing != null)
				routing.quit();
		}
	}

	final List<Endpoint> endpoints = new CopyOnWriteArrayList<>();

	private final KnxDevice device;
	private final InterfaceObjectServer ios;
	private static final int knxObject = KNXNETIP_PARAMETER_OBJECT;

	private static final int objectInstance = 1;

	private final EventListeners<ServerListener> listeners;

	private final class KnxServerDevice extends BaseKnxDevice {

		KnxServerDevice(final ServerConfiguration config, final KnxDeviceServiceLogic logic) {
			super(config.name(), DD0.TYPE_091A, null, logic, config.iosResource().orElse(null),
					config.iosResourcePassword());
		}

		@Override
		protected void ipRoutingConfigChanged(final RoutingConfig config) {
			for (final var ep : endpoints) {
				final var rep = ep.routingEndpoint();
				if (rep.isPresent()) {
					// TODO support >1 routing services
					final var routingService = rep.get();
					routingService.quit();
					return;
				}
			}
		}
	}

	final KnxDeviceServiceLogic logic = new KnxDeviceServiceLogic() {
		private static final int pidIpSbcControl = 120;

		private final ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(1, r -> {
			final var t = new Thread(r, "IP SBC routing mode timeout");
			t.setDaemon(true);
			return t;
		});
		{
			scheduler.setKeepAliveTime(1, TimeUnit.MINUTES);
			scheduler.allowCoreThreadTimeOut(true);
		}

		private volatile Future<?> disableSbcFuture = CompletableFuture.completedFuture(Void.TYPE);

		@Override
		public void updateDatapointValue(final Datapoint ofDp, final DPTXlator update) {}

		@Override
		public DPTXlator requestDatapointValue(final Datapoint ofDp) throws KNXException { return null; }

		@Override
		public ServiceResult<byte[]> functionPropertyCommand(final Destination remote, final int objectIndex,
				final int propertyId, final byte[] command) {
			final int serviceId = command[1] & 0xff;
			final var ios = device.getInterfaceObjectServer();
			final int objectType = ios.getInterfaceObjects()[objectIndex].getType();

			if (objectType == InterfaceObject.ROUTER_OBJECT) {
				if (propertyId == pidIpSbcControl) {
					var returnCode = ReturnCode.Success;
					if (serviceId == 0) {
						final int info = command[2] & 0xff;
						if (info == 0 || info == 1) {
							disableSbcFuture.cancel(false);
							setSbcMode(objectIndex, info);
							if (info == 1)
								disableSbcFuture = scheduler.schedule(() -> setSbcMode(objectIndex, (byte) 0), 20,
										TimeUnit.SECONDS);
						}
						else
							returnCode = ReturnCode.DataVoid;
					}
					else
						returnCode = ReturnCode.InvalidCommand;
					return new ServiceResult<>((byte) returnCode.code(), (byte) serviceId);
				}
			}
			return super.functionPropertyCommand(remote, objectIndex, propertyId, command);
		}

		private void setSbcMode(final int objectIndex, final int info) {
			logger.info("{} IP system broadcast routing mode", info == 1 ? "enable" : "disable");
			ios.setProperty(objectIndex, pidIpSbcControl, 1, 1, (byte) info);
		}
	};

	/**
	 * Creates a new KNXnet/IP server instance using the supplied configuration.
	 * <p>
	 * During construction, the server creates its own Interface Object Server (IOS) and adds KNX properties with
	 * default values. Subsequent property changes can be done by calling {@link #getInterfaceObjectServer()}. Be aware
	 * that KNX properties added might change between implementations, as might their default property values.
	 *
	 * @param config server configuration
	 */
	public KNXnetIPServer(final ServerConfiguration config) {
		serverName = config.name();
		friendlyName = config.friendlyName();
		logger = LogService.getLogger("calimero.server." + getName());

		device = new KnxServerDevice(config, logic);
		ios = device.getInterfaceObjectServer();
		listeners = new EventListeners<>(logger);

		logger.info("{} v{}", friendlyName, Settings.getLibraryVersion());

		ios.addServerListener(this::onPropertyValueChanged);

		// server KNX device address, since we don't know about routing at this time
		// address is always 15.15.0; might be updated later or by routing configuration
		final byte[] device1 = defKnxAddress.toByteArray();
		// equal to PID.KNX_INDIVIDUAL_ADDRESS
		setProperty(DEVICE_OBJECT, objectInstance, PID.SUBNET_ADDRESS, device1[0]);
		setProperty(DEVICE_OBJECT, objectInstance, PID.DEVICE_ADDRESS, device1[1]);

		for (final var containerConfig : config.containers()) {
			final var svcContainer = containerConfig.subnetConnector().getServiceContainer();
			addServiceContainer(svcContainer);
		}
		setOption(KNXnetIPServer.OPTION_DISCOVERY_INTERFACES, config.discoveryNetifs().toString().replaceAll("\\[|\\]", ""));
		setOption(KNXnetIPServer.OPTION_OUTGOING_INTERFACE, config.outgoingNetifs().toString().replaceAll("\\[|\\]", ""));
		setOption(KNXnetIPServer.OPTION_DISCOVERY_DESCRIPTION, config.runDiscovery() ? "true" : "false");
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
	public final synchronized boolean addServiceContainer(final ServiceContainer sc)
	{
		if (findContainer(sc.getName()) != null) {
			logger.warn("service container \"" + sc.getName() + "\" already exists in server");
			return false;
		}

		// add new KNXnet/IP parameter object for this service container
		final var knxipParameters = (KnxipParameterObject) findOrAddInterfaceObject(endpoints.size() + 1, knxObject);

		final Supplier<ServiceLooper> builder = () -> new ControlEndpointService(this, sc);
		final var controlEndpoint = new LooperTask(this, serverName + " control endpoint " + sc.getName(), -1, builder);

		final var endpoint = new Endpoint(sc, knxipParameters, controlEndpoint);
		endpoints.add(endpoint);

		final var settings = sc.getMediumSettings();
		final int size = endpoints.size();
		if (size == 1) {
			final byte[] device = settings.getDeviceAddress().toByteArray();
			setProperty(DEVICE_OBJECT, objectInstance, PID.SUBNET_ADDRESS, device[0]);
			setProperty(DEVICE_OBJECT, objectInstance, PID.DEVICE_ADDRESS, device[1]);
		}
		final int medium = settings.getMedium();
		setProperty(InterfaceObject.CEMI_SERVER_OBJECT, 1, PID.MEDIUM_TYPE, (byte) 0, (byte) medium);

		final int pidMaxInterfaceApduLength = 68;
		setProperty(InterfaceObject.CEMI_SERVER_OBJECT, 1, pidMaxInterfaceApduLength, bytesFromWord(settings.maxApduLength()));
		final int pidMaxLocalApduLength = 69;
		setProperty(InterfaceObject.CEMI_SERVER_OBJECT, 1, pidMaxLocalApduLength, bytesFromWord(1400));

		if (medium == KNXMediumSettings.MEDIUM_PL110)
			setProperty(DEVICE_OBJECT, objectInstance, PID.DOMAIN_ADDRESS,
					((PLSettings) settings).getDomainAddress());

		initKNXnetIpParameterObject(size, sc);
		if (running)
			endpoint.start();
		fireServiceContainerAdded(sc);
		return true;
	}

	private InterfaceObject findOrAddInterfaceObject(final int objectInstance, final int objectType) {
		int instances = 0;
		for (final var io : ios.getInterfaceObjects()) {
			if (io.getType() == objectType && ++instances == objectInstance)
				return io;
		}
		InterfaceObject io = null;
		while (instances++ < objectInstance)
			io = ios.addInterfaceObject(objectType);
		return io;
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
	public final void removeServiceContainer(final ServiceContainer sc) {
		endpointFor(sc).ifPresent(endpoint -> {
			// stop service if we are already launched
			synchronized (this) {
				if (running)
					endpoint.stop();
			}
			endpoints.remove(endpoint);
			getInterfaceObjectServer().removeInterfaceObject(endpoint.knxipParameters);
			fireServiceContainerRemoved(sc);
		});
	}

	/**
	 * Returns all service containers currently hosted by this server.
	 *
	 * @return a new ServiceContainer array holding the service containers with the array size equal
	 *         to the number of service containers (i.e., can be an empty array)
	 */
	public ServiceContainer[] getServiceContainers()
	{
		return endpoints.stream().map(ep -> ep.serviceContainer).toArray(ServiceContainer[]::new);
	}

	/**
	 * Returns the Interface Object Server currently set (and used) by this server.
	 *
	 * @return the server IOS instance
	 */
	public final InterfaceObjectServer getInterfaceObjectServer() {
		return device.getInterfaceObjectServer();
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

	public void configureSecurity(final ServiceContainer sc, final Map<String, byte[]> keys,
			final EnumSet<ServiceFamily> securedServices) {
		final int objectInstance = objectInstance(sc);
		final var endpoint = endpointFor(sc);
		final int objIndex = endpoint.get().knxipParameters.getIndex();

		// option to not require secured services only, but also allow plain (mainly for testing)
		boolean setSecuredServices = true;
		if (securedServices.size() == 1 && securedServices.contains(ServiceFamily.Security)) {
			securedServices.clear();
			setSecuredServices = false;
		}

		// if securedServices is empty, by default we secure what is configured in the keys map;
		// otherwise, we specifically follow the securedServices set
		final boolean configureDefault = securedServices.isEmpty();
		final var secure = EnumSet.<ServiceFamily>noneOf(ServiceFamily.class);

		final boolean useSecureDevMgmtTunneling = securedServices.contains(ServiceFamily.DeviceManagement)
				|| securedServices.contains(ServiceFamily.Tunneling);
		final boolean configureSecureUnicast = configureDefault || useSecureDevMgmtTunneling;

		// if we setup secure unicast services, we need at least device authentication
		if (configureSecureUnicast && keys.containsKey("device.key")) {
			if (configureDefault || securedServices.contains(ServiceFamily.DeviceManagement))
				secure.add(ServiceFamily.DeviceManagement);
			if (configureDefault || securedServices.contains(ServiceFamily.Tunneling)) {
				if (!configureDefault && !securedServices.contains(ServiceFamily.DeviceManagement))
					throw new KnxSecureException("KNX IP secure tunneling requires secure device management");
				secure.add(ServiceFamily.Tunneling);
			}

			ios.setDescription(new Description(objIndex, KNXNETIP_PARAMETER_OBJECT, SecureSession.pidDeviceAuth, 0,
					PropertyTypes.PDT_GENERIC_16, false, 1, 1, 0, 0), true);
			setProperty(knxObject, objectInstance, SecureSession.pidDeviceAuth, keys.get("device.key"));

			boolean mgmtUser = false;
			boolean tunnelingUser = false;
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();
			for (int user = 1; keys.containsKey("user[" + user + "].key"); user++) {
				final byte[] userPwdHash = keys.get("user[" + user + "].key");
				baos.write(userPwdHash.length == 0 ? SecureSession.emptyPwdHash : userPwdHash, 0, 16);

				if (user == 1)
					mgmtUser = true;
				else
					tunnelingUser = true;
			}

			if (!mgmtUser)
				throw new KnxSecureException("KNX IP secure device management requires a configured user 1");
			if (secure.contains(ServiceFamily.Tunneling) && !tunnelingUser)
				throw new KnxSecureException("KNX IP secure tunneling requires at least one configured tunneling user");
			ios.setDescription(new Description(objIndex, KNXNETIP_PARAMETER_OBJECT, SecureSession.pidUserPwdHashes, 0,
					PropertyTypes.PDT_GENERIC_16, false, 2, 127, 0, 0), true);
			final byte[] userPwdHashes = baos.toByteArray();
			final int users = userPwdHashes.length / 16;
			ios.setProperty(knxObject, objectInstance, SecureSession.pidUserPwdHashes, 1, users, userPwdHashes);
		}
		else if (useSecureDevMgmtTunneling)
			throw new KnxSecureException("KNX IP Secure device management requires a device key");

		final boolean useSecureRouting = securedServices.contains(ServiceFamily.Routing);
		final boolean configureSecureRouting = configureDefault || useSecureRouting;
		final byte[] groupKey = keys.get("group.key");
		if (configureSecureRouting && sc instanceof RoutingServiceContainer && groupKey != null) {
			secure.add(ServiceFamily.Routing);

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
		else if (useSecureRouting)
			throw new KnxSecureException("KNX IP Secure routing requires a routing configuration");

		if (!secure.isEmpty()) {
			final byte[] caps = getProperty(knxObject, objectInstance, PID.KNXNETIP_DEVICE_CAPABILITIES,
					bytesFromWord(defDeviceCaps));
			caps[1] |= 64;
			setProperty(knxObject, objectInstance, PID.KNXNETIP_DEVICE_CAPABILITIES, caps);
		}

		if (!setSecuredServices)
			secure.clear();

		final int bits = secure.stream().mapToInt(sf -> 1 << sf.id()).sum();
		ios.setDescription(new Description(objIndex, knxObject, SecureSession.pidSecuredServices, 0,
				PropertyTypes.PDT_FUNCTION, true, 1, 1, 3, 2), true);
		setProperty(knxObject, objectInstance, SecureSession.pidSecuredServices, (byte) 0, (byte) bits);
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
		endpoints.forEach(Endpoint::start);
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

		endpoints.forEach(Endpoint::stop);

		device.close();
		inShutdown = false;
		running = false;
	}

	public final KnxDevice device() { return device; }

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

	public Map<Integer, DataEndpoint> dataConnections(final ServiceContainer serviceContainer) {
		return endpointFor(serviceContainer).flatMap(Endpoint::controlEndpoint).map(ControlEndpointService::connections)
				.orElse(Map.of());
	}

	private int lastOverflowToKnx;

	private void onPropertyValueChanged(final PropertyEvent pe)
	{
		final InterfaceObject io = pe.getInterfaceObject();
		if (pe.getPropertyId() == PID.QUEUE_OVERFLOW_TO_KNX) {
			final byte[] data = pe.getNewData();
			final int overflow = toInt(data);
			if (overflow == 0)
				return;
			final int lost = (overflow - lastOverflowToKnx) & 0xffff;
			lastOverflowToKnx = overflow;
			if (lost == 0)
				return;
			// multicast routing lost message
			endpointFor(io).ifPresent(ep -> sendRoutingLostMessage(ep, lost));
		}
		else if (io.getType() == InterfaceObject.ROUTER_OBJECT) {
			if (pe.getPropertyId() == PID.MEDIUM_STATUS) {
				final var active = (pe.getNewData()[0] & 0x01) == 0x00; // 0x01: communication impossible
				endpointFor(io).flatMap(Endpoint::controlEndpoint).ifPresent(ep -> ep.mediumConnectionStatusChanged(active));
			}
		}
	}

	private void sendRoutingLostMessage(final Endpoint endpoint, final int lost) {
		final var routingService = endpoint.routingEndpoint();
		if (routingService.isEmpty())
			return;
		final int index = endpoint.knxipParameters.getIndex();
		final int state = toInt(getInterfaceObjectServer().getProperty(index, PID.KNXNETIP_DEVICE_STATE, 1, 1));
		try {
			routingService.get().sendRoutingLostMessage(lost, state);
		}
		catch (final KNXConnectionClosedException e) {
			logger.error("sending routing lost message notification", e);
		}
	}

	private void initKNXnetIpParameterObject(final int objectInstance, final ServiceContainer endpoint)
		throws KnxPropertyException
	{
		// reset transmit counter to 0
		// those two are 4 byte unsigned
		setProperty(knxObject, objectInstance, PID.MSG_TRANSMIT_TO_IP, new byte[4]);
		setProperty(knxObject, objectInstance, PID.MSG_TRANSMIT_TO_KNX, new byte[4]);

		//
		// set properties used in device DIB for search response during discovery
		//
		// friendly name property entry is an array of 30 characters
		final byte[] data = Arrays.copyOf(friendlyName.getBytes(StandardCharsets.ISO_8859_1), 30);
		ios.setProperty(knxObject, objectInstance, PID.FRIENDLY_NAME, 1, data.length, data);
		setPropertyIfAbsent(knxObject, objectInstance, PID.PROJECT_INSTALLATION_ID,
				bytesFromWord(defProjectInstallationId));
		final byte[] addr = endpoint.getMediumSettings().getDeviceAddress().toByteArray();
		setProperty(knxObject, objectInstance, PID.KNX_INDIVIDUAL_ADDRESS, addr);
		setProperty(knxObject, objectInstance, PID.MAC_ADDRESS, new byte[6]);

		// routing stuff
		if (endpoint instanceof RoutingServiceContainer)
			setRoutingConfiguration((RoutingServiceContainer) endpoint, objectInstance);
		else
			resetRoutingConfiguration(objectInstance);
		// 100 ms is the default busy wait time
		setPropertyIfAbsent(knxObject, objectInstance, PID.ROUTING_BUSY_WAIT_TIME, bytesFromWord(100));

		// ip and setup multicast
		final byte[] ip = endpoint.getControlEndpoint().getAddress().getAddress();
		setProperty(knxObject, objectInstance, PID.CURRENT_IP_ADDRESS, ip);
		setProperty(knxObject, objectInstance, PID.SYSTEM_SETUP_MULTICAST_ADDRESS, DefaultMulticast.getAddress());

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
		setPropertyIfAbsent(knxObject, objectInstance, PID.IP_ASSIGNMENT_METHOD, new byte[] { 1 });
		setPropertyIfAbsent(knxObject, objectInstance, PID.CURRENT_IP_ASSIGNMENT_METHOD, new byte[] { 1 });
	}

	private void setRoutingConfiguration(final RoutingServiceContainer endpoint, final int objectInstance)
		throws KnxPropertyException
	{
		final byte[] data = getProperty(knxObject, objectInstance, PID.ROUTING_MULTICAST_ADDRESS, null);
		if (data == null || Arrays.equals(new byte[4], data)) {
			final var multicastAddr = endpoint.routingMulticastAddress();
			setProperty(knxObject, objectInstance, PID.ROUTING_MULTICAST_ADDRESS, multicastAddr.getAddress());
		}
	}

	private void resetRoutingConfiguration(final int objectInstance)
	{
		setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance, PID.ROUTING_MULTICAST_ADDRESS, new byte[4]);
	}

	int objectInstance(final ServiceContainer sc)
	{
		final int i = 0;
		for (final var endpoint : endpoints) {
			if (endpoint.serviceContainer == sc)
				return i + 1;
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

	private void setPropertyIfAbsent(final int objectType, final int objectInstance, final int propertyId,
			final byte... data) {
		try {
			ios.getProperty(objectType, objectInstance, propertyId, 1, 1);
		}
		catch (final KnxPropertyException ignore) {
			setProperty(objectType, objectInstance, propertyId, data);
		}
	}

	DeviceDIB createDeviceDIB(final ServiceContainer sc)
	{
		final var knxipObject = KnxipParameterObject.lookup(ios, objectInstance(sc));
		final String friendly = knxipObject.friendlyName();

		final var deviceObject = DeviceObject.lookup(ios);
		final int deviceStatus = deviceObject.programmingMode() ? 1 : 0;
		final int projectInstallationId = getProperty(knxObject, objectInstance(sc), PID.PROJECT_INSTALLATION_ID, 1,
				defProjectInstallationId);

		final var serialNumber = deviceObject.serialNumber();
		final IndividualAddress knxAddress = new IndividualAddress(
				getProperty(knxObject, objectInstance(sc), PID.KNX_INDIVIDUAL_ADDRESS, defKnxAddress.toByteArray()));
		InetAddress mcast = DefaultMulticast;
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
		final int coreVersion = ((DefaultServiceContainer) sc).udpOnly() ? 1 : 2;
		final int[] serviceVersion = { coreVersion, 2, 2, 2, 0, 0, 0, 1 };

		final var supported = new EnumMap<ServiceFamily, Integer>(ServiceFamily.class);
		for (final var familyId : ServiceFamily.values()) {
			if (!extended && familyId.id() > ServiceFamily.ObjectServer.id())
				break;
			final int bit = familyId.ordinal();
			if ((caps >> bit & 0x1) == 1)
				supported.put(familyId, serviceVersion[bit]);
		}
		if (((DefaultServiceContainer) sc).baosSupport())
			supported.put(ServiceFamily.Baos, 2);
		return new ServiceFamiliesDIB(supported);
	}

	private void startDiscoveryService(final NetworkInterface[] outgoing,
		final NetworkInterface[] listen, final int retryAttempts)
	{
		synchronized (this) {
			if (!runDiscovery)
				return;
		}
		final Supplier<ServiceLooper> builder = () -> new DiscoveryService(this, outgoing, listen);
		discovery = new LooperTask(this, serverName + " discovery endpoint", retryAttempts, builder);
		LooperTask.scheduleWithRetry(discovery);
	}

	private void stopDiscoveryService()
	{
		final LooperTask d = discovery;
		discovery = null;
		if (d != null)
			d.quit();
	}

	private Optional<Endpoint> endpointFor(final ServiceContainer sc) {
		return endpoints.stream().filter(ep -> ep.serviceContainer == sc).findFirst();
	}

	private Optional<Endpoint> endpointFor(final InterfaceObject io) {
		final var objects = getInterfaceObjectServer().getInterfaceObjects();
		Endpoint endpoint = null;
		final Iterator<Endpoint> iterator = endpoints.iterator();
		for (int i = 0; i <= io.getIndex() && iterator.hasNext(); i++) {
			if (objects[i].getType() == io.getType())
				endpoint = iterator.next();
		}
		return Optional.ofNullable(endpoint);
	}

	private ServiceContainer findContainer(final String svcContName) {
		for (final var endpoint : endpoints) {
			if (endpoint.serviceContainer.getName().equals(svcContName))
				return endpoint.serviceContainer;
		}
		return null;
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
