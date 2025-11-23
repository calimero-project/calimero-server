/*
    Calimero 3 - A library for KNX network access
    Copyright (c) 2010, 2025 B. Malinowsky

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

package io.calimero.server.gateway;

import static io.calimero.cemi.CEMIFactory.create;
import static io.calimero.device.ios.InterfaceObject.DEVICE_OBJECT;
import static io.calimero.device.ios.InterfaceObject.KNXNETIP_PARAMETER_OBJECT;
import static io.calimero.device.ios.InterfaceObject.ROUTER_OBJECT;
import static io.calimero.device.ios.InterfaceObject.SECURITY_OBJECT;
import static io.calimero.knxnetip.KNXnetIPConnection.BlockingMode.WaitForAck;
import static java.lang.String.format;
import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;

import java.lang.System.Logger;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.StringJoiner;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import io.calimero.CloseEvent;
import io.calimero.DataUnitBuilder;
import io.calimero.DeviceDescriptor;
import io.calimero.FrameEvent;
import io.calimero.GroupAddress;
import io.calimero.IndividualAddress;
import io.calimero.KNXAddress;
import io.calimero.KNXException;
import io.calimero.KNXFormatException;
import io.calimero.KNXRemoteException;
import io.calimero.KNXTimeoutException;
import io.calimero.KnxRuntimeException;
import io.calimero.Priority;
import io.calimero.ReturnCode;
import io.calimero.baos.BaosLink;
import io.calimero.baos.BaosService;
import io.calimero.cemi.AdditionalInfo;
import io.calimero.cemi.CEMI;
import io.calimero.cemi.CEMIBusMon;
import io.calimero.cemi.CEMIDevMgmt;
import io.calimero.cemi.CEMIFactory;
import io.calimero.cemi.CEMILData;
import io.calimero.cemi.CEMILDataEx;
import io.calimero.datapoint.StateDP;
import io.calimero.device.AccessPolicies;
import io.calimero.device.BaseKnxDevice;
import io.calimero.device.ios.InterfaceObject;
import io.calimero.device.ios.InterfaceObjectServer;
import io.calimero.device.ios.KnxPropertyException;
import io.calimero.device.ios.KnxipParameterObject;
import io.calimero.device.ios.PropertyEvent;
import io.calimero.device.ios.RouterObject;
import io.calimero.device.ios.SecurityObject;
import io.calimero.dptxlator.DPTXlator;
import io.calimero.dptxlator.DPTXlatorDate;
import io.calimero.dptxlator.DPTXlatorDateTime;
import io.calimero.dptxlator.DPTXlatorTime;
import io.calimero.dptxlator.PropertyTypes;
import io.calimero.dptxlator.TranslatorTypes;
import io.calimero.internal.Executor;
import io.calimero.knxnetip.KNXConnectionClosedException;
import io.calimero.knxnetip.KNXnetIPConnection;
import io.calimero.knxnetip.KNXnetIPDevMgmt;
import io.calimero.knxnetip.KNXnetIPRouting;
import io.calimero.knxnetip.LostMessageEvent;
import io.calimero.knxnetip.RoutingBusyEvent;
import io.calimero.knxnetip.RoutingListener;
import io.calimero.knxnetip.servicetype.RoutingBusy;
import io.calimero.knxnetip.servicetype.RoutingSystemBroadcast;
import io.calimero.knxnetip.util.ServiceFamiliesDIB.ServiceFamily;
import io.calimero.link.Connector.Link;
import io.calimero.link.KNXLinkClosedException;
import io.calimero.link.KNXNetworkLink;
import io.calimero.link.KNXNetworkLinkIP;
import io.calimero.link.KNXNetworkLinkUsb;
import io.calimero.link.KNXNetworkMonitor;
import io.calimero.link.LinkEvent;
import io.calimero.link.NetworkLinkListener;
import io.calimero.link.medium.KNXMediumSettings;
import io.calimero.link.medium.KnxIPSettings;
import io.calimero.log.LogService;
import io.calimero.mgmt.LocalDeviceManagementUsb;
import io.calimero.mgmt.PropertyAccess.PID;
import io.calimero.mgmt.PropertyClient;
import io.calimero.mgmt.PropertyClient.PropertyKey;
import io.calimero.secure.SecureApplicationLayer;
import io.calimero.secure.Security;
import io.calimero.secure.SecurityControl;
import io.calimero.secure.SecurityControl.DataSecurity;
import io.calimero.serial.ConnectionStatus;
import io.calimero.serial.usb.UsbConnection;
import io.calimero.server.ServerConfiguration;
import io.calimero.server.VirtualLink;
import io.calimero.server.gateway.SubnetConnector.InterfaceType;
import io.calimero.server.gateway.trace.CemiFrameTracer;
import io.calimero.server.gateway.trace.CemiFrameTracer.FramePath;
import io.calimero.server.knxnetip.DataEndpoint;
import io.calimero.server.knxnetip.DataEndpoint.ConnectionType;
import io.calimero.server.knxnetip.DefaultServiceContainer;
import io.calimero.server.knxnetip.KNXnetIPServer;
import io.calimero.server.knxnetip.KnxipQueuingEndpoint;
import io.calimero.server.knxnetip.RoutingServiceContainer;
import io.calimero.server.knxnetip.ServerListener;
import io.calimero.server.knxnetip.ServiceContainer;
import io.calimero.server.knxnetip.ServiceContainerEvent;
import io.calimero.server.knxnetip.ShutdownEvent;

/**
 * Provides gateway functionality to dispatch KNX messages between different networks and processes
 * server requests.
 * <p>
 * The main functionality is to bridge IP networks and KNX subnets and allow KNX messages exchange a
 * KNXnet/IP server and links to KNX subnets.<br>
 * Besides, the gateway handles KNXnet/IP local device management by processing and answering
 * received client messages.<br>
 * The gateway implements a group address filter using a memory-mapped table with its location stored in the KNX property
 * {@link io.calimero.mgmt.PropertyAccess.PID#TABLE_REFERENCE} in the interface object
 * {@link InterfaceObject#ROUTER_OBJECT}.
 * <p>
 * Starting a gateway by invoking {@link #run()} is a blocking operation. Therefore, this class
 * implements {@link Runnable} to allow execution in its own thread.
 *
 * @author B. Malinowsky
 */
public class KnxServerGateway implements Runnable
{
	// Connection listener for accepted KNXnet/IP connections
	private final class ConnectionListener implements RoutingListener
	{
		final ServiceContainer sc;
		final String name;


		ConnectionListener(final ServiceContainer svcContainer, final String connectionName)
		{
			sc = svcContainer;
			// same as calling ((KNXnetIPConnection) getSource()).getName()
			name = connectionName;
		}

		@Override
		public void frameReceived(final FrameEvent e)
		{
			if (!ipEvents.offer(new IpEvent(sc, e)))
				incMsgQueueOverflow(true);
		}

		@Override
		public void lostMessage(final LostMessageEvent e)
		{
			final String unit = e.getLostMessages() > 1 ? "messages" : "message";
			logger.log(WARNING, "KNXnet/IP router {0} lost {1} {2}",  e.getSender(), e.getLostMessages(), unit);
		}

		@Override
		public void routingBusy(final RoutingBusyEvent e) {}

		@Override
		public void connectionClosed(final CloseEvent e)
		{
			serverConnections.remove(e.getSource());
			logger.log(DEBUG, "removed connection {0} ({1})", name, e.getReason());
			if (e.getInitiator() == CloseEvent.CLIENT_REQUEST) {
				final KNXnetIPConnection c = (KNXnetIPConnection) e.getSource();
				subnetEventBuffers.computeIfPresent(sc, (sc, rb) -> { rb.remove(c); return rb; });
			}
		}
	}

	private final class KNXnetIPServerListener implements ServerListener
	{
		private final Set<ServiceContainer> verifiedSubnetInterfaceAddress = Collections.synchronizedSet(new HashSet<>());

		@Override
		public boolean acceptDataConnection(final ServiceContainer svcContainer, final KNXnetIPConnection conn,
				final IndividualAddress assignedDeviceAddress, final ConnectionType type) {
			final SubnetConnector connector = getSubnetConnector(svcContainer.getName());

			if (!(conn instanceof KNXnetIPDevMgmt)) {
				final AutoCloseable subnetLink = connector.getSubnetLink();
				AutoCloseable rawLink = subnetLink instanceof Link ? ((Link<?>) subnetLink).target() : subnetLink;
				try {
					if (type == ConnectionType.Baos) {
						final String format = connector.format();
						if (!"baos".equals(format))
							return false;
						connector.requestBaos(true);

						if (!(rawLink instanceof BaosLink)) {
							// TODO closeLink has a delay, which we hit twice now (here and below)
							closeLink(subnetLink);
							rawLink = null;
						}
					}
					else {
						connector.requestBaos(false);
						if (rawLink instanceof BaosLink) {
							closeLink(subnetLink);
							rawLink = null;
						}
					}

					if (rawLink instanceof VirtualLink) {
						/* no-op */
					}
					else if (type != ConnectionType.Monitor && !(rawLink instanceof KNXNetworkLink)) {
						closeLink(subnetLink);
						connector.openNetworkLink();
						// we immediately set a virtual network to connected, so that there is no
						// initial state "knx bus not connected" in a server discovery
						if (connector.interfaceType() == InterfaceType.Virtual)
							setNetworkState(1, true, false);
					}
					else if (type == ConnectionType.Monitor && !(rawLink instanceof KNXNetworkMonitor)) {
						closeLink(subnetLink);
						connector.openMonitorLink();
					}
				}
				catch (KNXException | InterruptedException e) {
					final var interfaceType = connector.interfaceType();
					final String subnetArgs = connector.linkArguments();
					final ServiceContainer serviceContainer = connector.getServiceContainer();
					final KNXMediumSettings settings = serviceContainer.getMediumSettings();
					logger.log(ERROR, MessageFormat.format("open subnet link using {0} interface {1} for {2}", interfaceType,
							subnetArgs, settings), e);
					if (e instanceof InterruptedException)
						Thread.currentThread().interrupt();
					return false;
				}
			}

			conn.addConnectionListener(new ConnectionListener(svcContainer, conn.name()));
			return true;
		}

		@Override
		public void connectionEstablished(final ServiceContainer svcContainer, final KNXnetIPConnection connection)
		{
			final var endpoint = (KnxipQueuingEndpoint) connection;
			serverConnections.add(endpoint);
			logger.log(DEBUG, "established connection {0}", connection);

			try {
				if (!verifiedSubnetInterfaceAddress.contains(svcContainer)) {
					verifySubnetInterfaceAddress(svcContainer);
					verifiedSubnetInterfaceAddress.add(svcContainer);
				}
			}
			catch (KNXException | InterruptedException | RuntimeException e) {
				String msg = e.getMessage();
				msg = msg != null && msg.length() > 0 ? msg : e.getClass().getSimpleName();
				logger.log(WARNING, "skip verifying knx address of ''{0}'' subnet interface ({1})", svcContainer.getName(), msg);
			}

			final ReplayBuffer<FrameEvent> buffer = subnetEventBuffers.get(svcContainer);
			if (buffer == null)
				return;
			final int[] portRange = ((DefaultServiceContainer) svcContainer).disruptionBufferPortRange();
			final InetSocketAddress remote = connection.getRemoteAddress();
			// unix domain sockets are not applicable for our replay buffer
			if (remote == null)
				return;
			final int port = remote.getPort();
			if (port >= portRange[0] && port <= portRange[1]) {
				buffer.add(connection);
				if (buffer.isDisrupted(connection)) {
					waitingForReplay.put(endpoint, svcContainer);
					synchronized (KnxServerGateway.this) {
						KnxServerGateway.this.notify();
					}
				}
			}
		}

		@Override
		public void onPropertyValueChanged(final PropertyEvent pe) {}

		@Override
		public void onServiceContainerChange(final ServiceContainerEvent sce)
		{
			final int event = sce.getEventType();
			final ServiceContainer sc = sce.getContainer();
			if (event == ServiceContainerEvent.ROUTING_SVC_STARTED) {
				final KNXnetIPConnection conn = sce.getConnection();
				conn.addConnectionListener(new ConnectionListener(sc, conn.name()));
				serverConnections.add((KnxipQueuingEndpoint) conn);
			}
			else if (event == ServiceContainerEvent.REMOVED_FROM_SERVER) {
				for (final Iterator<SubnetConnector> i = connectors.iterator(); i.hasNext();) {
					final SubnetConnector b = i.next();
					if (b.getServiceContainer() == sc) {
						i.remove();
						closeLink(b.getSubnetLink());
						break;
					}
				}
			}
		}

		@Override
		public void onResetRequest(final ShutdownEvent se) {}

		@Override
		public void onShutdown(final ShutdownEvent se)
		{
			if (inReset) {
				inReset = false;
				return;
			}
			final int i = se.getInitiator();
			final String s = i == CloseEvent.USER_REQUEST ? "user" : i == CloseEvent.CLIENT_REQUEST
					? "client" : "server internal";
			logger.log(INFO, server.getName() + ": " + s + " request for shutdown");
			quit();
		}

		private void closeLink(final AutoCloseable link)
		{
			try {
				if (link == null)
					return;
				link.close();
				// give slow interfaces some time to settle down
				Thread.sleep(700);
			}
			catch (final InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			catch (final Exception bogus) {}
		}
	}

	final class SubnetListener implements NetworkLinkListener
	{
		private final SubnetConnector subnet;

		SubnetListener(final SubnetConnector subnet) { this.subnet = subnet; }

		@Override
		public void confirmation(final FrameEvent e) {
			subnetConnected(true);
		}

		@Override
		public void indication(final FrameEvent e)
		{
			subnetConnected(true);
			if (!subnetEvents.offer(new FrameEvent(subnet, e.getFrame())))
				incMsgQueueOverflow(false);
		}

		@LinkEvent
		void baosService(final BaosService svc) {
			if (!subnetEvents.offer(new FrameEvent(subnet, svc.toByteArray())))
				incMsgQueueOverflow(false);
		}

		@Override
		public void linkClosed(final CloseEvent e)
		{
			subnetConnected(false);
			logger.log(INFO, "KNX subnet link closed (" + e.getReason() + ")");
		}

		// connection status notification of the link (closed/open)
		void connectionStatus(final boolean connected) {
			final var sc = subnet.getServiceContainer();
			final byte[] data = bytesFromWord(sc.getMediumSettings().maxApduLength());
			final int pidMaxRoutingApduLength = 58;
			setProperty(ROUTER_OBJECT, objectInstance(subnet), pidMaxRoutingApduLength, data);
			if (subnet == connectors.get(0)) {
				setProperty(DEVICE_OBJECT, 1, PID.MAX_APDULENGTH, data);
				final int pidMaxInterfaceApduLength = 68;
				setProperty(InterfaceObject.CEMI_SERVER_OBJECT, 1, pidMaxInterfaceApduLength, data);
			}

			logger.log(DEBUG, "set maximum APDU length of ''{0}'' to {1}", sc.getName(), sc.getMediumSettings().maxApduLength());

			subnetConnected(connected);
		}

		private void subnetConnected(final boolean connected) {
			setNetworkState(objectInstance(subnet), true, !connected);
		}

		// connection status for serial connections (knx network offline/online)
		@LinkEvent
		void connectionStatus(final ConnectionStatus status) {
			logger.log(INFO, "KNX connection {0}", status);
			switch (status) {
				case Offline -> subnetConnected(false);
				case Online -> subnetConnected(true);
			}
		}
	}

	private final String name;
	private final Logger logger;

	private final KNXnetIPServer server;
	// connectors array is not sync'd throughout gateway
	private final List<SubnetConnector> connectors = new ArrayList<>();
	private final List<KnxipQueuingEndpoint> serverConnections = new CopyOnWriteArrayList<>();

	record IpEvent(ServiceContainer sc, FrameEvent event) {}
	private final int maxEventQueueSize = 250;
	private final BlockingQueue<IpEvent> ipEvents = new ArrayBlockingQueue<>(maxEventQueueSize);
	private final BlockingQueue<FrameEvent> subnetEvents = new ArrayBlockingQueue<>(maxEventQueueSize);

	private static final FrameEvent ResetEvent = new FrameEvent(KnxServerGateway.class, new byte[0]);

	// support replaying subnet events for disrupted tunneling connections
	// TODO move to subnet connector?
	private final Map<ServiceContainer, ReplayBuffer<FrameEvent>> subnetEventBuffers = new ConcurrentHashMap<>();
	private final Map<KnxipQueuingEndpoint, ServiceContainer> waitingForReplay = new ConcurrentHashMap<>();

	private final Instant startTime;

	private volatile boolean trucking;
	private volatile boolean inReset;

	private static final Duration sendRateHistory = Duration.ofMinutes(10);
	private final List<SlidingTimeWindowCounter> telegramsToKnx = new ArrayList<>();
	private final List<SlidingTimeWindowCounter> telegramsFromKnx = new ArrayList<>();

	// we deny clients direct property r/w access to function properties
	private final Set<PropertyKey> functionProperties = new HashSet<>();

	// Frame forwarding based on KNX address (AN031)
	// KNX properties to determine address routing and address filtering:
	// properties for individual address forwarding
//	private static final int MAIN_LCCONFIG = 52;
//	private static final int SUB_LCCONFIG = 53;
	// properties for group address forwarding
	// MAIN_LCGRPCONFIG/SUB_LCGRPCONFIG bits:
	// Bits 0-1: address handling for addresses <= 0x6fff
	// Bits 2-3: address handling for addresses >= 0x7000
	// Values:
	// 0 = not used, 1 = route all frames (repeater) (default for addresses >= 0x7000),
	// 2 = block all, 3 = use filter table (default for addresses <= 0x6fff)


	private final Runnable dispatcher = new Runnable() {
		// threshold for multicasting routing busy msg is 10 incoming routing indications
		private static final int routingBusyMsgThreshold = 10;
		private int ipMsgCount;

		@Override
		public void run()
		{
			try {
				while (trucking) {
					final var ipEvent = ipEvents.take();
					try {
						if (!ipEvent.event().systemBroadcast())
							checkRoutingBusy();
						onServerFrameReceived(ipEvent);
					}
					catch (final RuntimeException e) {
						logger.log(ERROR, "on server-side frame event", e);
					}
				}
			}
			catch (final InterruptedException e) {}
		}

		private void checkRoutingBusy()
		{
			final var subnet = connectors.get(0);
			final var settings = subnet.getServiceContainer().getMediumSettings();
			final int medium = settings.getMedium();

			final int maxMsgsPerSecond = switch (medium) {
				case KNXMediumSettings.MEDIUM_TP1 -> 50;
				case KNXMediumSettings.MEDIUM_PL110 -> 6;
				case KNXMediumSettings.MEDIUM_RF -> 50;
				case KNXMediumSettings.MEDIUM_KNXIP -> 50;
				default -> throw new KnxRuntimeException("unsupported KNX medium");
			};

			ipMsgCount++;
			final int msgs = ipEvents.size();
			final Duration observationPeriod = Duration.ofMillis(500);
			final double seconds = ((double) observationPeriod.toMillis()) / 1000;
			final int msgsPerPeriod = (int) (maxMsgsPerSecond * seconds);
			if (msgs >= msgsPerPeriod)
				sendRoutingBusy();
		}

		private void sendRoutingBusy()
		{
			if (ipMsgCount < routingBusyMsgThreshold)
				return;
			ipMsgCount = 0;
			serverConnections.stream().filter(KNXnetIPRouting.class::isInstance)
					.forEach(c -> c.enqueue(() -> sendRoutingBusy((KNXnetIPRouting) c)));
		}

		private void sendRoutingBusy(final KNXnetIPRouting connection)
		{
			final int deviceState = getPropertyOrDefault(KNXNETIP_PARAMETER_OBJECT, objectInstance,
					PID.KNXNETIP_DEVICE_STATE, 0);
			final int waitTime = getPropertyOrDefault(KNXNETIP_PARAMETER_OBJECT, objectInstance,
					PID.ROUTING_BUSY_WAIT_TIME, 100);
			final RoutingBusy msg = new RoutingBusy(deviceState, Duration.ofMillis(waitTime), 0);
			try {
				connection.send(msg);
			}
			catch (final KNXConnectionClosedException e) {
				logger.log(WARNING, "trying to send routing busy message on closed " + connection, e);
			}
		}
	};

	private final List<NetworkLinkListener> deviceListeners = new ArrayList<>();


	private final class LinkAdapter implements KNXNetworkLink {
		@Override
		public void addLinkListener(final NetworkLinkListener l) { deviceListeners.add(l); }

		@Override
		public void removeLinkListener(final NetworkLinkListener l) { deviceListeners.remove(l); }

		@Override
		public void sendRequest(final KNXAddress dst, final Priority p, final byte... nsdu) {
			sendRequestWait(dst, p, nsdu);
		}

		@Override
		public void sendRequestWait(final KNXAddress dst, final Priority p, final byte... nsdu) {

			final boolean ldm = dst != null && dst.equals(new IndividualAddress(0));
			if (ldm) {
				for (final var c : serverConnections) {
					// device mgmt endpoints don't have a device address assigned
					if (c instanceof DataEndpoint && ((DataEndpoint) c).deviceAddress() == null) {
//						final var deviceMgmtEndpoint = (DataEndpoint) c;
						// NYI send cEMI T-Data
					}
				}
			}
			else {
				final var self = connectors.get(0).getServiceContainer().getMediumSettings().getDeviceAddress();
				final boolean sysBcast = dst == null;
				final CEMILData msg;
				if (sysBcast) {
					msg = new CEMILDataEx(CEMILData.MC_LDATA_IND, self, GroupAddress.Broadcast, nsdu, p);
					((CEMILDataEx) msg).setBroadcast(false);
				}
				else
					msg = nsdu.length > 16 ? new CEMILDataEx(CEMILData.MC_LDATA_IND, self, dst, nsdu, p)
							: new CEMILData(CEMILData.MC_LDATA_IND, self, dst, nsdu, p);
				send(msg, false);
			}
		}

		@Override
		public void send(final CEMILData msg, final boolean waitForCon) {
			// TODO support > 1 service containers
			final SubnetConnector connector = connectors.get(0);
			final long eventId = connector.lastEventId + 1; // required for fake busmonitor sequence number
			dispatchToServer(connector, msg, eventId, FramePath.LocalToClient);
		}

		@Override
		public String getName() { return name; }

		@Override
		public void setKNXMedium(final KNXMediumSettings settings) {}

		@Override
		public KNXMediumSettings getKNXMedium() { return new KnxIPSettings(server.device().getAddress()); }

		@Override
		public void setHopCount(final int count) {}

		@Override
		public int getHopCount() { return 6; }

		@Override
		public boolean isOpen() { return true; }

		@Override
		public void close() {}
	}


	/**
	 * Creates a new server gateway for the supplied KNXnet/IP server.
	 * On running this gateway ({@link #run()}), it is ensured the KNXnet/IP server is launched.
	 *
	 * @param s KNXnet/IP server representing the server side
	 * @param config server configuration
	 */
	public KnxServerGateway(final KNXnetIPServer s, final ServerConfiguration config) {
		this(config.name(), s, config.containers().stream().map(c -> c.subnetConnector()).toList());
		for (final var c : config.containers()) {
			setupTimeServer(c.subnetConnector(), c.timeServerDatapoints());
		}

		try {
			server.device().setDeviceLink(new LinkAdapter());

			// setting the device link also sets the medium of our link proxy (KNX IP), so restore the correct
			// value of the first service container
			final var serviceContainer = config.containers().get(0).subnetConnector().getServiceContainer();
			final int medium = serviceContainer.getMediumSettings().getMedium();
			server.getInterfaceObjectServer().setProperty(InterfaceObject.CEMI_SERVER_OBJECT, objectInstance,
					PID.MEDIUM_TYPE, 1, 1, (byte) 0, (byte) medium);
		}
		catch (final KNXLinkClosedException e) {
			throw new KnxRuntimeException("setting device link", e);
		}
	}

	private KnxServerGateway(final String gatewayName, final KNXnetIPServer s, final List<SubnetConnector> subnetConnectors) {
		name = gatewayName;
		server = s;
		server.addServerListener(new KNXnetIPServerListener());
		logger = LogService.getLogger("io.calimero.server.gateway." + name);
		connectors.addAll(subnetConnectors);
		startTime = Instant.now().truncatedTo(ChronoUnit.SECONDS);

		final var ios = server.getInterfaceObjectServer();
		for (final var entry : ios.propertyDefinitions().entrySet()) {
			if (entry.getValue().pdt() == PropertyTypes.PDT_FUNCTION)
				functionProperties.add(entry.getKey());
		}

		int objinst = 0;
		for (final SubnetConnector connector : connectors) {
			objinst++;

			connector.setSubnetListener(new SubnetListener(connector));

			final ServiceContainer sc = connector.getServiceContainer();
			final Duration timeout = ((DefaultServiceContainer) sc).disruptionBufferTimeout();
			if (!timeout.isZero()) {
				final int[] portRange = ((DefaultServiceContainer) sc).disruptionBufferPortRange();
				logger.log(INFO, "activate ''{0}'' disruption buffer on ports [{1}-{2}], disruption timeout {3} s", sc.getName(),
						portRange[0], portRange[1], timeout.getSeconds());
				subnetEventBuffers.put(sc, new ReplayBuffer<>(timeout));
			}

			ios.setProperty(ROUTER_OBJECT, objinst, pidIpSbcControl, 1, 1, (byte) 0);
			// init PID.PRIORITY_FIFO_ENABLED property to non-fifo message queue
			ios.setProperty(KNXNETIP_PARAMETER_OBJECT, objinst, PID.PRIORITY_FIFO_ENABLED, 1, 1, (byte) 0);

			// init capability list of different routing features
			// bit field: bit 0: Queue overflow counter available
			// 1: Transmitted message counter available
			// 2: Support of priority/FIFO message queues
			// 3: Multiple KNX installations supported
			// 4: Group address mapping supported
			// other bits reserved
			final byte caps = 1 << 0 | 1 << 1 | 1 << 3;
			ios.setProperty(KNXNETIP_PARAMETER_OBJECT, objinst, PID.KNXNETIP_ROUTING_CAPABILITIES, 1, 1, caps);

			telegramsToKnx.add(
					new SlidingTimeWindowCounter(connector.getName() + " to KNX", sendRateHistory, ChronoUnit.MINUTES));
			telegramsFromKnx.add(
					new SlidingTimeWindowCounter(connector.getName() + " to IP", sendRateHistory, ChronoUnit.MINUTES));
		}
	}

	@Override
	public void run()
	{
		launchServer();

		for (final var connector : connectors) {
			if (connector.getServiceContainer().isActivated())
				try {
					connector.openNetworkLink();
					// we immediately set a virtual network to connected, so that there is no
					// initial state "knx bus not connected" in a server discovery
					if (connector.interfaceType() == InterfaceType.Virtual)
						setNetworkState(1, true, false);
				}
				catch (KNXException | RuntimeException e) {
					logger.log(ERROR, "error opening network link for " + connector.getName(), e);
					server.shutdown();
					return;
				}
				catch (final InterruptedException e) {
					server.shutdown();
					Thread.currentThread().interrupt();
					return;
				}
		}

		trucking = true;
		final var dispatcherThread = Executor.execute(dispatcher, name + " subnet dispatcher");
		while (trucking) {
			try {
				// although we possibly run in a dedicated thread so to not delay any
				// other user tasks, be aware that subnet frame dispatching to IP
				// front-end is done in this thread
				final FrameEvent event = subnetEvents.take();
				// If we received a reset.req message in the message handler, the resetEvent marker gets added
				if (event == ResetEvent) {
					// Check trucking, since someone might have called quit during server shutdown
					if (trucking)
						launchServer();
				}
				else {
					replayPendingSubnetEvents();
					onSubnetFrameReceived(event);
				}
			}
			catch (final RuntimeException e) {
				logger.log(ERROR, "on dispatching KNX message", e);
			}
			catch (final InterruptedException e) {
				quit();
				Thread.currentThread().interrupt();
			}
		}

		dispatcherThread.interrupt();
	}

	/**
	 * Quits the gateway, and stops a running KNXnet/IP server.
	 */
	public void quit()
	{
		if (!trucking)
			return;
		trucking = false;
		subnetEvents.offer(ResetEvent);
		server.shutdown();
		CemiFrameTracer.instance().close();
	}

	/**
	 * Returns the name of this server gateway.
	 *
	 * @return the gateway name as string
	 */
	public String getName()
	{
		return name;
	}

	/**
	 * {@return the KNXnet/IP server used by this gateway}
	 */
	public final KNXnetIPServer getServer()
	{
		return server;
	}

	/**
	 * {@return the list of subnet connectors currently maintained by the gateway}
	 */
	public final List<SubnetConnector> getSubnetConnectors()
	{
		return List.copyOf(connectors);
	}

	private void setupTimeServer(final SubnetConnector connector, final List<StateDP> datapoints) {
		for (final var datapoint : datapoints) {
			final var security = Security.defaultInstallation().groupKeys().containsKey(datapoint.getMainAddress())
					? DataSecurity.AuthConf : DataSecurity.None;
			((BaseKnxDevice) server.device()).addGroupObject(datapoint, security, false);
			if (security != DataSecurity.None)
				server.getInterfaceObjectServer().setProperty(InterfaceObject.SECURITY_OBJECT, 1, 51, 1, 1, (byte) 1);

			final var dpt = datapoint.getDPT();
			final var dst = datapoint.getMainAddress();
			final int sendInterval = datapoint.getExpirationTimeout();
			logger.log(DEBUG, "setup time server for {0}: publish ''{1}'' ({2}) to {3} every {4} seconds", connector.getName(),
					datapoint.getName(), dpt, dst, sendInterval);
			try {
				final var xlator = TranslatorTypes.createTranslator(dpt);

				Executor.scheduledExecutor().scheduleWithFixedDelay(
						() -> transmitCurrentTime(connector, xlator, dst, datapoint.getPriority()),
						5, sendInterval, TimeUnit.SECONDS);
			}
			catch (final KNXException e) {
				throw new KnxRuntimeException("time server DPT setup", e);
			}
		}
	}

	private void transmitCurrentTime(final SubnetConnector connector, final DPTXlator xlator, final GroupAddress dst,
			final Priority p) {
		Thread.currentThread().setName("Calimero time server");
		final ServiceContainer sc = connector.getServiceContainer();
		final var src = sc.getMediumSettings().getDeviceAddress();
		try {
			// dispatch to subnet
			try {
				final var apdu = prepareTimestamp(xlator, src, dst);
				final var ldata = new CEMILDataEx(CEMILData.MC_LDATA_REQ, src, dst, apdu, p);
				dispatchToSubnet(connector, ldata, false, FramePath.LocalToSubnet);
			}
			catch (final RuntimeException e) {
				logger.log(WARNING, MessageFormat.format("time server error {0} {1}", dst, xlator), e);
			}

			// dispatch to server-side clients
			try {
				logger.log(DEBUG, "dispatch {0}->{1} to all server-side connections", src, dst);
				final long eventId = new FrameEvent(this, (CEMI) null).id();
				final var apdu = prepareTimestamp(xlator, src, dst);

				for (final var conn : serverConnections) {
					boolean monitor = false;
					if (conn instanceof final DataEndpoint de) {
						if (de.type() == ConnectionType.DevMgmt)
							continue;
						// if we have a bus monitoring connection, but a subnet connector does not support busmonitor mode,
						// we serve that connection by converting cEMI L-Data -> cEMI BusMon
						monitor = de.type() == ConnectionType.Monitor;
					}

					final var f = new CEMILDataEx(CEMILData.MC_LDATA_IND, src, dst, apdu, p);
					// if we have a bus monitoring connection, but a subnet connector does not support busmonitor mode,
					// we serve that connection by converting cEMI L-Data -> cEMI BusMon
					final CEMI send = monitor ? convertToBusmon(f, eventId, connector) : f;
					asyncSend(sc, conn, send, FramePath.LocalToClient);
				}
			}
			catch (final RuntimeException e) {
				logger.log(WARNING, MessageFormat.format("time server error {0} {1}", dst, xlator), e);
			}
		}
		catch (final InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	private byte[] prepareTimestamp(final DPTXlator xlator, final IndividualAddress src,
									final GroupAddress dst) throws InterruptedException {
		final long millis = System.currentTimeMillis();

		if (xlator instanceof final DPTXlatorDate date)
			date.setValue(millis);
		else if (xlator instanceof final DPTXlatorTime time)
			time.setValue(millis);
		else if (xlator instanceof final DPTXlatorDateTime dateTime) {
			dateTime.setValue(millis);
			dateTime.setClockSync(true);
		}
		final var plainApdu = DataUnitBuilder.createAPDU(0x80, xlator.getData());
		final var sal = ((BaseKnxDevice) server.device()).secureApplicationLayer();
		// this might incur some time overhead that will outdate the timestamp
		return sal.secureGroupObject(src, dst, plainApdu).orElse(plainApdu);
	}

	@Override
	public String toString() {
		return friendlyName() + " -- " + stat();
	}

	private String stat() {
		final StringBuilder info = new StringBuilder();
		final var uptime = Duration.between(startTime, Instant.now()).truncatedTo(ChronoUnit.SECONDS);
		final var days = uptime.toDays();
		final var dayPart = days > 1 ? days + " days " : days == 1 ? "1 day " : "";
		final var dtFormatter = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.LONG).withZone(ZoneId.systemDefault());

		info.append(format("start time %s (uptime %s%02d:%02d)%n", dtFormatter.format(startTime), dayPart,
				uptime.toHoursPart(), uptime.toMinutesPart()));

		int objInst = 0;

		info.append(format("used msg buffer:%n"));
		info.append(format("    IP => KNX: %d/%d (%d %%)%n", ipEvents.size(), maxEventQueueSize,
				ipEvents.size() * 100 / maxEventQueueSize));
		info.append(format("    KNX => IP: %d/%d (%d %%)%n", subnetEvents.size(), maxEventQueueSize,
				subnetEvents.size() * 100 / maxEventQueueSize));

		for (final SubnetConnector c : getSubnetConnectors()) {
			objInst++;
			info.append(format("service container '%s':%n", c.getName()));
			final InterfaceObjectServer ios = server.getInterfaceObjectServer();
			try {
				final var knxipObject = KnxipParameterObject.lookup(ios, objInst);

				final InetAddress ip = knxipObject.inetAddress(PID.CURRENT_IP_ADDRESS);
				final InetAddress mask = knxipObject.inetAddress(PID.CURRENT_SUBNET_MASK);
				info.append(format("    server IP: %s (subnet %s) netif %s%n", ip.getHostAddress(), mask.getHostAddress(),
						NetworkInterface.getByInetAddress(ip).getName()));

				if (c.getServiceContainer() instanceof final RoutingServiceContainer rsc) {
					info.append(format("     IP mcast: %s netif %s%n",
							rsc.routingMulticastAddress().getHostAddress(), rsc.networkInterface()));
				}

				info.append(format("       subnet: %s%n", c.getSubnetLink()));

				final long toKnx = property(KNXNETIP_PARAMETER_OBJECT, objInst, PID.MSG_TRANSMIT_TO_KNX).orElse(0L);
				final long overflowKnx = property(KNXNETIP_PARAMETER_OBJECT, objInst, PID.QUEUE_OVERFLOW_TO_KNX).orElse(0L);
				final int rateToKnx = telegramsToKnx.get(objInst - 1).average();
				info.append(format("    IP => KNX: sent %d, overflow %d [msgs], %d [msgs/min]%n", toKnx, overflowKnx, rateToKnx));
				final long toIP = property(KNXNETIP_PARAMETER_OBJECT, objInst, PID.MSG_TRANSMIT_TO_IP).orElse(0L);
				final long overflowIP = property(KNXNETIP_PARAMETER_OBJECT, objInst, PID.QUEUE_OVERFLOW_TO_IP).orElse(0L);
				final int rateToIP = telegramsFromKnx.get(objInst - 1).average();
				info.append(format("    KNX => IP: sent %d, overflow %d [msgs], %d [msgs/min]%n", toIP, overflowIP, rateToIP));

				final var connections = server.dataConnections(c.getServiceContainer());
				if (!connections.isEmpty())
					info.append("  active client connections:\n");
				connections.forEach((addr, client) -> info.append(format("    %s, connected since %s%n",
						client, dtFormatter.format(client.connectedSince()))));
			}
			catch (final Exception e) {
				logger.log(ERROR, "gathering stat for service container {0}", c.getName(), e);
			}
		}
		return info.toString();
	}

	private void replayPendingSubnetEvents()
	{
		for (final var entry : waitingForReplay.entrySet()) {
			final var endpoint = entry.getKey();
			final ServiceContainer svcContainer = entry.getValue();
			final ReplayBuffer<FrameEvent> replayBuffer = subnetEventBuffers.get(svcContainer);
			final Collection<FrameEvent> events = replayBuffer.replay(endpoint);

			endpoint.enqueue(() -> {
				logger.log(WARNING, "previous connection of {0} got disrupted => replay {1} pending messages", endpoint,
						events.size());
				try {
					final String hostPort = hostPort(endpoint.getRemoteAddress());
					for (final var fe : events) {
						logger.log(TRACE, "replay {0}: {1}", hostPort, fe.getFrame());
						send(svcContainer, endpoint, fe.getFrame(), FramePath.LocalToClient);
					}
				}
				catch (final InterruptedException e) {
					logger.log(WARNING, "interrupted replay for " + endpoint, e);
				}
				waitingForReplay.remove(endpoint);
				logger.log(DEBUG, "replay completed for connection {0}", endpoint);
			});
		}
	}

	static String hostPort(final InetSocketAddress addr) {
		return addr.getAddress().getHostAddress() + ":" + addr.getPort();
	}

	private void launchServer()
	{
		try {
			server.launch();
		}
		catch (final RuntimeException e) {
			logger.log(ERROR, "cannot launch " + friendlyName(), e);
			quit();
			throw e;
		}
	}

	private String friendlyName() {
		try {
			final var knxipObject = KnxipParameterObject.lookup(server.getInterfaceObjectServer(), 1);
			return knxipObject.friendlyName();
		}
		catch (final KnxPropertyException e) {
			return name;
		}
	}

	private void recordEvent(final SubnetConnector connector, final FrameEvent fe)
	{
		final ReplayBuffer<FrameEvent> buffer = subnetEventBuffers.get(connector.getServiceContainer());
		if (buffer != null)
			buffer.recordEvent(fe);
	}

	private void onServerFrameReceived(final IpEvent ipEvent) throws InterruptedException {
		final String s = "server-side";
		final var fe = ipEvent.event();
		final CEMI frame = fe.getFrame();

		if (frame == null) {
			checkBaosService(fe);
			return;
		}

		final ServiceContainer svcCont = ipEvent.sc();
		final int objinst = objectInstance(svcCont);
		final RouterObject routerObj = RouterObject.lookup(server.getInterfaceObjectServer(), objinst);

		final int mc = frame.getMessageCode();
		if (frame instanceof final CEMILData ldata) {
			final var dst = ldata.getDestination();
			logger.log(TRACE, "{0} {1}: {2}: {3}", s, fe.getSource(), frame, DataUnitBuilder.decode(ldata.getPayload(), dst));

			// we get L-data.ind if client uses routing protocol
			if (mc == CEMILData.MC_LDATA_REQ || mc == CEMILData.MC_LDATA_IND) {
				if (mc == CEMILData.MC_LDATA_REQ) {
					// send confirmation only for .req type
					sendConfirmationFor((KnxipQueuingEndpoint) fe.getSource(), ldata);

					// if routing is active, convert .req to .ind and dispatch over routing connection
					findRoutingConnection().ifPresent(c -> dispatch(c,
							() -> create(null, null, (CEMILData) create(CEMILData.MC_LDATA_IND, null, ldata), false, false),
							ind -> {
								logger.log(DEBUG, "dispatch {0}->{1} using {2}", ldata.getSource(), dst, c);
								send(svcCont, c, ind, FramePath.ClientToClient);
							}
					));
				}

				final var client = (KnxipQueuingEndpoint) fe.getSource();

				if (dst instanceof final IndividualAddress ia) {
					final Optional<SubnetConnector> connector = connectorFor(ia);
					if (connector.isPresent()) {
						if (localDeviceManagement(connector.get(), ldata))
							return;

						// see if the frame is addressed to us
						final IndividualAddress localInterface = connector.get().getServiceContainer()
								.getMediumSettings().getDeviceAddress();
						if (dst.equals(localInterface)) {
							deviceListeners.forEach(l -> l.indication(fe));
							return;
						}
					}

					final var routingConfig = routerObj.routingLcConfig(true);
					switch (routingConfig) {
						case All -> {
							dispatchLdataToClients(getSubnetConnector(svcCont.getName()), ldata, fe.id(), null, FramePath.ClientToClient);

							final CEMILData send = adjustHopCount(ldata);
							if (send == null)
								return;
							dispatchToSubnets(send, fe.systemBroadcast(), FramePath.ClientToSubnet);
						}
						case Block -> {
							logger.log(DEBUG, "no p2p frames shall be routed from {0} - discard {1}", svcCont.getName(), ldata);
							return;
						}
						case Route -> {
							// check if destination is a client of ours
							final var dataConnections = server.dataConnections(svcCont);
							for (final var dataEndpoint : dataConnections.values()) {
								if (dst.equals(dataEndpoint.deviceAddress())) {
									try {
										final var ind = create(null, null,
												(CEMILData) create(CEMILData.MC_LDATA_IND, null, ldata), false, false);
										asyncSend(svcCont, dataEndpoint, ind, FramePath.ClientToClient);
									}
									catch (KNXFormatException | RuntimeException e) {
										e.printStackTrace();
									}
									return;
								}
							}

							// defend our own unused additional individual addresses when receiving a TL connect.req
							if (DataUnitBuilder.getTPDUService(ldata.getPayload()) == 0x80) {
								final var addresses = additionalAddresses(objinst);
								if (addresses.contains(dst)) {
									// send disconnect
									try {
										final var disconnect = create(ia, ldata.getSource(), (CEMILData) create(CEMILData.MC_LDATA_IND, new byte[] { (byte) 0x81 }, ldata), false);
										logger.log(DEBUG, "defend own additional individual address {0}, dispatch {1}->{2} using {3}",
												dst, disconnect.getSource(), disconnect.getDestination(), client);
										asyncSend(svcCont, client, disconnect, FramePath.LocalToClient);
									}
									catch (final KNXFormatException e) {
										e.printStackTrace();
									}
									return;
								}
							}

							final CEMILData send = adjustHopCount(ldata);
							if (send == null)
								return;

							// if destination is the default individual address 0xffff (e.g., after a device reset)
							// we can't route, dispatch to all subnets
							if (dst.getRawAddress() == 0xffff) {
								logger.log(TRACE, "destination is default individual address 15.15.255, dispatch to all subnets");
								for (final var subnet : connectors) {
									if (subnet.getServiceContainer().isActivated() && isNetworkLink(subnet))
										send(subnet, send, FramePath.ClientToSubnet);
								}
								return;
							}

							connector.ifPresentOrElse(
									subnet -> dispatchToSubnet(subnet, send, fe.systemBroadcast(), FramePath.ClientToSubnet),
									() -> logger.log(DEBUG, "drop frame {0} (no matching KNX subnet) {1}", FramePath.ClientToSubnet, ldata));
						}
					}
				}
				else { // GroupAddress
					// broadcasts are of interest to us
					if (dst.equals(GroupAddress.Broadcast))
						deviceListeners.forEach(l -> l.indication(fe));

					// send to all clients except sender
					logger.log(TRACE, "forward {0} to all tunneling clients (except {1})", ldata, ldata.getSource());
					for (final var conn : serverConnections) {
						if (client == conn || conn instanceof final DataEndpoint de
								&& (de.type() == ConnectionType.DevMgmt || de.type() == ConnectionType.Monitor))
								continue;

						try {
							final var ind = create(null, null, (CEMILData) create(CEMILData.MC_LDATA_IND, null, ldata), false, false);
							asyncSend(svcCont, conn, ind, FramePath.ClientToClient);
						}
						catch (KNXFormatException | RuntimeException e) {
							e.printStackTrace();
						}
					}

					if (routeBasedOnGroupConfig(ldata, routerObj, true, svcCont.getName())) {
						final CEMILData send = adjustHopCount(ldata);
						if (send != null)
							dispatchToSubnets(send, fe.systemBroadcast(), FramePath.ClientToSubnet);
					}
				}
				return;
			}
		}
		else if (mc == CEMIDevMgmt.MC_PROPREAD_REQ || mc == CEMIDevMgmt.MC_PROPWRITE_REQ
				|| mc == CEMIDevMgmt.MC_RESET_REQ || mc == CEMIDevMgmt.MC_FUNCPROP_CMD_REQ
				|| mc == CEMIDevMgmt.MC_FUNCPROP_READ_REQ) {
			logger.log(TRACE, "{0} {1}: {2}", s, fe.getSource(), frame);
			CemiFrameTracer.instance().trace(frame, fe.getSource().toString(), null, FramePath.ClientToLocal);

			final var securityControl = fe.security().orElse(SecurityControl.Plain);
			doDeviceManagement((KnxipQueuingEndpoint) fe.getSource(), (CEMIDevMgmt) frame, securityControl);
			return;
		}

		logger.log(WARNING, "received {0} {1} - ignored", s, frame);
	}

	private void checkBaosService(final FrameEvent fe) {
		final var source = fe.getSource();
		if (!(source instanceof DataEndpoint && ((DataEndpoint) source).type() == ConnectionType.Baos))
			return;

		for (final var connector : connectors) {
			// we assume there is only one service container with baos support
			if ("baos".equals(connector.format())) {
				if (connector.getSubnetLink() instanceof final Link<?> subnetLink) {
					if (subnetLink.target() instanceof final BaosLink baosLink) {
						try {
							final var baosService = BaosService.from(ByteBuffer.wrap(fe.getFrameBytes()));
							logger.log(TRACE, "send baos {0}", baosService);
							baosLink.send(baosService);
						}
						catch (final KNXException e) {
							logger.log(WARNING, "forwarding client baos service", e);
						}
					}
				}
				return;
			}
		}
	}

	private void onSubnetFrameReceived(final FrameEvent fe) throws InterruptedException {
		final String s = "subnet";
		final SubnetConnector subnet = (SubnetConnector) fe.getSource();
		final CEMI frame = fe.getFrame();

		if (frame instanceof final CEMILData ldata) {
			logger.log(TRACE, "{0} {1}: {2}: {3}", s, subnet.getName(), frame,
					DataUnitBuilder.decode(ldata.getPayload(), ldata.getDestination()));

			if (frame.getMessageCode() == CEMILData.MC_LDATA_IND) {
				final var sc = subnet.getServiceContainer();

				final int objinst = objectInstance(subnet);
				final RouterObject routerObj = RouterObject.lookup(server.getInterfaceObjectServer(), objinst);

				if (ldata.getDestination() instanceof final IndividualAddress dst) {
					// check if frame is addressed to us
					final var containerAddr = sc.getMediumSettings().getDeviceAddress();
					if (ldata.getDestination().equals(containerAddr)) {
						// with an usb interface, device is always our own address, so we always exclude it for now
						if (subnet.interfaceType() == InterfaceType.Usb)
							logger.log(TRACE, "received from subnet using usb interface {0}, don''t intercept frame",
									subnet.getName());
						else if (subnet.interfaceAddress().isPresent())
							logger.log(TRACE, "received from subnet interface {0}, don''t intercept frame",
									subnet.getName());
						else {
							deviceListeners.forEach(l -> l.indication(fe));
							return;
						}
					}

					final CEMILData send = adjustHopCount(ldata);
					if (send == null)
						return;

					final var config = routerObj.routingLcConfig(false);
					switch (config) {
						case All -> {
							dispatchLdataToClients(subnet, send, fe.id(), null, FramePath.SubnetToClient);
							dispatchToOtherSubnets(send, subnet, false, FramePath.SubnetToSubnet);
						}
						case Block -> {
							logger.log(DEBUG, "no p2p frames shall be routed from subnet {0} - discard {1}",
									subnet.getName(), ldata);
							return;
						}
						case Route -> {
							dispatchToServer(subnet, send, 0, FramePath.SubnetToClient);
							// route to other subnet if indicated by destination
							final var otherSubnet = connectorFor(dst);
							if (otherSubnet.isPresent()) {
								final var os = otherSubnet.get();
								// only forward if dst is actually in a different subnet (never feed back into originating subnet)
								if (!os.equals(subnet))
									dispatchToSubnet(os, send, fe.systemBroadcast(), FramePath.SubnetToSubnet);
							}
							else
								logger.log(TRACE, "no subnet for {0}->{1} (received {2})",
										send.getSource(), send.getDestination(),
										DataUnitBuilder.decode(send.getPayload(), send.getDestination()));
						}
					}
				}
				else { // GroupAddress
					if (!routeBasedOnGroupConfig(ldata, routerObj, false, subnet.getName()))
						return;

					final CEMILData send = adjustHopCount(ldata);
					if (send == null)
						return;

					final var routing = findRoutingConnection();
					if (routing.isPresent() && isSubnetBroadcast(objinst, ldata)) {
						logger.log(INFO, "forward as IP system broadcast {0}", ldata);
						final CEMILData bcast;
						if (ldata instanceof final CEMILDataEx ex) {
							ex.setBroadcast(false);
							bcast = ex;
						}
						else {
							bcast = new CEMILDataEx(send.getMessageCode(), send.getSource(), send.getDestination(),
									send.getPayload(), send.getPriority(), send.isRepetition(), false, send.isAckRequested(),
									send.getHopCount());
						}

						broadcastOnEachRoutingNetif(sc, bcast, FramePath.SubnetToClient);
						return;
					}

					recordEvent(subnet, fe);
					dispatchLdataToClients(subnet, send, fe.id(), fe, FramePath.SubnetToClient);
					dispatchToOtherSubnets(send, subnet, false, FramePath.SubnetToSubnet);
				}
				return;
			}
		}
		else if (frame instanceof CEMIBusMon) {
			logger.log(TRACE, "{0} {1}: {2}", s, subnet.getName(), frame);
			recordEvent(subnet, fe);

			for (final var conn : serverConnections) {
				// routing does not support busmonitor mode
				if (!(conn instanceof KNXnetIPRouting))
					asyncSend(subnet.getServiceContainer(), conn, frame, fe, FramePath.SubnetToClient);
			}
			return;
		}

		if (frame == null) {
			if ("baos".equals(subnet.format())) {
				try {
					final var svc = BaosService.from(ByteBuffer.wrap(fe.getFrameBytes()));
					final var serviceContainer = subnet.getServiceContainer();

					final var connections = server.dataConnections(serviceContainer);
					for (final var c : connections.values()) {
						if (c.type() == ConnectionType.Baos) {
							logger.log(TRACE, "{0}: send baos {1}", c, svc);
							c.send(svc);
						}
					}

					final int oi = objectInstance(serviceContainer.getName());
					setNetworkState(oi, false, false);
					incMsgTransmitted(oi, false);
				}
				catch (final Exception e) {
					logger.log(WARNING, "forwarding baos service", e);
				}
				return;
			}
		}

		logger.log(WARNING, "received {0} {1} - ignored", s, frame);
	}

	private boolean routeBasedOnGroupConfig(final CEMILData ldata, final RouterObject routerObj, final boolean fromMain,
			final String name) {
		final GroupAddress dst = (GroupAddress) ldata.getDestination();
		final String net = fromMain ? "main line" : "subnet";
		if (dst.equals(GroupAddress.Broadcast)) {
			if (!routerObj.broadcastLcConfig(fromMain)) {
				logger.log(DEBUG, "no broadcast frames shall be routed from {0} {1} - discard {2}", net, name, ldata);
				return false;
			}
		}
		else {
			final var config = routerObj.routingLcGroupConfig(fromMain, dst);
			switch (config) {
				case All -> {} // nothing extra to do
				case Block -> {
					logger.log(DEBUG, "no group addressed frames shall be routed from {0} {1} - discard {2}",
							net, name, ldata);
					return false;
				}
				case Route -> {
					if (!inGroupFilterTable(routerObj, dst)) {
						logger.log(DEBUG, "destination {0} not set in {1} group filter - discard {2}", dst, name, ldata);
						return false;
					}
				}
			}
		}
		return true;
	}

	@FunctionalInterface
	private interface FrameSupplier {
		CEMI get() throws KNXException;
	}

	@FunctionalInterface
	private interface SendIt {
		void send(CEMI frame) throws KNXException, InterruptedException;
	}

	private void dispatch(final KnxipQueuingEndpoint endpoint, final FrameSupplier frameSupplier, final SendIt sender) {
		endpoint.enqueue(() -> {
			CEMI cemi = null;
			try {
				cemi = frameSupplier.get();
				sender.send(cemi);
			}
			catch (final KNXException e) {
				var detail = new StringJoiner(" ", " (", ")").setEmptyValue("");
				if (cemi != null) {
					detail.add(cemi.toString());
					if (cemi instanceof final CEMILData ldata)
						detail.add(DataUnitBuilder.decode(ldata.getPayload(), ldata.getDestination()));
				}
				logger.log(WARNING, "send failed on {0}: {1}{2}", endpoint, e.getMessage(), detail);
			}
			catch (final InterruptedException e) {
				logger.log(WARNING, "send interrupted on {0} ({1})", endpoint, cemi);
			}
		});
	}

	private void sendConfirmationFor(final KnxipQueuingEndpoint c, final CEMILData f) {
		// TODO check for reasons to send negative L-Data.con
		final boolean error = false;
		dispatch(c, () -> createCon(f.getPayload(), f, error), con -> {
			logger.log(TRACE, "send positive cEMI L_Data.con");
			c.send(con, WaitForAck);
		});
	}

	private static CEMI createCon(final byte[] data, final CEMILData original, final boolean error)
		throws KNXFormatException
	{
		if (original instanceof CEMILDataEx) {
			// since we don't use the error flag, simply always create positive .con using the cemi factory
			return create(CEMILData.MC_LDATA_CON, null, original);

//			final CEMILDataEx con = new CEMILDataEx(CEMILData.MC_LDATA_CON, original.getSource(),
//					original.getDestination(), data, original.getPriority(), error);
//			final List<AddInfo> l = ((CEMILDataEx) original).getAdditionalInfo();
//			for (final Iterator<AddInfo> i = l.iterator(); i.hasNext();) {
//				final CEMILDataEx.AddInfo info = i.next();
//				con.addAdditionalInfo(info.getType(), info.getInfo());
//			}
//			return con;
		}
		final var con = new CEMILDataEx(CEMILData.MC_LDATA_CON, original.getSource(),
				original.getDestination(), data, original.getPriority(), error);
		con.setHopCount(original.getHopCount());
		return con;
	}

	private SubnetConnector getSubnetConnector(final String containerName) {
		return connectors.stream().filter(c -> c.getServiceContainer().getName().equals(containerName))
				.findFirst()
				.orElseThrow(() -> new KnxRuntimeException("no subnet connector found for '" + containerName + "'"));
	}

	private void dispatchToOtherSubnets(final CEMILData ldata, final SubnetConnector exclude,
			final boolean systemBroadcast, final FramePath path) {
		for (final SubnetConnector subnet : connectors) {
			if (subnet.getServiceContainer().isActivated()) {
				if (subnet.equals(exclude))
					logger.log(TRACE, "dispatching to KNX subnets: exclude subnet " + exclude.getName());
				else
					dispatchToSubnet(subnet, ldata, systemBroadcast, path);
			}
		}
	}

	private void dispatchToSubnets(final CEMILData f, final boolean systemBroadcast, final FramePath path) {
		dispatchToOtherSubnets(f, null, systemBroadcast, path);
	}

	private void dispatchToSubnet(final SubnetConnector subnet, final CEMILData ldata, final boolean systemBroadcast,
			final FramePath path) {
		if (!isNetworkLink(subnet))
			return;
		if (systemBroadcast) {
			final int objinst = objectInstance(subnet);
			if (!isIpSystemBroadcast(objinst, ldata)) {
				logger.log(WARNING, "cEMI in IP system broadcast not qualified for subnet broadcast: {0}", ldata);
				return;
			}
			// std frames have the SB flag already removed when adjusting the hop count
			if (ldata instanceof final CEMILDataEx cemilDataEx) {
				cemilDataEx.setBroadcast(true);
			}
		}
		send(subnet, ldata, path);
	}

	// ensure we have a network link open (and no monitor link)
	private boolean isNetworkLink(final SubnetConnector subnet)
	{
		AutoCloseable link = subnet.getSubnetLink();
		if (link instanceof Link)
			link = ((Link<?>) link).target();
		if (!(link instanceof KNXNetworkLink)) {
			final IndividualAddress addr = subnet.getServiceContainer().getMediumSettings().getDeviceAddress();
			logger.log(WARNING, "cannot dispatch to KNX subnet {0}: {1}", addr, link == null ? "no subnet connection" : link);
			return false;
		}
		return true;
	}

	private static boolean matchesSubnet(final IndividualAddress addr, final IndividualAddress subnetMask)
	{
		if (subnetMask == null)
			return true;
		if (subnetMask.getArea() == addr.getArea()) {
			// if we represent an area coupler, line is 0
			return subnetMask.getLine() == 0 || subnetMask.getLine() == addr.getLine();
		}
		return false;
	}

	private void dispatchToServer(final SubnetConnector subnet, final CEMILData f, final long eventId, final FramePath path) {
		final ServiceContainer sc = subnet.getServiceContainer();
		try {
			final int objinst = objectInstance(subnet);
			if (f.getDestination() instanceof final IndividualAddress dst) {
				final IndividualAddress localInterface = sc.getMediumSettings().getDeviceAddress();

				final var connections = server.dataConnections(sc);
				// 1. look for client tunneling connection with matching assigned address
				KnxipQueuingEndpoint c = findConnection(dst);
				if (c != null) {
					logger.log(TRACE, "dispatch {0}->{1} using {2}", f.getSource(), dst, c);
					asyncSend(sc, c, f, path);
				}
				// 2. workaround for usb interfaces and interfaces with address override: allow assigning additional
				// addresses to client connections,
				// even though we always have the same destination (e.g., the address of the usb interface)
				else if (subnet.interfaceType() == InterfaceType.Usb
						&& dst.equals(localInterface) || subnet.interfaceAddress().isPresent()) {
					for (final var connection : connections.values()) {
						final IndividualAddress assignedAddress = connection.deviceAddress();
						// skip devmgmt connections
						if (assignedAddress != null) {
							logger.log(DEBUG, "dispatch {0}->{1} ({2}) using {3}", f.getSource(), assignedAddress,
									dst, connection);
							asyncSend(sc, connection, create(null, assignedAddress, f, false), path);
						}
					}
					// also dispatch via routing as-is
					c = findRoutingConnection().orElse(null);
					if (c != null) {
						logger.log(DEBUG, "dispatch {0}->{1} using {2}", f.getSource(), dst, c);
						asyncSend(sc, c, f, path);
					}
				}
				// 3. look for activated client-side routing
				else if ((c = findRoutingConnection().orElse(null)) != null) {
					logger.log(DEBUG, "dispatch {0}->{1} using {2}", f.getSource(), dst, c);
					asyncSend(sc, c, f, path);
				}
				else {
					logger.log(TRACE, "drop frame {0} (no matching KNXnet/IP connection) {1}", path, f);
				}
			}
			else {
				// group destination address
				final KNXnetIPConnection routing = findRoutingConnection().orElse(null);

				if (routing != null && isSubnetBroadcast(objinst, f)) {
					logger.log(INFO, "forward as IP system broadcast {0}", f);
					final CEMILData bcast;
					if (f instanceof CEMILDataEx) {
						((CEMILDataEx) f).setBroadcast(false);
						bcast = f;
					}
					else {
						bcast = new CEMILDataEx(f.getMessageCode(), f.getSource(), f.getDestination(),
								f.getPayload(), f.getPriority(), f.isRepetition(), false, f.isAckRequested(),
								f.getHopCount());
					}

					broadcastOnEachRoutingNetif(sc, bcast, path);
					return;
				}

				dispatchLdataToClients(subnet, f, eventId, null, path);
			}
		}
		catch (final KnxPropertyException e) {
			logger.log(ERROR, "send to server-side failed for " + f, e);
		}
	}

	private void broadcastOnEachRoutingNetif(final ServiceContainer sc, final CEMILData bcast, final FramePath path) {
		final var sentOnNetif = new HashSet<>();
		for (final var conn : serverConnections) {
			if (conn instanceof final KNXnetIPRouting rc) {
				if (sentOnNetif.add(rc.networkInterface()))
					asyncSend(sc, conn, bcast, path);
			}
		}
	}

	private void dispatchLdataToClients(final SubnetConnector subnet, final CEMILData f, final long eventId,
			final FrameEvent recordFrameEvent, final FramePath path) {
		logger.log(DEBUG, "dispatch {0}->{1} to all server-side connections", f.getSource(), f.getDestination());
		final ServiceContainer sc = subnet.getServiceContainer();
		for (final var conn : serverConnections) {
			CEMI send = f;
			if (conn instanceof final DataEndpoint de) {
				if (de.type() == ConnectionType.DevMgmt)
					continue;
				// if we have a bus monitoring connection, but a subnet connector does not support busmonitor mode,
				// we serve that connection by converting cEMI L-Data -> cEMI BusMon
				if (de.type() == ConnectionType.Monitor)
					send = convertToBusmon(f, eventId, subnet);
			}
			asyncSend(sc, conn, send, recordFrameEvent, path);
		}
	}

	private KnxipQueuingEndpoint findConnection(final IndividualAddress dst) {
		for (final ServiceContainer sc : server.getServiceContainers()) {
			if (matchesSubnet(dst, sc.getMediumSettings().getDeviceAddress())) {
				final var connections = server.dataConnections(sc);
				for (final var connection : connections.values())
					if (dst.equals(connection.deviceAddress()))
						return connection;
			}
		}
		return null;
	}

	private static final int DOA_WRITE = 0x3E0;
	private static final int DOA_READ = 0x3E1;
//	private static final int DOA_RESPONSE = 0x3E2;
	private static final int DOA_SELECTIVE_READ = 0x3E3;

	private static final int SystemNetworkParamRead = 0b0111001000;
	private static final int SystemNetworkParamResponse = 0b0111001001;
	private static final int SystemNetworkParamWrite = 0b0111001010;

	private static final int DomainAddressSerialNumberRead =  0b1111101100;
	private static final int DomainAddressSerialNumberWrite = 0b1111101110;

	private static final int pidIpSbcControl = 120;

	// checks if received subnet frame qualifies as IP system broadcast
	private boolean isSubnetBroadcast(final int objInstance, final CEMILData f) {
		if (f.getDestination().getRawAddress() != 0)
			return false;

		final int sbc = getPropertyOrDefault(InterfaceObject.ROUTER_OBJECT, objInstance, pidIpSbcControl, 0);
		if (sbc == 0)
			return false;

		return RoutingSystemBroadcast.isSubnetSystemBroadcast(f);
	}

	// checks if received server-side frame qualifies as subnet broadcast
	private boolean isIpSystemBroadcast(final int objInstance, final CEMILData f) {
		final int sbc = getPropertyOrDefault(InterfaceObject.ROUTER_OBJECT, objInstance, pidIpSbcControl, 0);
		// NYI if disabled, still check if sysbcast, and handle like IP device
		if (sbc == 0)
			return false;

		return RoutingSystemBroadcast.isIpSystemBroadcast(f);
	}

	private Optional<KnxipQueuingEndpoint> findRoutingConnection()
	{
		return serverConnections.stream().filter(KNXnetIPRouting.class::isInstance).findAny();
	}

	private void asyncSend(final ServiceContainer svcContainer, final KnxipQueuingEndpoint endpoint, final CEMI f,
			final FramePath path) {
		asyncSend(svcContainer, endpoint, f, null, path);
	}

	private void asyncSend(final ServiceContainer svcContainer, final KnxipQueuingEndpoint endpoint, final CEMI f,
			final FrameEvent recordFrameEvent, final FramePath path) {
		dispatch(endpoint, () -> f, frame -> {
			send(svcContainer, endpoint, frame, path);
			if (recordFrameEvent != null) {
				final ReplayBuffer<FrameEvent> buffer = subnetEventBuffers.get(svcContainer);
				if (buffer != null)
					buffer.completeEvent(endpoint, recordFrameEvent);
			}
		});
	}

	private void send(final ServiceContainer svcContainer, final KNXnetIPConnection c, final CEMI f,
			final FramePath path) throws InterruptedException {
		final int oi = objectInstance(svcContainer.getName());
		try {
			c.send(f, WaitForAck);
			CemiFrameTracer.instance().trace(f, c.name(), traceSubnetLink(svcContainer, path), path);
			setNetworkState(oi, false, false);
			incMsgTransmitted(oi, false);
		}
		catch (final KNXTimeoutException e) {
			logger.log(WARNING, "sending on {0} failed: {1} ({2})", c, e.getMessage(), f.toString());
			setNetworkState(oi, false, true);
		}
		catch (final KNXConnectionClosedException e) {
			logger.log(DEBUG, "sending on {0} failed: connection closed", c);
		}
	}

	private String traceSubnetLink(final ServiceContainer svcContainer, final FramePath path) {
		if (path != FramePath.SubnetToSubnet && path != FramePath.SubnetToClient)
			return "";
		final AutoCloseable ac = getSubnetConnector(svcContainer.getName()).getSubnetLink();
		if (ac instanceof final Link<?> link)
			return link.getName();
		if (ac instanceof final VirtualLink vLink)
			return vLink.getName();
		return ac.toString();
	}

	private void send(final SubnetConnector subnet, final CEMILData f, final FramePath path)
	{
		final KNXNetworkLink link = (KNXNetworkLink) subnet.getSubnetLink();
		final int oi = objectInstance(subnet);
		try {
			final CEMILData ldata;
			final int mc = f.getMessageCode();

			// we have to adjust a possible routing .ind from server-side to .req,
			// or vice versa a .req to .ind if we use KNXnet/IP routing on the KNX subnet
			// ??? HACK: do we use routing on the KNX subnet
			AutoCloseable subnetLink = link;
			if (subnetLink instanceof Link)
				subnetLink = ((Link<?>) subnetLink).target();
			final boolean routing = subnetLink instanceof KNXNetworkLinkIP && subnetLink.toString().contains("routing");
			final boolean usb = subnetLink instanceof KNXNetworkLinkUsb;
			IndividualAddress source = usb ? new IndividualAddress(0) : null;
			source = subnet.interfaceAddress().orElse(source);
			final boolean overrideSrcAddress = subnet.interfaceAddress().isPresent();

			// we can't forward secure services if we change the source address
			if (usb) {
				final var subnetAddress = subnet.getServiceContainer().getMediumSettings().getDeviceAddress();
				if (!f.getSource().equals(subnetAddress) && SecureApplicationLayer.isSecuredService(f)) {
					logger.log(WARNING, "{0}->{1} source address mismatch: cannot forward secure service to {2}", f.getSource(),
							f.getDestination(), subnet.getName());
					return;
				}
			}

			// adjust .ind: on every KNX subnet link (except routing links) we require an L-Data.req
			// also ensure repeat flag is set/cleared according to medium
			if (mc == CEMILData.MC_LDATA_IND && !routing)
				ldata = create(source, null, (CEMILData) create(CEMILData.MC_LDATA_REQ, null, f), false, true);
			// adjust .req: on KNX subnets with KNXnet/IP routing, we require an L-Data.ind
			else if (mc == CEMILData.MC_LDATA_REQ && routing)
				ldata = create(null, null, (CEMILData) create(CEMILData.MC_LDATA_IND, null, f), false, false);
			else if (usb || overrideSrcAddress)
				ldata = create(source, null, f, false);
			else
				ldata = f;

			var send = ldata;

			final int medium = subnet.getServiceContainer().getMediumSettings().getMedium();
			if (medium == KNXMediumSettings.MEDIUM_RF && f.getPayload().length > 1) {
				final byte[] tpdu = f.getPayload();
				final int svc = DataUnitBuilder.getAPDUService(tpdu);
				switch (svc) {
				case SystemNetworkParamRead:
				case SystemNetworkParamResponse:
				case SystemNetworkParamWrite:
				case DOA_WRITE:
				case DOA_READ:
				case DOA_SELECTIVE_READ:
				case DomainAddressSerialNumberRead:
				case DomainAddressSerialNumberWrite:
					if (!send.isSystemBroadcast()) {
						if (!(send instanceof CEMILDataEx))
							send = create(null, null, send, true);
						((CEMILDataEx) send).setBroadcast(false);
						logger.log(DEBUG, "{0} changed to system broadcast", DataUnitBuilder.decodeAPCI(svc));
					}
				}
			}

			logger.log(TRACE, "dispatch to subnet {0}: {1}", subnet.getName(), send);
			link.send(send, true);
			CemiFrameTracer.instance().trace(f, null, link.getName(), path);
			setNetworkState(oi, true, false);
			incMsgTransmitted(oi, true);
		}
		catch (final KNXTimeoutException e) {
			setNetworkState(oi, true, true);
			logger.log(WARNING, "timeout sending to {0}: {1}", f.getDestination(), e.getMessage());
		}
		catch (final KNXFormatException | KNXLinkClosedException e) {
			logger.log(ERROR, "error sending to {0} on subnet {1}: {2}", f.getDestination(), link.getName(), e.getMessage());
			if (e.getCause() != null)
				logger.log(DEBUG, e + ", caused by:", e.getCause());
		}
	}

	private OptionalLong property(final int objectType, final int objectInstance, final int propertyId) {
		final InterfaceObjectServer ios = server.getInterfaceObjectServer();
		try {
			return OptionalLong.of(toUnsignedInt(ios.getProperty(objectType, objectInstance, propertyId, 1, 1)));
		}
		catch (final KnxPropertyException e) {
			return OptionalLong.empty();
		}
	}

	private int getPropertyOrDefault(final int objectType, final int objectInstance, final int propertyId,
		final int defaultValue)
	{
		final InterfaceObjectServer ios = server.getInterfaceObjectServer();
		try {
			return (int) toUnsignedInt(ios.getProperty(objectType, objectInstance, propertyId, 1, 1));
		}
		catch (final KnxPropertyException e) {
			return defaultValue;
		}
	}

	private void setProperty(final int objectType, final int objectInstance, final int propertyId, final byte... data) {
		server.getInterfaceObjectServer().setProperty(objectType, objectInstance, propertyId, 1, 1, data);
	}

	// queries KNX group address filter, a message shall be routed if corresponding address bit is set
	private boolean inGroupFilterTable(final RouterObject routerObj, final GroupAddress addr) {
		try {
			// Filter table realisation type 3: memory location of table is stored in Router object PID_TABLE_REFERENCE
			final int tableLoc = (int) toUnsignedInt (routerObj.get(PID.TABLE_REFERENCE));

			// table size is 8192 bytes to fit all 1<<16 group addresses
			final int addrOffset = addr.getRawAddress() / 8;
			final int bitPos = addr.getRawAddress() % 8;
			final int bits = server.device().deviceMemory().get(tableLoc + addrOffset);
			return (bits & (1 << bitPos)) != 0;
		}
		catch (final KnxPropertyException e) {
			// when in doubt, pass the message on...
			return true;
		}
	}

	private List<IndividualAddress> additionalAddresses(final int objectInstance) {
		final var knxipObject = KnxipParameterObject.lookup(server.getInterfaceObjectServer(), objectInstance);
		return knxipObject.additionalAddresses();
	}

	private boolean checkPropertyAccess(final int objectType, final int objectInstance, final int pid,
			final boolean read, final SecurityControl securityCtrl) {
		final var ios = server.getInterfaceObjectServer();
		boolean securityMode = false;
		try {
			securityMode = ios.getProperty(SECURITY_OBJECT, 1, SecurityObject.Pid.SecurityMode, 1, 1)[0] == 1;
		}
		catch (final KnxPropertyException noSecurityObject) {}
		final boolean allowed = AccessPolicies.checkPropertyAccess(objectType, pid, read, securityMode, securityCtrl);
		if (!allowed)
			logger.log(INFO, "deny property {0} access to {1}({2})|{3} ({4}{5})", read ? "read" : "write", objectType,
					objectInstance, pid, PropertyClient.getObjectTypeName(objectType), propertyName(objectType, pid));
		return allowed;
	}

	private String propertyName(final int objectType, final int pid) {
		final var ios = server.getInterfaceObjectServer();
		final var key = pid <= 50 ? new PropertyKey(pid) : new PropertyKey(objectType, pid);
		final var property = ios.propertyDefinitions().get(key);
		if (property != null && !property.propertyName().isEmpty())
			return " - " + property.propertyName();
		return "";
	}

	private void doDeviceManagement(final KnxipQueuingEndpoint c, final CEMIDevMgmt f,
			final SecurityControl securityControl) {
		final int mc = f.getMessageCode();
		if (mc == CEMIDevMgmt.MC_PROPREAD_REQ || mc == CEMIDevMgmt.MC_PROPWRITE_REQ) {
			final boolean read = mc == CEMIDevMgmt.MC_PROPREAD_REQ;
			byte[] data = null;
			int elems = f.getElementCount();

			if (functionProperties.contains(new PropertyKey(f.getObjectType(), f.getPID()))) {
				data = new byte[] { CEMIDevMgmt.ErrorCodes.UNSPECIFIED_ERROR };
				elems = 0;
			}
			else {
				final var ios = server.getInterfaceObjectServer();
				try {
					// read property elements first so we know property exists
					ios.getProperty(f.getObjectType(), f.getObjectInstance(), f.getPID(), 0, 1);

					if (checkPropertyAccess(f.getObjectType(), f.getObjectInstance(), f.getPID(),
							mc == CEMIDevMgmt.MC_PROPREAD_REQ, securityControl)) {
						if (read)
							data = ios.getProperty(f.getObjectType(), f.getObjectInstance(), f.getPID(),
									f.getStartIndex(), elems);
						else
							ios.setProperty(f.getObjectType(), f.getObjectInstance(), f.getPID(), f.getStartIndex(),
									elems, f.getPayload());
					}
					else {
						data = new byte[] { (byte) CEMIDevMgmt.ErrorCodes.UNSPECIFIED_ERROR };
						elems = 0;
					}
				}
				catch (final KnxPropertyException e) {
					logger.log(DEBUG, e.getMessage());
					data = new byte[] { (byte) e.errorCode() };
					elems = 0;
				}
			}

			final int con = read ? CEMIDevMgmt.MC_PROPREAD_CON : CEMIDevMgmt.MC_PROPWRITE_CON;
			final CEMIDevMgmt dm = read || data != null
					? new CEMIDevMgmt(con, f.getObjectType(), f.getObjectInstance(), f.getPID(), f.getStartIndex(), elems, data)
					: new CEMIDevMgmt(con, f.getObjectType(), f.getObjectInstance(), f.getPID(), f.getStartIndex(), elems);
			dispatch(c, () -> dm, frame -> {
				c.send(frame, WaitForAck);
				CemiFrameTracer.instance().trace(frame, c.toString(), null, FramePath.LocalToClient);
			});
		}
		else if (mc == CEMIDevMgmt.MC_FUNCPROP_CMD_REQ || mc == CEMIDevMgmt.MC_FUNCPROP_READ_REQ) {
			final boolean read = mc == CEMIDevMgmt.MC_FUNCPROP_READ_REQ;
			byte[] data = {};

			var returnCode = ReturnCode.Error;

			final int objectType = f.getObjectType();
			final int objInst = f.getObjectInstance();
			final int propertyId = f.getPID();

			final CEMIDevMgmt dm;
			if (!functionProperties.contains(new PropertyKey(f.getObjectType(), f.getPID()))) {
				dm = CEMIDevMgmt.newFunctionPropertyService(CEMIDevMgmt.MC_FUNCPROP_CON, objectType, objInst,
						propertyId);
			}
			else {
				final byte[] functionInput = f.getPayload();
				if (functionInput.length > 1) {
					final int rc = functionInput[0] & 0xff;
					final int serviceId = functionInput[1] & 0xff;
					if (rc != 0) // received return code shall be 0
						returnCode = ReturnCode.DataVoid;
					else {
						if (read) {
							final var ios = server.getInterfaceObjectServer();

							if (objectType == InterfaceObject.KNXNETIP_PARAMETER_OBJECT) {
								if (propertyId == KnxipParameterObject.Pid.SecuredServiceFamilies) {
									if (serviceId == 0) {
										if (functionInput.length == 3) {
											final int famId = functionInput[2];
											if (famId > 2 && famId < 6) {
												final var serviceFamily = famId == 3 ? ServiceFamily.DeviceManagement
														: famId == 4 ? ServiceFamily.Tunneling : ServiceFamily.Routing;
												final boolean secured = KnxipParameterObject.lookup(ios, objInst)
														.securedService(serviceFamily);
												data = new byte[] { (byte) famId, (byte) (secured ? 1 : 0) };
											}
											else
												returnCode = ReturnCode.DataVoid;
										}
										else
											returnCode = ReturnCode.DataVoid;
									}
									else
										returnCode = ReturnCode.InvalidServiceCommand;
								}
							}
						}
						else { // write
							returnCode = ReturnCode.InvalidServiceCommand;
						}
					}
					dm = CEMIDevMgmt.newFunctionPropertyService(CEMIDevMgmt.MC_FUNCPROP_CON, objectType,
							objInst, propertyId, returnCode, serviceId, data);
				}
				else // function input length too short, ignore
					return;
			}
			dispatch(c, () -> dm, frame -> {
				c.send(frame, WaitForAck);
				CemiFrameTracer.instance().trace(frame, c.toString(), null, FramePath.LocalToClient);
			});
		}
		else if (mc == CEMIDevMgmt.MC_RESET_REQ) {
			// handle reset.req here since we have the connection name for logging
			logger.log(INFO, "received reset request " + c.name() + " - restarting " + server.getName());
			inReset = true;
			server.shutdown();
			// corresponding launch is done in run()
			subnetEvents.offer(ResetEvent);
		}
	}

	private Optional<SubnetConnector> connectorFor(final IndividualAddress dst) {
		for (final SubnetConnector connector : connectors) {
			final ServiceContainer c = connector.getServiceContainer();
			if (matchesSubnet(dst, c.getMediumSettings().getDeviceAddress()))
				return Optional.of(connector);
		}
		return Optional.empty();
	}

	private int objectInstance(final ServiceContainer svcCont) {
		return objectInstance(svcCont.getName());
	}

	private int objectInstance(final SubnetConnector connector) {
		return connectors.indexOf(connector) + 1;
	}

	private int objectInstance(final String id) {
		for (int i = 0; i < connectors.size(); i++)
			if (connectors.get(i).getName().equals(id))
				return i + 1;
		throw new KnxRuntimeException("no subnet connector with ID '" + id + "'");
	}

	// TODO support > 1 service containers with usb
	private LocalDeviceManagementUsb ldmAdapter;
	private DeviceDescriptor dd0;

	private LocalDeviceManagementUsb localDevMgmtAdapter(final SubnetConnector connector)
		throws KNXException, InterruptedException
	{
		LocalDeviceManagementUsb adapter = ldmAdapter;
		if (adapter != null && adapter.isOpen())
			return adapter;

		// make sure we don't have a virtual link
		if (!(connector.getSubnetLink() instanceof Link<?> l))
			throw new KNXException("no USB subnet link for " + connector.getName());

		final var target = l.target();
		if (target == null)
			throw new KNXException("no open subnet link for " + connector.getName());
		// make sure we don't have a monitor link
		if (!(target instanceof KNXNetworkLink link))
			throw new KNXException("subnet link is in busmonitor-layer");

		if (!link.isOpen()) {
			@SuppressWarnings("unchecked")
			final var cast = ((Link<KNXNetworkLink>) connector.openNetworkLink());
			link = (KNXNetworkLink) cast.target();
		}

		try {
			Class<?> clazz = link.getClass();
			while (clazz != null && !clazz.getSimpleName().equals("AbstractLink"))
				clazz = clazz.getSuperclass();
			if (clazz == null)
				throw new KNXException("unknown link implementation for initializing local device management");
			final Field conn = clazz.getDeclaredField("conn");
			conn.setAccessible(true);
			final UsbConnection c = (UsbConnection) conn.get(link);
			dd0 = c.deviceDescriptor();
			adapter = new LocalDeviceManagementUsb(c, __ -> ldmAdapter = null, false);
			ldmAdapter = adapter;
			return adapter;
		}
		catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
			throw new KNXException("accessing usb connection field while initializing local device management", e);
		}
	}

	private static final int PropertyDescRead = 0x03D8;
	private static final int PropertyDescResponse = 0x03D9;
	private static final int PropertyRead = 0x03D5;
	private static final int PropertyResponse = 0x03D6;
	private static final int DeviceDescRead = 0x0300;
	private static final int DeviceDescRes = 0x0340;
//	private static final int PropertyWrite = 0x03D7;

	// KNX USB cEMI only
	private boolean localDeviceManagement(final SubnetConnector connector, final CEMILData ldata)
	{
		final IndividualAddress localInterface = connector.getServiceContainer().getMediumSettings().getDeviceAddress();
		if (connector.interfaceType() == InterfaceType.Usb && ldata.getDestination().equals(localInterface)) {
			final byte[] data = ldata.getPayload();
			logger.log(DEBUG, "request for {0}, use USB Local-DM", localInterface);
			if (data.length < 2)
				return true;
			final int svc = DataUnitBuilder.getAPDUService(data);
			try {
				// in TL connected-oriented mode, send TL ack
				final int dataConnectedTsdu = 0x40;
				final int rcvSeq = (data[0] >> 2) & 0x0f;
				final boolean connected = (data[0] & dataConnectedTsdu) == dataConnectedTsdu;
				if (connected) {
					final CEMILData ack = new CEMILDataEx(CEMILData.MC_LDATA_IND,
							(IndividualAddress) ldata.getDestination(), ldata.getSource(),
							new byte[] { (byte) (0xc2 | rcvSeq << 2) }, Priority.SYSTEM);
					dispatchToServer(connector, ack, 0, FramePath.LocalToClient);
				}

				final LocalDeviceManagementUsb ldm = localDevMgmtAdapter(connector);
				if (svc == DeviceDescRead) {
					final byte[] tpdu = DataUnitBuilder.createAPDU(DeviceDescRes, dd0.toByteArray());
					tpdu[0] |= data[0];
					final CEMILData f = new CEMILDataEx(CEMILData.MC_LDATA_IND,
							(IndividualAddress) ldata.getDestination(), ldata.getSource(), tpdu, Priority.LOW);
					dispatchToServer(connector, f, 0, FramePath.LocalToClient);
					return true;
				}
				else if (svc == PropertyDescRead || svc == PropertyRead) {
					final byte[] asdu = DataUnitBuilder.extractASDU(data);
					final int objIndex = asdu[0] & 0xff;
					final int pid = asdu[1] & 0xff;
					final int elements = (asdu[2] & 0xff) >> 4;
					int start = 0;
					if (svc == PropertyRead)
						start = (asdu[2] & 0xf) << 8 | (asdu[3] & 0xff);

					byte[] response;
					if (svc == PropertyDescRead) {
						final int propIndex = asdu[2] & 0xff;
						try {
							response = ldm.getDescription(objIndex, pid, propIndex);
							final int descPid = response[1] & 0xff;
							final int objectType = ldm.interfaceObjects().get(objIndex);
							final var key = descPid <= 50 ? new PropertyKey(descPid) : new PropertyKey(objectType, descPid);
							final var definitions = server.getInterfaceObjectServer().propertyDefinitions();
							final var property = definitions.get(key);
							if (property != null)
								response[3] |= (byte) property.pdt();
							response[response.length - 2] = 1;
						}
						catch (final KNXRemoteException pidNotFound) {
							response = new byte[] { (byte) objIndex, (byte) pid, (byte) propIndex, (byte) 0, 0, 0, 0 };
						}
						logger.log(DEBUG, "Local-DM {0} read property description {1}|{2} (idx {3}): {4}", localInterface,
								objIndex, pid, propIndex, HexFormat.ofDelimiter(" ").formatHex(response));
					}
					else {
						try {
							final byte[] propData = ldm.getProperty(objIndex, pid, start, elements);
							response = new byte[4 + propData.length];
							int i = 0;
							response[i++] = (byte) objIndex;
							response[i++] = (byte) pid;
							response[i++] = (byte) ((elements << 4) | (start >> 8));
							response[i++] = (byte) start;
							for (final byte b : propData)
								response[i++] = b;
							logger.log(DEBUG, "Local-DM {0} read property values {1}|{2} (start {3}, {4} elements): {5}",
									localInterface, objIndex, pid, start, elements, HexFormat.ofDelimiter(" ").formatHex(propData));
						}
						catch (final KNXRemoteException e) {
							response = new byte[] { (byte) objIndex, (byte) pid, (byte) (start >> 8), (byte) start };
						}
					}
					final int svcResponse = svc == PropertyDescRead ? PropertyDescResponse : PropertyResponse;
					final byte[] tpdu = DataUnitBuilder.createAPDU(svcResponse, response);
					if (connected)
						tpdu[0] |= (byte) (dataConnectedTsdu | (rcvSeq << 2));
					final CEMILData f = new CEMILDataEx(CEMILData.MC_LDATA_IND,
							(IndividualAddress) ldata.getDestination(), ldata.getSource(), tpdu, Priority.LOW);
					dispatchToServer(connector, f, 0, FramePath.LocalToClient);
					return true;
				}
			}
			catch (KNXException | InterruptedException e) {
				logger.log(ERROR, "KNX USB local device management with {0}", connector.getName(), e);
			}
		}
		return false;
	}

	// defaults to 1 for now
	private final int objectInstance = 1;
	private static final int deviceObject = 0;

	// KNX USB cEMI only
	private void verifySubnetInterfaceAddress(final ServiceContainer svcCont) throws KNXException, InterruptedException
	{
		final SubnetConnector connector = getSubnetConnector(svcCont.getName());
		// TODO check for cEMI server
		if (connector.interfaceType() != InterfaceType.Usb)
			return;
		final IndividualAddress configured = svcCont.getMediumSettings().getDeviceAddress();
		final LocalDeviceManagementUsb ldm = localDevMgmtAdapter(connector);
		final byte[] subnet = ldm.getProperty(deviceObject, objectInstance, PID.SUBNET_ADDRESS, 1, 1);
		final byte[] device = ldm.getProperty(deviceObject, objectInstance, PID.DEVICE_ADDRESS, 1, 1);
		final IndividualAddress current = new IndividualAddress(new byte[] { subnet[0], device[0] });
		if (!current.equals(configured)) {
			logger.log(WARNING, "KNX address mismatch with USB interface: currently {0}, configured {1} -> assigning {2}", current,
					configured, configured);
			final byte[] addr = configured.toByteArray();
			ldm.setProperty(deviceObject, objectInstance, PID.SUBNET_ADDRESS, 1, 1, addr[0]);
			ldm.setProperty(deviceObject, objectInstance, PID.DEVICE_ADDRESS, 1, 1, addr[1]);
		}
	}

	private synchronized void incMsgTransmitted(final int objinst, final boolean toKnxNetwork)
	{
		final int pid = toKnxNetwork ? PID.MSG_TRANSMIT_TO_KNX : PID.MSG_TRANSMIT_TO_IP;
		// must be 4 byte unsigned
		// getPropertyOrDefault casts to int, but we just increment and store so it doesn't matter
		long transmit = getPropertyOrDefault(KNXNETIP_PARAMETER_OBJECT, objinst, pid, 0);
		try {
			server.getInterfaceObjectServer().setProperty(KNXNETIP_PARAMETER_OBJECT, objinst, pid, 1, 1,
					bytesFromInt(++transmit));
		}
		catch (final KnxPropertyException e) {
			logger.log(ERROR, "on increasing message transmit counter", e);
		}
		incSendRateCounter(objinst, toKnxNetwork);
	}

	private void incSendRateCounter(final int objInstance, final boolean toKnxNetwork) {
		final int idx = objInstance - 1;
		final var counter = toKnxNetwork ? telegramsToKnx.get(idx) : telegramsFromKnx.get(idx);
		counter.increment();
	}

	// support queue overflow statistics
	private void incMsgQueueOverflow(final boolean toKnxNetwork)
	{
		final int pid = toKnxNetwork ? PID.QUEUE_OVERFLOW_TO_KNX : PID.QUEUE_OVERFLOW_TO_IP;
		int overflow = getPropertyOrDefault(KNXNETIP_PARAMETER_OBJECT, objectInstance, pid, 0);
		if (overflow == 0xffff) {
			logger.log(WARNING, "queue overflow counter reached maximum of 0xffff, not incremented");
			return;
		}
		++overflow;
		final var direction = toKnxNetwork ? "IP => KNX" : "KNX => IP";
		logger.log(WARNING, "queue overflow {0}, counter incremented to {1}", direction, overflow);
		try {
			server.getInterfaceObjectServer().setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance, pid, 1, 1,
					bytesFromWord(overflow));
		}
		catch (final KnxPropertyException e) {
			logger.log(ERROR, "on increasing queue overflow counter", e);
		}
	}

	// returns null to indicate a discarded frame
	private CEMILData adjustHopCount(final CEMILData msg)
	{
		int count = msg.getHopCount();
		// if counter == 0, discard frame
		if (count == 0) {
			logger.log(WARNING, "hop count 0, discard frame {0}->{1}", msg.getSource(), msg.getDestination());
			return null;
		}
		// otherwise, decrement and forward
		--count;
		if (msg instanceof CEMILDataEx) {
			((CEMILDataEx) msg).setHopCount(count);
			return msg;
		}
		return new CEMILData(msg.getMessageCode(), msg.getSource(), msg.getDestination(),
				msg.getPayload(), msg.getPriority(), msg.isRepetition(), count);
	}

	// if we can not transmit for 5 seconds, we assume some network fault
	private synchronized void setNetworkState(final int objectInstance, final boolean knxNetwork, final boolean faulty)
	{
		// 1 byte bit field
		int state = getPropertyOrDefault(KNXNETIP_PARAMETER_OBJECT, objectInstance, PID.KNXNETIP_DEVICE_STATE, 0);
		// set the corresponding bit in device state field
		// bit 0: KNX fault, bit 1: IP fault, others reserved
		if (knxNetwork)
			state = (faulty ? state | 1 : state & 0xfe);
		else
			state = (faulty ? state | 2 : state & 0xfd);
		try {
			setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance, PID.KNXNETIP_DEVICE_STATE, (byte) state);
			setProperty(ROUTER_OBJECT, objectInstance, PID.MEDIUM_STATUS, (byte) (faulty ? 1 : 0));
		}
		catch (final KnxPropertyException e) {
			logger.log(WARNING, "on modifying network fault in device state", e);
		}
	}

	private static CEMI convertToBusmon(final CEMILData ldata, final long eventId, final SubnetConnector connector)
	{
		// maintain busmon frame sequence using the event id
		if (eventId != connector.lastEventId) {
			connector.eventCounter++;
			connector.lastEventId = eventId;
		}
		final int seq = (int) (connector.eventCounter % 8);

		// provide 32 bit timestamp with 1 us precision
		final long timestamp = (System.nanoTime() / 1000) & 0xFFFFFFFFL;

		byte[] doa = null;
		final CEMILData copy = (CEMILData) CEMIFactory.copy(ldata);
		if (copy instanceof final CEMILDataEx ex) {
			doa = ex.getAdditionalInfo(AdditionalInfo.PlMedium);
			ex.additionalInfo().clear();
		}

		final int doaLength = doa != null ? 1 : 0;
		final byte[] src = copy.toByteArray();
		// -2 to remove msg code and add.info field, +1 for fcs + length for DoA (if any)
		final byte[] raw = new byte[src.length - 2 + 1 + doaLength];
		System.arraycopy(src, 2, raw, 0, src.length - 2);
		if (doa != null) {
			// insert PL DoA
			raw[raw.length - 1] = doa[1];
		}

		final int extFrameFormatFlag = 0x80;
		raw[0] = (byte) (raw[0] & ~extFrameFormatFlag); // clear bit to indicate ext. frame format
		if (copy.isSystemBroadcast())
			raw[0] |= 0x10;
		raw[raw.length - 1 - doaLength] = (byte) checksum(raw); // fcs

		return CEMIBusMon.newWithSequenceNumber(seq, timestamp, true, raw);
	}

	private static int checksum(final byte[] frame)
	{
		int cs = 0;
		for (final byte b : frame)
			cs ^= b;
		return ~cs;
	}

	private static long toUnsignedInt(final byte[] data) {
		if (data.length == 1)
			return (data[0] & 0xff);
		if (data.length == 2)
			return (long) (data[0] & 0xff) << 8 | (data[1] & 0xff);
		return (long) (data[0] & 0xff) << 24 | (data[1] & 0xff) << 16 | (data[2] & 0xff) << 8 | (data[3] & 0xff);
	}

	private static byte[] bytesFromInt(final long value)
	{
		return new byte[] { (byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value };
	}

	private static byte[] bytesFromWord(final int word)
	{
		return new byte[] { (byte) (word >> 8), (byte) word };
	}
}
