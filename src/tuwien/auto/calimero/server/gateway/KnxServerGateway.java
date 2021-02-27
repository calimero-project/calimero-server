/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2021 B. Malinowsky

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

package tuwien.auto.calimero.server.gateway;

import static java.lang.String.format;
import static tuwien.auto.calimero.device.ios.InterfaceObject.DEVICE_OBJECT;
import static tuwien.auto.calimero.device.ios.InterfaceObject.KNXNETIP_PARAMETER_OBJECT;
import static tuwien.auto.calimero.device.ios.InterfaceObject.ROUTER_OBJECT;
import static tuwien.auto.calimero.device.ios.InterfaceObject.SECURITY_OBJECT;
import static tuwien.auto.calimero.knxnetip.KNXnetIPConnection.BlockingMode.WaitForAck;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.slf4j.Logger;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.DeviceDescriptor;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXRemoteException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.KnxRuntimeException;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.cemi.AdditionalInfo;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.cemi.CEMIBusMon;
import tuwien.auto.calimero.cemi.CEMIDevMgmt;
import tuwien.auto.calimero.cemi.CEMIFactory;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.cemi.CEMILDataEx;
import tuwien.auto.calimero.datapoint.StateDP;
import tuwien.auto.calimero.device.AccessPolicies;
import tuwien.auto.calimero.device.BaseKnxDevice;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KnxPropertyException;
import tuwien.auto.calimero.device.ios.PropertyEvent;
import tuwien.auto.calimero.dptxlator.DPTXlator;
import tuwien.auto.calimero.dptxlator.DPTXlatorDate;
import tuwien.auto.calimero.dptxlator.DPTXlatorDateTime;
import tuwien.auto.calimero.dptxlator.DPTXlatorTime;
import tuwien.auto.calimero.dptxlator.PropertyTypes;
import tuwien.auto.calimero.dptxlator.TranslatorTypes;
import tuwien.auto.calimero.knxnetip.KNXConnectionClosedException;
import tuwien.auto.calimero.knxnetip.KNXnetIPConnection;
import tuwien.auto.calimero.knxnetip.KNXnetIPDevMgmt;
import tuwien.auto.calimero.knxnetip.KNXnetIPRouting;
import tuwien.auto.calimero.knxnetip.LostMessageEvent;
import tuwien.auto.calimero.knxnetip.RoutingBusyEvent;
import tuwien.auto.calimero.knxnetip.RoutingListener;
import tuwien.auto.calimero.knxnetip.servicetype.RoutingBusy;
import tuwien.auto.calimero.knxnetip.servicetype.RoutingSystemBroadcast;
import tuwien.auto.calimero.link.Connector.Link;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.KNXNetworkLinkIP;
import tuwien.auto.calimero.link.KNXNetworkLinkUsb;
import tuwien.auto.calimero.link.KNXNetworkMonitor;
import tuwien.auto.calimero.link.NetworkLinkListener;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.log.LogService.LogLevel;
import tuwien.auto.calimero.mgmt.LocalDeviceManagementUsb;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.mgmt.PropertyClient;
import tuwien.auto.calimero.mgmt.PropertyClient.PropertyKey;
import tuwien.auto.calimero.secure.SecureApplicationLayer;
import tuwien.auto.calimero.secure.Security;
import tuwien.auto.calimero.secure.SecurityControl;
import tuwien.auto.calimero.secure.SecurityControl.DataSecurity;
import tuwien.auto.calimero.serial.usb.UsbConnection;
import tuwien.auto.calimero.server.ServerConfiguration;
import tuwien.auto.calimero.server.VirtualLink;
import tuwien.auto.calimero.server.knxnetip.DataEndpoint;
import tuwien.auto.calimero.server.knxnetip.DefaultServiceContainer;
import tuwien.auto.calimero.server.knxnetip.KNXnetIPServer;
import tuwien.auto.calimero.server.knxnetip.RoutingServiceContainer;
import tuwien.auto.calimero.server.knxnetip.ServerListener;
import tuwien.auto.calimero.server.knxnetip.ServiceContainer;
import tuwien.auto.calimero.server.knxnetip.ServiceContainerEvent;
import tuwien.auto.calimero.server.knxnetip.ShutdownEvent;

/**
 * Provides gateway functionality to dispatch KNX messages between different networks and processes
 * server requests.
 * <p>
 * The main functionality is to bridge IP networks and KNX subnets and allow KNX messages exchange a
 * KNXnet/IP server and links to KNX subnets.<br>
 * Besides, the gateway handles KNXnet/IP local device management by processing and answering
 * received client messages.<br>
 * The gateway implements group address filtering using the KNX property
 * {@link tuwien.auto.calimero.mgmt.PropertyAccess.PID#TABLE} in the interface object
 * {@link InterfaceObject#ADDRESSTABLE_OBJECT} in the Interface Object Server.
 * <p>
 * Starting a gateway by invoking {@link #run()} is a blocking operation. Therefore, this class
 * implements {@link Runnable} to allow execution in its own thread.
 *
 * @author B. Malinowsky
 */
public class KnxServerGateway implements Runnable
{
	// KNX IP routing busy flow control
	// currently only 1 routing service is supported per server
	private static final Duration randomWaitScale = Duration.ofMillis(50);
	private static final Duration throttleScale = Duration.ofMillis(100);
	private volatile Instant currentWaitUntil = Instant.EPOCH;
	private volatile Instant pauseSendingUntil = Instant.EPOCH;
	private volatile Instant throttleUntil = Instant.EPOCH;

	private final AtomicInteger routingBusyCounter = new AtomicInteger();
	private static final ScheduledExecutorService busyCounterDecrementor = Executors.newScheduledThreadPool(0, r -> {
		final Thread t = new Thread(r, "Calimero routing busy counter");
		t.setDaemon(true);
		return t;
	});

	private static final ScheduledExecutorService timeServerCyclicTransmitter = Executors
			.newSingleThreadScheduledExecutor(r -> {
				final var t = new Thread(r, "Calimero time server");
				t.setDaemon(true);
				return t;
			});

	// Connection listener for accepted KNXnet/IP connections
	private final class ConnectionListener implements RoutingListener
	{
		final ServiceContainer sc;
		final String name;

		private Instant lastRoutingBusy = Instant.EPOCH;
		// avoid null, assign bogus future
		private volatile ScheduledFuture<?> decrement = busyCounterDecrementor.schedule(() -> {}, 0, TimeUnit.SECONDS);

		ConnectionListener(final ServiceContainer svcContainer, final String connectionName,
			final IndividualAddress device)
		{
			sc = svcContainer;
			// same as calling ((KNXnetIPConnection) getSource()).getName()
			name = connectionName;
		}

		@Override
		public void frameReceived(final FrameEvent e)
		{
			if (!ipEvents.offer(e))
				incMsgQueueOverflow(true);
		}

		@Override
		public void lostMessage(final LostMessageEvent e)
		{
			final String unit = e.getLostMessages() > 1 ? "messages" : "message";
			logger.warn("KNXnet/IP router {} lost {} {}",  e.getSender(), e.getLostMessages(), unit);
		}

		@Override
		public void routingBusy(final RoutingBusyEvent e)
		{
			// in case we sent the routing busy notification, ignore it
			if (sentByUs(e.sender()))
				return;

			// setup timing for routing busy flow control
			final Instant now = Instant.now();
			final Instant waitUntil = now.plus(e.waitTime(), ChronoUnit.MILLIS);
			LogLevel level = LogLevel.TRACE;
			boolean update = false;
			if (waitUntil.isAfter(currentWaitUntil)) {
				currentWaitUntil = waitUntil;
				level = LogLevel.WARN;
				update = true;
			}
			LogService.log(logger, level, "device {} sent {}", e.sender(), e.get());

			// increment random wait scaling iff >= 10 ms have passed since the last counted routing busy
			if (now.isAfter(lastRoutingBusy.plusMillis(10))) {
				lastRoutingBusy = now;
				routingBusyCounter.incrementAndGet();
				update = true;
			}

			if (!update)
				return;

			final double rand = Math.random();
			final long randomWait = Math.round(rand * routingBusyCounter.get() * randomWaitScale.toMillis());

			// invariant on instants: throttle >= pause sending >= current wait
			pauseSendingUntil = currentWaitUntil.plusMillis(randomWait);
			final long throttle = routingBusyCounter.get() * throttleScale.toMillis();
			throttleUntil = pauseSendingUntil.plusMillis(throttle);

			final long continueIn = Duration.between(now, pauseSendingUntil).toMillis();
			logger.info("set routing busy counter = {}, random wait = {} ms, continue sending in {} ms, throttle {} ms",
					routingBusyCounter, randomWait, continueIn, throttle);

			final long initialDelay = Duration.between(now, throttleUntil).toMillis() + 5;
			decrement.cancel(false);
			decrement = busyCounterDecrementor.scheduleAtFixedRate(this::decrementBusyCounter, initialDelay, 5,
					TimeUnit.MILLISECONDS);
		}

		private void decrementBusyCounter()
		{
			// decrement iff counter > 0, otherwise cancel decrementing
			if (routingBusyCounter.accumulateAndGet(0, (v, u) -> v > 0 ? --v : v) == 0)
				decrement.cancel(false);
		}

		// this will give a false positive if sending device and server are on same host
		private boolean sentByUs(final InetSocketAddress sender)
		{
			try {
				final NetworkInterface netif = NetworkInterface.getByName(sc.networkInterface());
				return Optional.ofNullable(netif).map(ni -> (List<InetAddress>) Collections.list(ni.getInetAddresses()))
						.orElse(Arrays.asList(InetAddress.getLocalHost())).contains(sender.getAddress());
			}
			catch (UnknownHostException | SocketException e) {
				return false;
			}
		}

		@Override
		public void connectionClosed(final CloseEvent e)
		{
			serverConnections.remove(e.getSource());
			logger.debug("removed connection {} ({})", name, e.getReason());
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
		public boolean acceptDataConnection(final ServiceContainer svcContainer,
			final KNXnetIPConnection conn, final IndividualAddress assignedDeviceAddress,
			final boolean networkMonitor)
		{
			final SubnetConnector connector = getSubnetConnector(svcContainer.getName());
			if (connector == null)
				return false;

			if (!(conn instanceof KNXnetIPDevMgmt)) {
				final AutoCloseable subnetLink = connector.getSubnetLink();
				final AutoCloseable rawLink = subnetLink instanceof Link ? ((Link<?>) subnetLink).target() : subnetLink;
				try {
					if (rawLink instanceof VirtualLink) {
						/* no-op */
					}
					else if (!networkMonitor && !(rawLink instanceof KNXNetworkLink)) {
						closeLink(subnetLink);
						connector.openNetworkLink();
					}
					else if (networkMonitor && !(rawLink instanceof KNXNetworkMonitor)) {
						closeLink(subnetLink);
						connector.openMonitorLink();
					}
				}
				catch (KNXException | InterruptedException e) {
					final String subnetType = connector.getInterfaceType();
					final String subnetArgs = connector.linkArguments();
					final ServiceContainer serviceContainer = connector.getServiceContainer();
					final KNXMediumSettings settings = serviceContainer.getMediumSettings();
					logger.error("open network link using {} interface {} for {}", subnetType, subnetArgs, settings, e);
					if (e instanceof InterruptedException)
						Thread.currentThread().interrupt();
					return false;
				}
			}

			conn.addConnectionListener(new ConnectionListener(svcContainer, conn.getName(), assignedDeviceAddress));
			return true;
		}

		@Override
		public void connectionEstablished(final ServiceContainer svcContainer, final KNXnetIPConnection connection)
		{
			serverConnections.add(connection);
			logger.debug("established connection {}", connection);

			try {
				if (!verifiedSubnetInterfaceAddress.contains(svcContainer)) {
					verifySubnetInterfaceAddress(svcContainer);
					verifiedSubnetInterfaceAddress.add(svcContainer);
				}
			}
			catch (KNXException | InterruptedException | RuntimeException e) {
				String msg = e.getMessage();
				msg = msg != null && msg.length() > 0 ? msg : e.getClass().getSimpleName();
				logger.error("skip verifying knx address of '{}' subnet interface ({})", svcContainer.getName(), msg);
			}

			final ReplayBuffer<FrameEvent> buffer = subnetEventBuffers.get(svcContainer);
			if (buffer == null)
				return;
			final int[] portRange = ((DefaultServiceContainer) svcContainer).disruptionBufferPortRange();
			final InetSocketAddress remote = connection.getRemoteAddress();
			final int port = remote.getPort();
			if (port >= portRange[0] && port <= portRange[1]) {
				buffer.add(connection);
				if (buffer.isDisrupted(connection)) {
					waitingForReplay.put(connection, svcContainer);
					synchronized (KnxServerGateway.this) {
						KnxServerGateway.this.notify();
					}
				}
			}
		}

		@Override
		public void onPropertyValueChanged(final PropertyEvent pe)
		{
			//logger.trace("property id " + pe.getPropertyId() + " changed to ["
			//		+ DataUnitBuilder.toHex(pe.getNewData(), " ") + "]");

			if (pe.getNewData().length == 0)
				return;
		}

		@Override
		public void onServiceContainerChange(final ServiceContainerEvent sce)
		{
			final int event = sce.getEventType();
			final ServiceContainer sc = sce.getContainer();
			if (event == ServiceContainerEvent.ROUTING_SVC_STARTED) {
				final KNXnetIPConnection conn = sce.getConnection();
				conn.addConnectionListener(new ConnectionListener(sc, conn.getName(), null));
				serverConnections.add(conn);
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
			logger.info(server.getName() + ": " + s + " request for shutdown");
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
		private final String scid;

		SubnetListener(final String svcContainerId)
		{
			scid = svcContainerId;
		}

		@Override
		public void confirmation(final FrameEvent e) {
			subnetConnected(true);
		}

		@Override
		public void indication(final FrameEvent e)
		{
			subnetConnected(true);
			// In the dispatching to server side, we rely on having the
			// subnet link in the frame event source stored so to know where the
			// frame came from.
			// But this will not work if the sending link differs from the one
			// stored in this frame event, e.g., when using a buffered link.
			// Therefore, I store the svcContainer in here for re-association.
			if (!subnetEvents.offer(new FrameEvent(scid, e.getFrame())))
				incMsgQueueOverflow(false);
		}

		@Override
		public void linkClosed(final CloseEvent e)
		{
			subnetConnected(false);
			logger.info("KNX subnet link closed (" + e.getReason() + ")");
		}

		void connectionStatus(final boolean connected) {
			final var sc = getSubnetConnector(scid).getServiceContainer();
			final byte[] data = bytesFromWord(sc.getMediumSettings().maxApduLength());
			final int pidMaxRoutingApduLength = 58;
			setProperty(ROUTER_OBJECT, objectInstance(scid), pidMaxRoutingApduLength, data);
			if (scid.equals(connectors.get(0).getServiceContainer().getName())) {
				setProperty(DEVICE_OBJECT, 1, PID.MAX_APDULENGTH, data);
				final int pidMaxInterfaceApduLength = 68;
				setProperty(InterfaceObject.CEMI_SERVER_OBJECT, 1, pidMaxInterfaceApduLength, data);
			}

			logger.debug("set maximum APDU length of '{}' to {}", sc.getName(), sc.getMediumSettings().maxApduLength());

			subnetConnected(connected);
		}

		private void subnetConnected(final boolean connected) {
			setNetworkState(objectInstance(scid), true, !connected);
		}
	}

	private final String name;
	private final Logger logger;

	private final KNXnetIPServer server;
	// connectors array is not sync'd throughout gateway
	private final List<SubnetConnector> connectors = new ArrayList<>();
	private final List<KNXnetIPConnection> serverConnections = new CopyOnWriteArrayList<>();

	private final int maxEventQueueSize = 1000;
	private final BlockingQueue<FrameEvent> ipEvents = new ArrayBlockingQueue<>(maxEventQueueSize);
	private final BlockingQueue<FrameEvent> subnetEvents = new ArrayBlockingQueue<>(maxEventQueueSize);

	private static final FrameEvent ResetEvent = new FrameEvent(KnxServerGateway.class, new byte[0]);

	// support replaying subnet events for disrupted tunneling connections
	private final Map<ServiceContainer, ReplayBuffer<FrameEvent>> subnetEventBuffers = new HashMap<>();
	private final Map<KNXnetIPConnection, ServiceContainer> waitingForReplay = new ConcurrentHashMap<>();

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


	private final Thread dispatcher = new Thread() {
		// threshold for multicasting routing busy msg is 10 incoming routing indications
		private static final int routingBusyMsgThreshold = 10;
		private int ipMsgCount;

		@Override
		public void run()
		{
			try {
				while (trucking) {
					final FrameEvent event = ipEvents.take();
					try {
						if (!event.systemBroadcast())
							checkRoutingBusy();
						onClientFrameReceived(event);
					}
					catch (final RuntimeException e) {
						logger.error("on server-side frame event", e);
					}
				}
			}
			catch (final InterruptedException e) {}
		};

		private void checkRoutingBusy()
		{
			final Duration observationPeriod = Duration.ofMillis(100);
			// TODO adjust for KNX subnet capacity
			final int maxMsgsPerSecond = 200;

			ipMsgCount++;
			final int msgs = ipEvents.size();
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
			serverConnections.stream().filter(c -> c instanceof KNXnetIPRouting)
					.forEach(c -> sendRoutingBusy((KNXnetIPRouting) c));
		}

		private void sendRoutingBusy(final KNXnetIPRouting connection)
		{
			final int deviceState = getPropertyOrDefault(KNXNETIP_PARAMETER_OBJECT, objectInstance,
					PID.KNXNETIP_DEVICE_STATE, 0);
			final int waitTime = getPropertyOrDefault(KNXNETIP_PARAMETER_OBJECT, objectInstance,
					PID.ROUTING_BUSY_WAIT_TIME, 100);
			final RoutingBusy msg = new RoutingBusy(deviceState, waitTime, 0);
			try {
				connection.send(msg);
			}
			catch (final KNXConnectionClosedException e) {
				logger.warn("trying to send routing busy message on closed {}", connection, e);
			}
		}
	};

	private final List<NetworkLinkListener> deviceListeners = new ArrayList<>();
	private final KNXNetworkLink deviceLinkProxy = new KNXNetworkLink() {
		@Override
		public void addLinkListener(final NetworkLinkListener l) { deviceListeners.add(l); }

		@Override
		public void removeLinkListener(final NetworkLinkListener l) { deviceListeners.remove(l); }

		@Override
		public void sendRequest(final KNXAddress dst, final Priority p, final byte[] nsdu)
				throws KNXTimeoutException, KNXLinkClosedException {
			sendRequestWait(dst, p, nsdu);
		}

		@Override
		public void sendRequestWait(final KNXAddress dst, final Priority p, final byte[] nsdu)
				throws KNXTimeoutException, KNXLinkClosedException {

			final boolean ldm = dst != null && dst.equals(new IndividualAddress(0));
			if (ldm) {
				for (final var c : serverConnections) {
					// device mgmt endpoints don't have a device address assigned
					if (c instanceof DataEndpoint && ((DataEndpoint) c).deviceAddress() == null) {
						final var deviceMgmtEndpoint = (DataEndpoint) c;
						// send cEMI T-Data
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
		public void send(final CEMILData msg, final boolean waitForCon)
				throws KNXTimeoutException, KNXLinkClosedException {
			// TODO support > 1 service containers
			final SubnetConnector connector = connectors.get(0);
			final long eventId = connector.lastEventId + 1; // required for fake busmonitor sequence number
			dispatchToServer(connector, msg, eventId);
		}

		@Override
		public String getName() { return name + " device"; }

		@Override
		public void setKNXMedium(final KNXMediumSettings settings) {}

		@Override
		public KNXMediumSettings getKNXMedium() { return connectors.get(0).getServiceContainer().getMediumSettings(); }

		@Override
		public void setHopCount(final int count) {}

		@Override
		public int getHopCount() { return 6; }

		@Override
		public boolean isOpen() { return true; }

		@Override
		public void close() {}
	};

	/**
	 * Creates a new server gateway for the supplied KNXnet/IP server.
	 * On running this gateway ({@link #run()}), it is ensured the KNXnet/IP server is launched.
	 *
	 * @param s KNXnet/IP server representing the server side
	 * @param config server configuration
	 */
	public KnxServerGateway(final KNXnetIPServer s, final ServerConfiguration config) {
		this(config.name(), s, config.containers().stream().map(c -> c.subnetConnector()).collect(Collectors.toList()));
		for (final var c : config.containers()) {
			final var sc = c.subnetConnector().getServiceContainer();
			setupTimeServer(sc, c.timeServer());
		}

		try {
			server.device.setDeviceLink(deviceLinkProxy);
		}
		catch (final KNXLinkClosedException e) {
			throw new KnxRuntimeException("setting device link", e);
		}
	}

	/**
	 * @deprecated Use {@link #KnxServerGateway(KNXnetIPServer, ServerConfiguration)}.
	 *
	 * @param gatewayName descriptive name to use for this gateway
	 * @param s KNXnet/IP server representing the server side
	 * @param subnetConnectors list of {@link SubnetConnector} objects, which specify the
	 *        associations between the connections from either side of the gateway
	 */
	@Deprecated(forRemoval = true)
	public KnxServerGateway(final String gatewayName, final KNXnetIPServer s, final SubnetConnector[] subnetConnectors)
	{
		this(gatewayName, s, Arrays.asList(subnetConnectors));

		try {
			server.device.setDeviceLink(deviceLinkProxy);
		}
		catch (final KNXLinkClosedException e) {
			throw new KnxRuntimeException("setting device link", e);
		}

	}

	private KnxServerGateway(final String gatewayName, final KNXnetIPServer s, final List<SubnetConnector> subnetConnectors) {
		name = gatewayName;
		server = s;
		server.addServerListener(new KNXnetIPServerListener());
		logger = LogService.getLogger("calimero.server.gateway." + name);
		connectors.addAll(subnetConnectors);
		startTime = Instant.now().truncatedTo(ChronoUnit.SECONDS);
		dispatcher.setName(name + " subnet dispatcher");

		final var ios = server.getInterfaceObjectServer();
		for (final var entry : ios.propertyDefinitions().entrySet()) {
			if (entry.getValue().getPDT() == PropertyTypes.PDT_FUNCTION)
				functionProperties.add(entry.getKey());
		}

		int objinst = 0;
		for (final SubnetConnector connector : connectors) {
			objinst++;

			connector.setSubnetListener(new SubnetListener(connector.getName()));

			final ServiceContainer sc = connector.getServiceContainer();
			final Duration timeout = ((DefaultServiceContainer) sc).disruptionBufferTimeout();
			if (!timeout.isZero()) {
				final int[] portRange = ((DefaultServiceContainer) sc).disruptionBufferPortRange();
				logger.info("activate \'{}\' disruption buffer on ports [{}-{}], disruption timeout {} s", sc.getName(),
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
				}
				catch (final KNXException e) {
					logger.error("error opening network link for {}", connector.getName(), e);
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
		dispatcher.start();
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
				logger.error("on dispatching KNX message", e);
			}
			catch (final InterruptedException e) {
				quit();
				Thread.currentThread().interrupt();
			}
		}

		dispatcher.interrupt();
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
	 * @return the KNXnet/IP server used by this gateway
	 */
	public final KNXnetIPServer getServer()
	{
		return server;
	}

	/**
	 * @return the list of subnet connectors currently maintained by the gateway
	 */
	public final List<SubnetConnector> getSubnetConnectors()
	{
		return new ArrayList<>(connectors);
	}

	private void setupTimeServer(final ServiceContainer sc, final List<StateDP> datapoints) {
		final var connector = getSubnetConnector(sc.getName());
		for (final var datapoint : datapoints) {
			final var security = Security.defaultInstallation().groupKeys().containsKey(datapoint.getMainAddress())
					? DataSecurity.AuthConf : DataSecurity.None;
			((BaseKnxDevice) server.device).addGroupObject(datapoint, security, false);
			if (security != DataSecurity.None)
				server.getInterfaceObjectServer().setProperty(InterfaceObject.SECURITY_OBJECT, 1, 51, 1, 1, (byte) 1);

			final var dpt = datapoint.getDPT();
			final var dst = datapoint.getMainAddress();
			final int sendInterval = datapoint.getExpirationTimeout();
			logger.debug("setup time server for {}: publish '{}' ({}) to {} every {} seconds", connector.getName(),
					datapoint.getName(), dpt, dst, sendInterval);
			try {
				final var xlator = TranslatorTypes.createTranslator(dpt);

				timeServerCyclicTransmitter.scheduleAtFixedRate(
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
		final long millis = System.currentTimeMillis();
		final var src = connector.getServiceContainer().getMediumSettings().getDeviceAddress();
		if (xlator instanceof DPTXlatorDate)
			((DPTXlatorDate) xlator).setValue(millis);
		else if (xlator instanceof DPTXlatorTime)
			((DPTXlatorTime) xlator).setValue(millis);
		else if (xlator instanceof DPTXlatorDateTime) {
			final DPTXlatorDateTime dateTime = (DPTXlatorDateTime) xlator;
			dateTime.setValue(millis);
			dateTime.setClockSync(true);
		}
		final var plainApdu = DataUnitBuilder.createAPDU(0x80, xlator.getData());
		final var sal = ((BaseKnxDevice) server.device).secureApplicationLayer();
		try {
			final var apdu = sal.secureGroupObject(src, dst, plainApdu).orElse(plainApdu);
			final var ldata = new CEMILDataEx(CEMILData.MC_LDATA_REQ, src, dst, apdu, p);
			dispatchToSubnet(connector, ldata, dst.getRawAddress(), false);
		}
		catch (final InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		catch (final RuntimeException e) {
			logger.warn("time server error {} {}", dst, xlator, e);
		}
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
		info.append(format("start time %s (uptime %s%d:%d)%n", startTime, dayPart, uptime.toHoursPart(),
				uptime.toMinutesPart()));

		int objInst = 0;

		info.append(format("used msg buffer IP => KNX: %d/%d (%d %%)%n", ipEvents.size(), maxEventQueueSize,
				ipEvents.size() * 100 / maxEventQueueSize));
		info.append(format("used msg buffer KNX => IP: %d/%d (%d %%)%n", subnetEvents.size(), maxEventQueueSize,
				subnetEvents.size() * 100 / maxEventQueueSize));

		for (final SubnetConnector c : getSubnetConnectors()) {
			objInst++;
			info.append(format("service container '%s'%n", c.getName()));
			final InterfaceObjectServer ios = server.getInterfaceObjectServer();
			try {
				if (c.getServiceContainer() instanceof RoutingServiceContainer) {
					final RoutingServiceContainer rsc = (RoutingServiceContainer) c.getServiceContainer();
					info.append(format("\trouting multicast %s netif %s%n",
							rsc.routingMulticastAddress().getHostAddress(), rsc.networkInterface()));
				}

				final InetAddress ip = InetAddress.getByAddress(
						ios.getProperty(KNXNETIP_PARAMETER_OBJECT, objInst, PID.CURRENT_IP_ADDRESS, 1, 1));
				final InetAddress mask = InetAddress.getByAddress(
						ios.getProperty(KNXNETIP_PARAMETER_OBJECT, objInst, PID.CURRENT_SUBNET_MASK, 1, 1));
				info.append(format("\tserver IP %s (subnet %s) netif %s%n", ip.getHostAddress(), mask.getHostAddress(),
						NetworkInterface.getByInetAddress(ip)));

				AutoCloseable link = c.getSubnetLink();
				if (link instanceof Link<?>)
					link = ((Link<?>) link).target();

				info.append(format("\tsubnet %s%n", c.getSubnetLink()));

				final long toKnx = property(KNXNETIP_PARAMETER_OBJECT, objInst, PID.MSG_TRANSMIT_TO_KNX).orElse(0L);
				final long overflowKnx = property(KNXNETIP_PARAMETER_OBJECT, objInst, PID.QUEUE_OVERFLOW_TO_KNX).orElse(0L);
				final int rateToKnx = telegramsToKnx.get(objInst - 1).average();
				info.append(format("\tIP => KNX: sent %d, overflow %d [msgs], %d [msgs/min]%n", toKnx, overflowKnx, rateToKnx));
				final long toIP = property(KNXNETIP_PARAMETER_OBJECT, objInst, PID.MSG_TRANSMIT_TO_IP).orElse(0L);
				final long overflowIP = property(KNXNETIP_PARAMETER_OBJECT, objInst, PID.QUEUE_OVERFLOW_TO_IP).orElse(0L);
				final int rateToIP = telegramsFromKnx.get(objInst - 1).average();
				info.append(format("\tKNX => IP: sent %d, overflow %d [msgs], %d [msgs/min]%n", toIP, overflowIP, rateToIP));

				final var connections = server.dataConnections(c.getServiceContainer());
				connections.forEach((addr, client) -> info.append(format("\t%s, connected since %s%n",
						client, client.connectedSince())));
			}
			catch (final Exception e) {
				logger.error("gathering stat for service container {}", c.getName(), e);
			}
		}
		return info.toString();
	}

	private void replayPendingSubnetEvents()
	{
		for (final Entry<KNXnetIPConnection, ServiceContainer> entry : waitingForReplay.entrySet()) {
			final KNXnetIPConnection c = entry.getKey();
			final ServiceContainer svcContainer = entry.getValue();
			final ReplayBuffer<FrameEvent> replayBuffer = subnetEventBuffers.get(svcContainer);
			final Collection<FrameEvent> events = replayBuffer.replay(c);
			logger.warn("previous connection of {} got disrupted => replay {} pending messages", c, events.size());
			events.forEach(fe -> {
				try {
					send(svcContainer, c, fe.getFrame());
				}
				catch (final InterruptedException e) {
					logger.warn("failed to replay frame event", e);
				}
			});
			waitingForReplay.remove(c);
			logger.debug("replay completed for connection {}", c);
		}
	}

	private void launchServer()
	{
		try {
			server.launch();
		}
		catch (final RuntimeException e) {
			logger.error("cannot launch " + friendlyName(), e);
			quit();
			throw e;
		}
	}

	private String friendlyName() {
		try {
			// friendly name property entry is an array of 30 characters
			final var data = server.getInterfaceObjectServer().getProperty(KNXNETIP_PARAMETER_OBJECT, 1,
					PID.FRIENDLY_NAME, 1, 30);
			final String s = new String(data, StandardCharsets.ISO_8859_1);
			final int end = s.indexOf(0);
			return s.substring(0, end == -1 ? data.length : end);
		}
		catch (final KnxPropertyException e) {
			return name;
		}
	}

	private FrameEvent recordFrameEvent;

	private void recordEvent(final SubnetConnector connector, final FrameEvent fe)
	{
		final ReplayBuffer<FrameEvent> buffer = subnetEventBuffers.get(connector.getServiceContainer());
		if (buffer != null) {
			buffer.recordEvent(fe);
			recordFrameEvent = fe;
		}
	}

	private void onClientFrameReceived(final FrameEvent fe) {
		final String s = "server-side";
		final CEMI frame = fe.getFrame();

		final int mc = frame.getMessageCode();
		if (frame instanceof CEMILData) {
			final var ldata = (CEMILData) frame;

			logger.trace("{} {}: {}: {}", s, fe.getSource(), frame,
					DataUnitBuilder.decode(ldata.getPayload(), ldata.getDestination()));

			// we get L-data.ind if client uses routing protocol
			if (mc == CEMILData.MC_LDATA_REQ || mc == CEMILData.MC_LDATA_IND) {
				if (mc == CEMILData.MC_LDATA_REQ) {
					// send confirmation only for .req type
					sendConfirmationFor((KNXnetIPConnection) fe.getSource(), (CEMILData) CEMIFactory.copy(ldata));

					// if routing is active, dispatch .req over routing connection
					final var c = findRoutingConnection().orElse(null);
					if (c != null) {
						logger.debug("dispatch {}->{} using {}", ldata.getSource(), ldata.getDestination(), c);
						try {
							final var ind = CEMIFactory.create(null, null,
									(CEMILData) CEMIFactory.create(CEMILData.MC_LDATA_IND, null, ldata), false, false);
							send(server.getServiceContainers()[0], c, ind);
						}
						catch (KNXFormatException | InterruptedException | RuntimeException e) {
							e.printStackTrace();
						}
					}
				}

				if (ldata.getDestination() instanceof IndividualAddress) {
					final IndividualAddress dst = (IndividualAddress) ldata.getDestination();
					final Optional<SubnetConnector> connector = connectorFor(dst);
					if (connector.isPresent() && localDeviceManagement(connector.get(), ldata))
						return;
					if (connector.isPresent()) {
						final var svcContainer = connector.get().getServiceContainer();

						// check if destination is a client of ours
						final var dataConnections = server.dataConnections(svcContainer);
						for (final var dataEndpoint : dataConnections.values()) {
							if (ldata.getDestination().equals(dataEndpoint.deviceAddress())) {
								try {
									final var ind = CEMIFactory.create(null, null,
											(CEMILData) CEMIFactory.create(CEMILData.MC_LDATA_IND, null, ldata), false, false);
									send(svcContainer, dataEndpoint, ind, true);
								}
								catch (final InterruptedException e) {
									Thread.currentThread().interrupt();
								}
								catch (KNXFormatException | RuntimeException e) {
									e.printStackTrace();
								}
								return;
							}
						}

						// defend our own additional individual addresses when receiving a TL connect.req
						if (DataUnitBuilder.getTPDUService(ldata.getPayload()) == 0x80) {
							final int objectInstance = 1;
							final var addresses = additionalAddresses(objectInstance);
							if (addresses.contains(ldata.getDestination())) {
								// send disconnect
								try {
									final var ind = CEMIFactory.create(dst, ldata.getSource(), (CEMILData) CEMIFactory
											.create(CEMILData.MC_LDATA_IND, new byte[] { (byte) 0x81 }, ldata), false);
									dispatchToServer(connector.get(), ind, fe.id());
								}
								catch (final KNXFormatException e) {
									e.printStackTrace();
								}
								return;
							}
						}
					}
				}

				// see if the frame is also of interest to us, or addressed to us
				final var dst = ldata.getDestination();
				if (dst instanceof GroupAddress && dst.getRawAddress() == 0) {
					deviceListeners.forEach(l -> l.indication(fe));

					// send to all clients except sender
					logger.trace("forward broadcast {} to all tunneling clients (except {})", ldata, ldata.getSource());
					final var svcCont = connectorFor(ldata.getSource()).map(SubnetConnector::getServiceContainer);
					if (svcCont.isPresent()) {
						for (final var conn : serverConnections) {
							final String type = conn.getName().toLowerCase();
							if (type.contains("devmgmt") || type.contains("monitor"))
								continue;
							final var client = (KNXnetIPConnection) fe.getSource();
							if (client == conn)
								continue;

							try {
								final var ind = CEMIFactory.create(null, null,
										(CEMILData) CEMIFactory.create(CEMILData.MC_LDATA_IND, null, ldata), false, false);
								send(svcCont.get(), conn, ind, true);
							}
							catch (final InterruptedException e) {
								Thread.currentThread().interrupt();
							}
							catch (KNXFormatException | RuntimeException e) {
								e.printStackTrace();
							}
						}
					}
				}
				else if (dst instanceof IndividualAddress) {
					final var ia = (IndividualAddress) dst;
					final Optional<SubnetConnector> connector = connectorFor(ia);
					if (connector.isPresent()) {
						final IndividualAddress localInterface = connector.get().getServiceContainer()
								.getMediumSettings().getDeviceAddress();
						if (ldata.getDestination().equals(localInterface)) {
							deviceListeners.forEach(l -> l.indication(fe));
							return;
						}
					}
				}

				final CEMILData send = adjustHopCount(ldata);
				if (send != null)
					dispatchToSubnets(send, fe.systemBroadcast());

				return;
			}
		}
		else if (mc == CEMIDevMgmt.MC_PROPREAD_REQ || mc == CEMIDevMgmt.MC_PROPWRITE_REQ || mc == CEMIDevMgmt.MC_RESET_REQ) {
			logger.trace("{} {}: {}", s, fe.getSource(), frame);

			final var securityControl = fe.security().orElse(SecurityControl.Plain);
			doDeviceManagement((KNXnetIPConnection) fe.getSource(), (CEMIDevMgmt) frame, securityControl);
			return;
		}

		logger.warn("received {} {} - ignored", s, frame);
	}

	private void onSubnetFrameReceived(final FrameEvent fe) {
		final String s = "subnet";
		final CEMI frame = fe.getFrame();

		if (frame instanceof CEMILData) {
			final var ldata = (CEMILData) frame;
			logger.trace("{} {}: {}: {}", s, fe.getSource(), frame,
					DataUnitBuilder.decode(ldata.getPayload(), ldata.getDestination()));

			if (frame.getMessageCode() == CEMILData.MC_LDATA_IND) {
				final SubnetConnector connector = getSubnetConnector((String) fe.getSource());

				// check if frame is addressed to us
				if (connector != null) {
					final var containerAddr = connector.getServiceContainer().getMediumSettings().getDeviceAddress();
					if (ldata.getDestination().equals(containerAddr)) {
						// with a usb interface, device is always our own address, so we always exclude it for now
						if (connector.getInterfaceType().equals("usb"))
							logger.debug("received from subnet using usb interface {}, don't intercept frame",
									connector.getName());
						else {
							deviceListeners.forEach(l -> l.indication(fe));
							return;
						}
					}
				}

				final CEMILData send = adjustHopCount(ldata);
				if (send == null)
					return;
				if (connector != null) {
					recordEvent(connector, fe);
					dispatchToServer(connector, send, fe.id());
				}

				dispatchToOtherSubnets(send, connector, false);
				return;
			}
		}
		else if (frame instanceof CEMIBusMon) {
			logger.trace("{} {}: {}", s, fe.getSource(), frame);

			final SubnetConnector connector = getSubnetConnector((String) fe.getSource());
			if (connector == null)
				return;
			recordEvent(connector, fe);

			for (final var conn : serverConnections) {
				// routing does not support busmonitor mode
				if (!(conn instanceof KNXnetIPRouting)) {
					try {
						send(connector.getServiceContainer(), conn, frame);
					}
					catch (final InterruptedException e) {}
				}
			}
			return;
		}

		logger.warn("received {} {} - ignored", s, frame);
	}

	private void sendConfirmationFor(final KNXnetIPConnection c, final CEMILData f) {
		CompletableFuture.runAsync(() -> {
			try {
				// TODO check for reasons to send negative L-Data.con
				final boolean error = false;
				logger.trace("send positive cEMI L_Data.con");
				c.send(createCon(f.getPayload(), f, error), WaitForAck);
			}
			catch (final Exception e) {
				throw new CompletionException(e);
			}
		}).exceptionally(t -> {
			logger.error("sending on {} failed: {} ({}->{} L_Data.con {})", c, t.getCause().getMessage(),
					f.getSource(), f.getDestination(), DataUnitBuilder.decode(f.getPayload(), f.getDestination()));
			return null;
		});
	}

	private static CEMI createCon(final byte[] data, final CEMILData original, final boolean error)
		throws KNXFormatException
	{
		if (original instanceof CEMILDataEx) {
			// since we don't use the error flag, simply always create positive .con using the cemi factory
			return CEMIFactory.create(CEMILData.MC_LDATA_CON, null, original);

//			final CEMILDataEx con = new CEMILDataEx(CEMILData.MC_LDATA_CON, original.getSource(),
//					original.getDestination(), data, original.getPriority(), error);
//			final List<AddInfo> l = ((CEMILDataEx) original).getAdditionalInfo();
//			for (final Iterator<AddInfo> i = l.iterator(); i.hasNext();) {
//				final CEMILDataEx.AddInfo info = i.next();
//				con.addAdditionalInfo(info.getType(), info.getInfo());
//			}
//			return con;
		}
		return new CEMILData(CEMILData.MC_LDATA_CON, original.getSource(),
				original.getDestination(), data, original.getPriority(), error);
	}

	// Using the sending link for identification does not always work,
	// see listener indication for the reason of using the container name
	private SubnetConnector getSubnetConnector(final String containerName)
	{
		for (final Iterator<SubnetConnector> i = connectors.iterator(); i.hasNext();) {
			final SubnetConnector b = i.next();
			if (b.getServiceContainer().getName().equals(containerName))
				return b;
		}
		logger.error("dispatch to server: no subnet connector found!");
		return null;
	}

	private void dispatchToOtherSubnets(final CEMILData f, final SubnetConnector exclude, final boolean systemBroadcast)
	{
		if (f.getDestination() instanceof IndividualAddress) {
			// deal with medium independent default individual address
			if (f.getDestination().getRawAddress() == 0xffff) {
				logger.trace("default individual address, dispatch to all active KNX subnets");
				for (final SubnetConnector subnet : connectors) {
					if (subnet.getServiceContainer().isActivated() && isNetworkLink(subnet))
						send(subnet, f);
				}
				return;
			}
			final KNXNetworkLink lnk = findSubnetLink((IndividualAddress) f.getDestination());
			if (lnk == null) {
				logger.warn("no subnet configured for destination " + f.getDestination() + " (received "
						+ DataUnitBuilder.decode(f.getPayload(), f.getDestination())
						+ " from " + f.getSource() + ")");
				return;
			}
			if (exclude != null && lnk.equals(exclude.getSubnetLink()))
				logger.trace("dispatching to KNX subnets: exclude subnet " + exclude.getName());
			else
				connectorFor((IndividualAddress) f.getDestination()).ifPresent(subnet -> send(subnet, f));
		}
		else {
			final int raw = f.getDestination().getRawAddress();
			for (final SubnetConnector subnet : connectors) {
				if (subnet.getServiceContainer().isActivated() && !subnet.equals(exclude))
					dispatchToSubnet(subnet, f, raw, systemBroadcast);
				else if (subnet.equals(exclude))
					logger.trace("dispatching to KNX subnets: exclude subnet " + exclude.getName());
			}
		}
	}

	private void dispatchToSubnets(final CEMILData f, final boolean systemBroadcast)
	{
		dispatchToOtherSubnets(f, null, systemBroadcast);
	}

	private void dispatchToSubnet(final SubnetConnector subnet, final CEMILData f, final int rawAddress,
		final boolean systemBroadcast)
	{
		final int objinst = objectInstance(subnet);
		if (f.getDestination() instanceof GroupAddress && rawAddress > 0 && rawAddress <= 0x6fff) {
			// get forwarding settings for group destination address
			final int value = getPropertyOrDefault(ROUTER_OBJECT, objinst, PID.MAIN_LCGROUPCONFIG, 3);
			final int subGroupAddressConfig = value & 0x03;
			if (subGroupAddressConfig == 2) {
				logger.debug("no frames shall be routed to subnet {} - discard {}", subnet.getName(), f);
				return;
			}
			final GroupAddress d = (GroupAddress) f.getDestination();
			if (subGroupAddressConfig == 3 && !inGroupAddressTable(d, objinst)) {
				logger.info("destination {} not in {} group address table - discard {}", d, subnet.getName(), f);
				return;
			}
		}

		if (!isNetworkLink(subnet))
			return;
		final CEMILData ldata = f;
		if (systemBroadcast) {
			if (!isIpSystemBroadcast(objinst, f)) {
				logger.warn("cEMI in IP system broadcast not qualified for subnet broadcast: {}", f);
				return;
			}
			// std frames have the SB flag already removed when adjusting the hop count
			if (f instanceof CEMILDataEx) {
				final CEMILDataEx cemilDataEx = (CEMILDataEx) f;
				cemilDataEx.setBroadcast(true);
			}
		}
		send(subnet, ldata);
	}

	// ensure we have a network link open (and no monitor link)
	private boolean isNetworkLink(final SubnetConnector subnet)
	{
		AutoCloseable link = subnet.getSubnetLink();
		if (link instanceof Link)
			link = ((Link<?>) link).target();
		if (!(link instanceof KNXNetworkLink)) {
			final IndividualAddress addr = subnet.getServiceContainer().getMediumSettings().getDeviceAddress();
			logger.warn("cannot dispatch to KNX subnet {}: {}", addr, link == null ? "no subnet connection" : link);
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
			if (subnetMask.getLine() == 0 || subnetMask.getLine() == addr.getLine()) {
				// address does match the mask
				return true;
			}
		}
		return false;
	}

	private KNXNetworkLink findSubnetLink(final IndividualAddress dst)
	{
		for (final Iterator<SubnetConnector> i = connectors.iterator(); i.hasNext();) {
			final SubnetConnector b = i.next();
			final ServiceContainer c = b.getServiceContainer();
			if (c.isActivated()) {
				final IndividualAddress subnet = c.getMediumSettings().getDeviceAddress();
				if (matchesSubnet(dst, subnet)) {
					if (!isNetworkLink(b))
						break;
					final KNXNetworkLink link = (KNXNetworkLink) b.getSubnetLink();
					logger.trace("dispatch to KNX subnet {} ({} in service container '{}')",
							subnet, link.getName(), b.getName());
					// assuming a proper address assignment of area/line coupler
					// addresses, this has to be the correct knx subnet link
					return link;
				}
				logger.trace("subnet=" + subnet + " dst=" + dst);
			}
		}
		return null;
	}

	private void dispatchToServer(final SubnetConnector subnet, final CEMILData f, final long eventId)
	{
		final ServiceContainer sc = subnet.getServiceContainer();
		try {
			if (f.getDestination() instanceof IndividualAddress) {
				final IndividualAddress localInterface = sc.getMediumSettings().getDeviceAddress();

				final var connections = server.dataConnections(sc);
				// 1. look for client tunneling connection with matching assigned address
				KNXnetIPConnection c = findConnection((IndividualAddress) f.getDestination());
				if (c != null) {
					logger.debug("dispatch {}->{} using {}", f.getSource(), f.getDestination(), c);
					send(sc, c, f);
				}
				// 2. workaround for usb interfaces: allow assigning additional addresses to client connections,
				// even though we always have the same destination (i.e., the address of the usb interface)
				else if (subnet.getInterfaceType().equals("usb")
						&& f.getDestination().equals(localInterface)) {
					for (final var entry : connections.entrySet()) {
						final var connection = entry.getValue();
						final IndividualAddress assignedAddress = connection.deviceAddress();
						// skip devmgmt connections
						if (assignedAddress != null) {
							logger.debug("dispatch {}->{} using {}", f.getSource(), assignedAddress, connection);
							send(sc, connection, CEMIFactory.create(null, assignedAddress, f, false));
						}
					}
					// also dispatch via routing as-is
					c = findRoutingConnection().orElse(null);
					if (c != null) {
						logger.debug("dispatch {}->{} using {}", f.getSource(), f.getDestination(), c);
						send(sc, c, f);
					}
				}
				// 3. look for activated client-side routing
				else if ((c = findRoutingConnection().orElse(null)) != null) {
					logger.debug("dispatch {}->{} using {}", f.getSource(), f.getDestination(), c);
					send(sc, c, f);
				}
				else {
					logger.warn("no active KNXnet/IP connection for destination {}, dispatch {}->{} to all server-side"
							+ " connections", f.getDestination(), f.getSource(), f.getDestination());
					for (final var conn : serverConnections)
						send(sc, conn, f);
				}
			}
			else {
				// group destination address
				final int raw = f.getDestination().getRawAddress();
				if (raw <= 0x6fff) {
					final int objinst = objectInstance(subnet);
					// check if forwarding requests us to block all frames
					final int value = getPropertyOrDefault(ROUTER_OBJECT, objinst, PID.SUB_LCGROUPCONFIG, 3);
					final int mainGroupAddressConfig = value & 0x03;
					if (mainGroupAddressConfig == 2) {
						logger.debug("no frames shall be routed from subnet {} - discard {}", subnet.getName(), f);
						return;
					}
					// check if forwarding requests us to use the filter table
					if (mainGroupAddressConfig == 3 && raw != 0
							&& !inGroupAddressTable((GroupAddress) f.getDestination(), objinst)) {
						logger.warn(f + ", destination not in group address table - throw away");
						return;
					}

					final KNXnetIPConnection routing = findRoutingConnection().orElse(null);
					if (routing != null && isSubnetBroadcast(objinst, f)) {
						logger.info("forward as IP system broadcast {}", f);
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

						final var sentOnNetif = new HashSet<NetworkInterface>();
						for (final var conn : serverConnections) {
							if (conn instanceof KNXnetIPRouting) {
								final KNXnetIPRouting rc = (KNXnetIPRouting) conn;
								if (sentOnNetif.add(rc.networkInterface()))
									send(sc, rc, bcast, false);
							}
						}
						return;
					}
				}

				logger.debug("dispatch {}->{} to all server-side connections", f.getSource(), f.getDestination());
				for (final var conn : serverConnections) {
					final String type = conn.getName().toLowerCase();
					if (type.contains("devmgmt"))
						continue;
					// if we have a bus monitoring connection, but a subnet connector does not support busmonitor mode,
					// we serve that connection by converting cEMI L-Data -> cEMI BusMon
					final boolean monitoring = type.contains("monitor");
					final CEMI send = monitoring ? convertToBusmon(f, eventId, subnet) : f;
					try {
						send(sc, conn, send);
					}
					catch (final KNXIllegalArgumentException e) {
						// Occurs, for example, if we serve a management connection which expects only cEMI device mgmt
						// frames. Catch here, so we can continue serving other open connections.
						logger.warn("frame not accepted by {} ({}): {}", conn.getName(), e.getMessage(), send, e);
					}
				}
			}
		}
		catch (KnxPropertyException | InterruptedException e) {
			logger.error("send to server-side failed for " + f.toString(), e);
		}
	}

	private KNXnetIPConnection findConnection(final IndividualAddress dst) {
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
	private static final int SecureService = 0b1111110001;

	private static final int SecureSyncResponse = 3;

	private static final int pidIpSbcControl = 120;

	// checks if received subnet frame qualifies as IP system broadcast
	private boolean isSubnetBroadcast(final int objInstance, final CEMILData f) {
		if (f.getDestination().getRawAddress() != 0)
			return false;

		final int sbc = getPropertyOrDefault(InterfaceObject.ROUTER_OBJECT, objInstance, pidIpSbcControl, 0);
		if (sbc == 0)
			return false;

		return RoutingSystemBroadcast.isSystemBroadcast(f);
	}

	// checks if received server-side frame qualifies as subnet broadcast
	private boolean isIpSystemBroadcast(final int objInstance, final CEMILData f) {
		final int sbc = getPropertyOrDefault(InterfaceObject.ROUTER_OBJECT, objInstance, pidIpSbcControl, 0);
		// NYI if disabled, still check if sysbcast, and handle like IP device
		if (sbc == 0)
			return false;

		final byte[] tpdu = f.getPayload();
		final ByteBuffer asdu = ByteBuffer.wrap(DataUnitBuilder.extractASDU(tpdu));
		final int svc = DataUnitBuilder.getAPDUService(tpdu);
		switch (svc) {
		case SystemNetworkParamResponse:
			return asdu.getShort() == InterfaceObject.DEVICE_OBJECT && (asdu.getShort() >> 4) == PID.SERIAL_NUMBER
					&& asdu.get() == 1; // TODO toolaccess bit
		case SecureService: // we look for sync response, and require tool access, system broadcast, A+C
			final int scf = asdu.get() & 0xff;
			final boolean toolAccess = (scf & 128) == 128;
			final int algorithmId = (scf >> 4) & 0x7;
			final boolean systemBroadcast = (scf & 0x8) == 0x8;
			final int service = scf & 0x3;
			return service == SecureSyncResponse && toolAccess && systemBroadcast && algorithmId == 1;
		}
		return false;
	}

	private Optional<KNXnetIPConnection> findRoutingConnection()
	{
		return serverConnections.stream().filter(KNXnetIPRouting.class::isInstance).findAny();
	}

	// check whether we have to slow down or pause sending for routing flow control
	private void applyRoutingFlowControl(final KNXnetIPConnection c) throws InterruptedException
	{
		if (!(c instanceof KNXnetIPRouting) || routingBusyCounter.get() == 0)
			return;

		// we have to loop because a new arrival of routing busy might update timings
		while (true) {
			final Instant now = Instant.now();
			final long sleep = Duration.between(now, pauseSendingUntil).toMillis();
			if (sleep > 0) {
				logger.info("applying routing flow control for {}, wait {} ms ...",
						c.getRemoteAddress().getAddress().getHostAddress(), sleep);
				Thread.sleep(sleep);
			}
			else if (now.isBefore(throttleUntil)) {
				Thread.sleep(5);
				break;
			}
			else
				break;
		}
	}

	private void send(final ServiceContainer svcContainer, final KNXnetIPConnection c, final CEMI f)
			throws InterruptedException {
		send(svcContainer, c, f, true);
	}

	private void send(final ServiceContainer svcContainer, final KNXnetIPConnection c, final CEMI f,
		final boolean applyRoutingFlowControl) throws InterruptedException {
		if (applyRoutingFlowControl)
			applyRoutingFlowControl(c);
		final int oi = objectInstance(svcContainer.getName());
		try {
			c.send(f, WaitForAck);
			setNetworkState(oi, false, false);
			incMsgTransmitted(oi, false);

			final ReplayBuffer<FrameEvent> buffer = subnetEventBuffers.get(svcContainer);
			if (buffer != null)
				buffer.completeEvent(c, recordFrameEvent);
		}
		catch (final KNXTimeoutException e) {
			logger.error("sending on {} failed: {} ({})", c, e.getMessage(), f.toString());
			setNetworkState(oi, false, true);
		}
		catch (final KNXConnectionClosedException e) {
			logger.debug("sending on {} failed: connection closed", c);
		}
	}

	private void send(final SubnetConnector subnet, final CEMILData f)
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
			final IndividualAddress source = usb ? new IndividualAddress(0) : null;

			// we can't forward secure services if we change the source address
			if (usb) {
				final var subnetAddress = subnet.getServiceContainer().getMediumSettings().getDeviceAddress();
				if (!f.getSource().equals(subnetAddress) && SecureApplicationLayer.isSecuredService(f)) {
					logger.warn("{}->{} source address mismatch: can't forward secure service to {}", f.getSource(),
							f.getDestination(), subnet.getName());
					return;
				}
			}

			// adjust .ind: on every KNX subnet link (except routing links) we require an L-Data.req
			// also ensure repeat flag is set/cleared according to medium
			if (mc == CEMILData.MC_LDATA_IND && !routing)
				ldata = CEMIFactory.create(source, null, (CEMILData) CEMIFactory.create(CEMILData.MC_LDATA_REQ, null, f), false, true);
			// adjust .req: on KNX subnets with KNXnet/IP routing, we require an L-Data.ind
			else if (mc == CEMILData.MC_LDATA_REQ && routing)
				ldata = CEMIFactory.create(null, null, (CEMILData) CEMIFactory.create(CEMILData.MC_LDATA_IND, null, f), false, false);
			else if (usb)
				ldata = CEMIFactory.create(source, null, f, false);
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
							send = CEMIFactory.create(null, null, send, true);
						((CEMILDataEx) send).setBroadcast(false);
						logger.debug("{} changed to system broadcast", DataUnitBuilder.decodeAPCI(svc));
					}
				}
			}

			link.send(send, true);
			setNetworkState(oi, true, false);
			incMsgTransmitted(oi, true);
		}
		catch (final KNXTimeoutException e) {
			setNetworkState(oi, true, true);
			logger.warn("timeout sending to {}: {}", f.getDestination(), e.getMessage());
		}
		catch (final KNXFormatException | KNXLinkClosedException e) {
			logger.error("error sending to {} on subnet {}: {}", f.getDestination(), link.getName(), e.getMessage());
			if (e.getCause() != null)
				logger.info("{}, caused by:", e.toString(), e.getCause());
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

	// implements KNX group address filtering using IOS addresstable object
	private boolean inGroupAddressTable(final GroupAddress addr, final int objectInstance)
	{
		final InterfaceObjectServer ios = server.getInterfaceObjectServer();
		try {
			final byte[] data = ios.getProperty(InterfaceObject.ADDRESSTABLE_OBJECT,
					objectInstance, PropertyAccess.PID.TABLE, 0, 1);
			final int elems = (data[0] & 0xff) << 8 | (data[1] & 0xff);

			// not sure if this is some common behavior: if property exists with zero length, allow every address
			if (elems == 0)
				return true;

			final byte[] addrTable = ios.getProperty(InterfaceObject.ADDRESSTABLE_OBJECT,
					objectInstance, PropertyAccess.PID.TABLE, 1, elems);
			final byte hi = (byte) (addr.getRawAddress() >> 8);
			final byte lo = (byte) addr.getRawAddress();
			for (int i = 0; i < addrTable.length; i += 2)
				if (hi == addrTable[i] && lo == addrTable[i + 1])
					return true;
			return false;
		}
		catch (final KnxPropertyException e) {
			// when in doubt, pass the message on...
			return true;
		}
	}

	private List<IndividualAddress> additionalAddresses(final int objectInstance) {
		final List<IndividualAddress> list = new ArrayList<>();
		try {
			final byte[] data = server.getInterfaceObjectServer().getProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance,
					PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 1, Integer.MAX_VALUE);
			final ByteBuffer buf = ByteBuffer.wrap(data);
			while (buf.hasRemaining())
				list.add(new IndividualAddress(buf.getShort() & 0xffff));
		}
		catch (final KnxPropertyException e) {
			logger.warn(e.getMessage());
		}
		return list;
	}

	private boolean checkPropertyAccess(final int objectType, final int objectInstance, final int pid,
			final boolean read, final SecurityControl securityCtrl) {
		final var ios = server.getInterfaceObjectServer();
		boolean securityMode = false;
		try {
			securityMode = ios.getProperty(SECURITY_OBJECT, objectInstance, pid, 1, 1)[0] == 1;
		}
		catch (final KnxPropertyException noSecurityObject) {}
		final boolean allowed = AccessPolicies.checkPropertyAccess(objectType, pid, read, securityMode, securityCtrl);
		if (!allowed)
			logger.info("deny property {} access to {}({})|{} ({}{})", read ? "read" : "write", objectType,
					objectInstance, pid, PropertyClient.getObjectTypeName(objectType), propertyName(objectType, pid));
		return allowed;
	}

	private String propertyName(final int objectType, final int pid) {
		final var ios = server.getInterfaceObjectServer();
		final var key = pid <= 50 ? new PropertyKey(pid) : new PropertyKey(objectType, pid);
		final var property = ios.propertyDefinitions().get(key);
		if (property != null && !property.getName().isEmpty())
			return " - " + property.getName();
		return "";
	}

	private void doDeviceManagement(final KNXnetIPConnection c, final CEMIDevMgmt f, final SecurityControl securityControl)
	{
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
					logger.debug(e.getMessage());
					data = new byte[] { (byte) e.errorCode() };
					elems = 0;
				}
			}

			final int con = read ? CEMIDevMgmt.MC_PROPREAD_CON : CEMIDevMgmt.MC_PROPWRITE_CON;
			final CEMIDevMgmt dm = read || data != null ? new CEMIDevMgmt(con, f.getObjectType(),
					f.getObjectInstance(), f.getPID(), f.getStartIndex(), elems, data)
					: new CEMIDevMgmt(con, f.getObjectType(), f.getObjectInstance(), f.getPID(),
							f.getStartIndex(), elems);
			try {
				c.send(dm, WaitForAck);
			}
			catch (KNXException | InterruptedException e) {
				logger.error("sending on {} failed: {} ({})", c, e.getMessage(), f.toString());
			}
		}
		else if (mc == CEMIDevMgmt.MC_RESET_REQ) {
			// handle reset.req here since we have the connection name for logging
			logger.info("received reset request " + c.getName() + " - restarting " + server.getName());
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
		@SuppressWarnings("unchecked")
		KNXNetworkLink link = (KNXNetworkLink) ((Link<KNXNetworkLink>) connector.getSubnetLink()).target();
		if (link == null)
			throw new KNXException("no open subnet link for " + connector.getName());
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
		if (connector.getInterfaceType().equals("usb") && ldata.getDestination().equals(localInterface)) {
			final byte[] data = ldata.getPayload();
			logger.debug("request for {}, use USB Local-DM", localInterface);
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
					dispatchToServer(connector, ack, 0);
				}

				final LocalDeviceManagementUsb ldm = localDevMgmtAdapter(connector);
				if (svc == DeviceDescRead) {
					final byte[] tpdu = DataUnitBuilder.createAPDU(DeviceDescRes, dd0.toByteArray());
					tpdu[0] |= data[0];
					final CEMILData f = new CEMILDataEx(CEMILData.MC_LDATA_IND,
							(IndividualAddress) ldata.getDestination(), ldata.getSource(), tpdu, Priority.LOW);
					dispatchToServer(connector, f, 0);
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
								response[3] |= property.getPDT();
							response[response.length - 2] = 1;
						}
						catch (final KNXRemoteException pidNotFound) {
							response = new byte[] { (byte) objIndex, (byte) pid, (byte) propIndex, (byte) 0, 0, 0, 0 };
						}
						logger.debug("Local-DM {} read property description {}|{} (idx {}): {}", localInterface,
								objIndex, pid, propIndex, DataUnitBuilder.toHex(response, " "));
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
							logger.debug("Local-DM {} read property values {}|{} (start {}, {} elements): {}",
									localInterface, objIndex, pid, start, elements, DataUnitBuilder.toHex(propData, " "));
						}
						catch (final KNXRemoteException e) {
							response = new byte[] { (byte) objIndex, (byte) pid, (byte) (start >> 8), (byte) start };
						}
					}
					final int svcResponse = svc == PropertyDescRead ? PropertyDescResponse : PropertyResponse;
					final byte[] tpdu = DataUnitBuilder.createAPDU(svcResponse, response);
					if (connected)
						tpdu[0] |= dataConnectedTsdu | (rcvSeq << 2);
					final CEMILData f = new CEMILDataEx(CEMILData.MC_LDATA_IND,
							(IndividualAddress) ldata.getDestination(), ldata.getSource(), tpdu, Priority.LOW);
					dispatchToServer(connector, f, 0);
					return true;
				}
			}
			catch (KNXException | InterruptedException e) {
				logger.error("KNX USB local device management with {}", connector.getName(), e);
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
		if (!connector.getInterfaceType().equals("usb"))
			return;
		final IndividualAddress configured = svcCont.getMediumSettings().getDeviceAddress();
		final LocalDeviceManagementUsb ldm = localDevMgmtAdapter(connector);
		final byte[] subnet = ldm.getProperty(deviceObject, objectInstance, PID.SUBNET_ADDRESS, 1, 1);
		final byte[] device = ldm.getProperty(deviceObject, objectInstance, PID.DEVICE_ADDRESS, 1, 1);
		final IndividualAddress current = new IndividualAddress(new byte[] { subnet[0], device[0] });
		if (!current.equals(configured)) {
			logger.warn("KNX address mismatch with USB interface: currently {}, configured {} -> assigning {}", current,
					configured, configured);
			final byte[] addr = configured.toByteArray();
			ldm.setProperty(deviceObject, objectInstance, PID.SUBNET_ADDRESS, 1, 1, addr[0]);
			ldm.setProperty(deviceObject, objectInstance, PID.DEVICE_ADDRESS, 1, 1, addr[1]);
		}
	}

	private void incMsgTransmitted(final int objinst, final boolean toKnxNetwork)
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
			logger.error("on increasing message transmit counter", e);
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
			logger.warn("queue overflow counter reached maximum of 0xffff, not incremented");
			return;
		}
		++overflow;
		final var direction = toKnxNetwork ? "IP => KNX" : "KNX => IP";
		logger.warn("queue overflow {}, counter incremented to {}", direction, overflow);
		try {
			server.getInterfaceObjectServer().setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance, pid, 1, 1,
					bytesFromWord(overflow));
		}
		catch (final KnxPropertyException e) {
			logger.error("on increasing queue overflow counter", e);
		}
	}

	// returns null to indicate a discarded frame
	private CEMILData adjustHopCount(final CEMILData msg)
	{
		int count = msg.getHopCount();
		// if counter == 0, discard frame
		if (count == 0) {
			logger.warn("hop count 0, discard frame {}->{}", msg.getSource(), msg.getDestination());
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
	private void setNetworkState(final int objectInstance, final boolean knxNetwork, final boolean faulty)
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
			logger.error("on modifying network fault in device state", e);
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
		if (copy instanceof CEMILDataEx) {
			final CEMILDataEx ex = (CEMILDataEx) copy;
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
