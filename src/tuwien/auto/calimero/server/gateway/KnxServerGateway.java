/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2017 B. Malinowsky

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

import static tuwien.auto.calimero.device.ios.InterfaceObject.KNXNETIP_PARAMETER_OBJECT;
import static tuwien.auto.calimero.knxnetip.KNXnetIPConnection.BlockingMode.WaitForAck;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.cemi.CEMIBusMon;
import tuwien.auto.calimero.cemi.CEMIDevMgmt;
import tuwien.auto.calimero.cemi.CEMIFactory;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.cemi.CEMILDataEx;
import tuwien.auto.calimero.cemi.CEMILDataEx.AddInfo;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KnxPropertyException;
import tuwien.auto.calimero.device.ios.PropertyEvent;
import tuwien.auto.calimero.knxnetip.KNXConnectionClosedException;
import tuwien.auto.calimero.knxnetip.KNXnetIPConnection;
import tuwien.auto.calimero.knxnetip.KNXnetIPRouting;
import tuwien.auto.calimero.knxnetip.LostMessageEvent;
import tuwien.auto.calimero.knxnetip.RoutingBusyEvent;
import tuwien.auto.calimero.knxnetip.RoutingListener;
import tuwien.auto.calimero.knxnetip.servicetype.RoutingBusy;
import tuwien.auto.calimero.link.Connector.Link;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.KNXNetworkLinkIP;
import tuwien.auto.calimero.link.KNXNetworkLinkTpuart;
import tuwien.auto.calimero.link.KNXNetworkMonitor;
import tuwien.auto.calimero.link.NetworkLinkListener;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.log.LogService.LogLevel;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.server.VirtualLink;
import tuwien.auto.calimero.server.knxnetip.DefaultServiceContainer;
import tuwien.auto.calimero.server.knxnetip.KNXnetIPServer;
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
 * {@link InterfaceObject#ADDRESSTABLE_OBJECT} in the Interface Object Server. Currently, the group
 * address filter table applies only for KNX messages in the direction from a KNX subnet to a server
 * side client.
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

	// Connection listener for accepted KNXnet/IP connections
	private final class ConnectionListener implements RoutingListener
	{
		final ServiceContainer sc;
		final String name;
		final IndividualAddress addr;

		private Instant lastRoutingBusy = Instant.EPOCH;
		// avoid null, assign bogus future
		private volatile ScheduledFuture<?> decrement = busyCounterDecrementor.schedule(() -> {}, 0, TimeUnit.SECONDS);

		ConnectionListener(final ServiceContainer svcContainer, final String connectionName,
			final IndividualAddress device)
		{
			sc = svcContainer;
			// same as calling ((KNXnetIPConnection) getSource()).getName()
			name = connectionName;
			addr = device;
		}

		@Override
		public void frameReceived(final FrameEvent e)
		{
			synchronized (KnxServerGateway.this) {
				if (ipEvents.size() < maxEventQueueSize) {
					ipEvents.add(e);
					KnxServerGateway.this.notifyAll();
					synchronized (dispatcher) {
						dispatcher.notify();
					}
				}
				else
					incMsgQueueOverflow(true);
			}
		}

		@Override
		public void lostMessage(final LostMessageEvent e)
		{
			logger.warn("routing message loss of KNXnet/IP router " + e.getSender()
					+ " increased to a total of " + e.getLostMessages());
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
			LogService.log(logger, level, "routing busy from device {}, wait time {} ms{}", e.sender(), e.waitTime(),
					e.get().isKnxFault() ? " (reason: KNX network fault)" : "");

			// increment random wait scaling iff >= 10 ms have passed since the last counted routing busy
			if (now.isAfter(lastRoutingBusy.plusMillis(10))) {
				lastRoutingBusy = now;
				routingBusyCounter.incrementAndGet();
				update = true;
			}

			if (!update)
				return;

			final double rand = new Random().nextDouble();
			final long randomWait = Math.round(rand * routingBusyCounter.get() * randomWaitScale.toMillis());

			// invariant on instants: throttle >= pause sending >= current wait
			pauseSendingUntil = currentWaitUntil.plusMillis(randomWait);
			final long throttle = routingBusyCounter.get() * throttleScale.toMillis();
			throttleUntil = pauseSendingUntil.plusMillis(throttle);

			final long continueIn = Duration.between(Instant.now(), pauseSendingUntil).toMillis();
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
			logger.debug("remove {} ({})", name, e.getReason());
			serverConnections.remove(e.getSource());
			serverDataConnections.remove(addr);
			if (e.getInitiator() == CloseEvent.CLIENT_REQUEST) {
				final KNXnetIPConnection c = (KNXnetIPConnection) e.getSource();
				subnetEventBuffers.computeIfPresent(sc, (sc, rb) -> { rb.remove(c); return rb; });
			}
		}
	}

	private final class KNXnetIPServerListener implements ServerListener
	{
		@Override
		public boolean acceptDataConnection(final ServiceContainer svcContainer,
			final KNXnetIPConnection conn, final IndividualAddress assignedDeviceAddress,
			final boolean networkMonitor)
		{
			final SubnetConnector connector = getSubnetConnector(svcContainer.getName());
			if (connector == null)
				return false;
			final String subnetType = connector.getInterfaceType();
			final String subnetArgs = connector.getLinkArguments();
			final ServiceContainer serviceContainer = connector.getServiceContainer();
			final KNXMediumSettings settings = serviceContainer.getMediumSettings();

			AutoCloseable subnetLink = connector.getSubnetLink();
			if (subnetLink instanceof Link)
				subnetLink = ((Link<?>) subnetLink).target();
			try {
				if (subnetLink instanceof VirtualLink)
					;
				else if (!networkMonitor && !(subnetLink instanceof KNXNetworkLink)) {
					closeLink(subnetLink);
					connector.openNetworkLink();
				}
				else if (networkMonitor && !(subnetLink instanceof KNXNetworkMonitor)) {
					closeLink(subnetLink);
					connector.openMonitorLink();
				}
			}
			catch (KNXException | InterruptedException e) {
				logger.error("open network link using {} interface {} for {}", subnetType, subnetArgs, settings, e);
				if (e instanceof InterruptedException)
					Thread.currentThread().interrupt();
				return false;
			}

			AutoCloseable unknown = connector.getSubnetLink();
			if (unknown instanceof Link)
				unknown = ((Link<?>) unknown).target();
			// if this is a TP-UART link (not monitor), we do have to tell it the assigned device
			// address, so it can generate the acks on the bus for our clients
			if (unknown instanceof KNXNetworkLinkTpuart) {
				final KNXNetworkLinkTpuart tpuart = (KNXNetworkLinkTpuart) unknown;
				tpuart.addAddress(assignedDeviceAddress);
			}
			conn.addConnectionListener(new ConnectionListener(svcContainer, conn.getName(), assignedDeviceAddress));
			if (assignedDeviceAddress != null)
				serverDataConnections.put(assignedDeviceAddress, conn);
			return true;
		}

		@Override
		public void connectionEstablished(final ServiceContainer svcContainer, final KNXnetIPConnection connection)
		{
			serverConnections.add(connection);

			final InetSocketAddress remote = connection.getRemoteAddress();
			logger.info("established connection to remote " + remote);
			final ReplayBuffer<FrameEvent> buffer = subnetEventBuffers.get(svcContainer);
			if (buffer == null)
				return;
			final int[] portRange = ((DefaultServiceContainer) svcContainer).disruptionBufferPortRange();
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

			// update group address forwarding settings
			if (pe.getPropertyId() == MAIN_LCGRPCONFIG) {
				if (pe.getInterfaceObject().getType() == ROUTER_OBJECT) {
					mainGroupAddressConfig = pe.getNewData()[0] & 0x03;
					logger.info("main-line group address config changed to " + mainGroupAddressConfig);
				}
			}
			else if (pe.getPropertyId() == SUB_LCGRPCONFIG) {
				if (pe.getInterfaceObject().getType() == ROUTER_OBJECT) {
					subGroupAddressConfig = pe.getNewData()[0] & 0x03;
					logger.info("sub-line group address config changed to " + subGroupAddressConfig);
				}
			}
		}

		@Override
		public void onServiceContainerChange(final ServiceContainerEvent sce)
		{
			final int event = sce.getEventType();
			final ServiceContainer sc = sce.getContainer();
			if (event == ServiceContainerEvent.ROUTING_SVC_STARTED) {
				final KNXnetIPConnection conn = sce.getConnection();
				logger.info(sc.getName() + " started " + conn.getName());
				conn.addConnectionListener(new ConnectionListener(sc, conn.getName(), null));
				serverConnections.add(conn);
			}
			else if (event == ServiceContainerEvent.ADDED_TO_SERVER) {
				logger.error("adding service container at runtime not yet implemented");
				// prevent Java unreachable code warning
				if (event != 0)
					return;
				// the following is not working!
				// XXX subnet link and group address table is missing!
				// what is the best way to get them here?
				final SubnetConnector connector = SubnetConnector.newWithInterfaceType(sc, null, null, 1);
				connectors.add(connector);
				connector.setSubnetListener(new SubnetListener(connector.getName()));
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
		public void onResetRequest(final ShutdownEvent se)
		{}

		@Override
		public void onShutdown(final ShutdownEvent se)
		{
			// shutdown is guaranteed to be called before server is shutdown, therefore
			// this flag status is correct
			if (inReset)
				return;
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

	private final class SubnetListener implements NetworkLinkListener
	{
		private final String scid;

		SubnetListener(final String svcContainerId)
		{
			scid = svcContainerId;
		}

		@Override
		public void confirmation(final FrameEvent e)
		{}

		@Override
		public void indication(final FrameEvent e)
		{
			synchronized (KnxServerGateway.this) {
				if (subnetEvents.size() < maxEventQueueSize) {
					// In the dispatching to server side, we rely on having the
					// subnet link in the frame event source stored so to know where the
					// frame came from.
					// But this will not work if the sending link differs from the one
					// stored in this frame event, e.g., when using a buffered link.
					// Therefore, I store the svcContainer in here for re-association.
					subnetEvents.add(new FrameEvent(scid, e.getFrame()));
					KnxServerGateway.this.notify();
				}
				else
					incMsgQueueOverflow(false);
			}
		}

		@Override
		public void linkClosed(final CloseEvent e)
		{
			logger.info("KNX subnet link closed (" + e.getReason() + ")");
		}
	}

	private final String name;
	private final Logger logger;

	private final KNXnetIPServer server;
	// connectors array is not sync'd throughout gateway
	private final List<SubnetConnector> connectors = new ArrayList<>();

	private final Map<IndividualAddress, KNXnetIPConnection> serverDataConnections = Collections
			.synchronizedMap(new HashMap<>());
	private final List<KNXnetIPConnection> serverConnections = Collections.synchronizedList(new ArrayList<>());

	private final int maxEventQueueSize = 200;
	private final List<FrameEvent> ipEvents = new LinkedList<>();
	private final List<FrameEvent> subnetEvents = new LinkedList<>();

	// support replaying subnet events for disrupted tunneling connections
	private final Map<ServiceContainer, ReplayBuffer<FrameEvent>> subnetEventBuffers = new HashMap<>();
	private final Map<KNXnetIPConnection, ServiceContainer> waitingForReplay = new ConcurrentHashMap<>();

	private volatile boolean trucking;
	private volatile boolean inReset;

	// Frame forwarding based on KNX address (AN031)
	// KNX properties to determine address routing and address filtering:
	// located in the Router Object Interface Object (Object Type 6)
	private static final int ROUTER_OBJECT = 6;
	// properties for individual address forwarding
//	private static final int MAIN_LCCONFIG = 52;
//	private static final int SUB_LCCONFIG = 53;
	// properties for group address forwarding
	// MAIN_LCGRPCONFIG/SUB_LCGRPCONFIG bits:
	// Bits 0-1: address handling for addresses <= 0x6fff
	// Bits 2-3: address handling for addresses >= 0x7000
	// Values 0-1:
	// 0 = not used, 1 = route all frames (repeater) (default for addresses >= 0x7000),
	// 2 = block all, 3 = use filter table (default for addresses <= 0x6fff)
	private static final int MAIN_LCGRPCONFIG = 54;
	private static final int SUB_LCGRPCONFIG = 55;

	// forwarding settings to main line for addresses <= 0x6fff
	private int mainGroupAddressConfig = 3;
	// forwarding settings to sub line for addresses <= 0x6fff
	private int subGroupAddressConfig = 3;

	private final Thread dispatcher = new Thread() {
		// threshold for multicasting routing busy msg is 10 incoming routing indications
		private static final int routingBusyMsgThreshold = 10;
		private int ipMsgCount;

		@Override
		public void run()
		{
			try {
				while (trucking) {
					for (FrameEvent event = getIPEvent(); event != null; event = getIPEvent())
						try {
							checkRoutingBusy();
							onFrameReceived(event, true);
						}
						catch (final RuntimeException e) {
							logger.error("on server-side frame event", e);
						}
					synchronized (this) {
						wait();
					}
				}
			}
			catch (final InterruptedException e) {}
		};

		private FrameEvent getIPEvent()
		{
			synchronized (KnxServerGateway.this) {
				return ipEvents.isEmpty() ? null : ipEvents.remove(0);
			}
		}

		private void checkRoutingBusy()
		{
			final Duration observationPeriod = Duration.ofMillis(100);
			// TODO adjust for KNX subnet capacity
			final int maxMsgsPerSecond = 200;

			ipMsgCount++;
			final int msgs;
			synchronized (KnxServerGateway.this) {
				msgs = ipEvents.size();
			}
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

	/**
	 * Creates a new server gateway for the supplied KNXnet/IP server.
	 * <p>
	 * On running this gateway ({@link #run()}), it is ensured the KNXnet/IP server is launched.
	 *
	 * @param gatewayName descriptive name to use for this gateway
	 * @param s KNXnet/IP server representing the server side
	 * @param subnetConnectors list of {@link SubnetConnector} objects, which specify the
	 *        associations between the connections from either side of the gateway
	 */
	public KnxServerGateway(final String gatewayName, final KNXnetIPServer s, final SubnetConnector[] subnetConnectors)
	{
		name = gatewayName;
		server = s;
		server.addServerListener(new KNXnetIPServerListener());
		connectors.addAll(Arrays.asList(subnetConnectors));
		logger = LogService.getLogger("calimero.server.gateway." + name);
		dispatcher.setName(name + " subnet dispatcher");
		for (final Iterator<SubnetConnector> i = connectors.iterator(); i.hasNext();) {
			final SubnetConnector b = i.next();
			b.setSubnetListener(new SubnetListener(b.getName()));
			final ServiceContainer sc = b.getServiceContainer();
			final Duration timeout = ((DefaultServiceContainer) sc).disruptionBufferTimeout();
			if (!timeout.isZero()) {
				final int[] portRange = ((DefaultServiceContainer) sc).disruptionBufferPortRange();
				logger.info("activate \'{}\' disruption buffer on ports [{}-{}], disruption timeout {} s", sc.getName(),
						portRange[0], portRange[1], timeout.getSeconds());
				subnetEventBuffers.put(sc, new ReplayBuffer<>(timeout));
			}
		}

		int value = getPropertyOrDefault(ROUTER_OBJECT, objectInstance, MAIN_LCGRPCONFIG, mainGroupAddressConfig);
		mainGroupAddressConfig = value & 0x03;
		logger.info("main-line group address forward setting set to " + mainGroupAddressConfig);

		value = getPropertyOrDefault(ROUTER_OBJECT, objectInstance, SUB_LCGRPCONFIG, subGroupAddressConfig);
		subGroupAddressConfig = value & 0x03;
		logger.info("sub-line group address forward setting set to " + subGroupAddressConfig);

		// init PID.PRIORITY_FIFO_ENABLED property to non-fifo message queue
		try {
			server.getInterfaceObjectServer().setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance,
					PID.PRIORITY_FIFO_ENABLED, 1, 1, new byte[] { 0 });
		}
		catch (final KnxPropertyException e) {
			logger.warn("failed to set KNX property 'priority fifo enabled' to false", e);
		}
		// init capability list of different routing features
		// bit field: bit 0: Queue overflow counter available
		// 1: Transmitted message counter available
		// 2: Support of priority/FIFO message queues
		// 3: Multiple KNX installations supported
		// 4: Group address mapping supported
		// other bits reserved
		final byte caps = 1 << 0 | 1 << 1 | 1 << 3;
		try {
			server.getInterfaceObjectServer().setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance,
					PID.KNXNETIP_ROUTING_CAPABILITIES, 1, 1, new byte[] { caps });
		}
		catch (final KnxPropertyException e) {
			logger.warn("failed to set KNX property 'KNXnet/IP routing capabilities'", e);
		}
	}

	@Override
	public void run()
	{
		launchServer();
		trucking = true;
		dispatcher.start();
		while (trucking) {
			try {
				// although we possibly run in a dedicated thread so to not delay any
				// other user tasks, be aware that subnet frame dispatching to IP
				// front-end is done in this thread
				for (FrameEvent event = getSubnetEvent(); event != null; event = getSubnetEvent())
					onFrameReceived(event, false);

				// How does reset work:
				// If we receive a reset.req message in the message handler, we set
				// the inReset flag, trigger the server shutdown, and resume here.
				// Check trucking, since someone might have called quit during
				// server shutdown.
				if (inReset && trucking) {
					inReset = false;
					launchServer();
				}

				synchronized (this) {
					if (subnetEvents.isEmpty())
						wait();
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
		synchronized (dispatcher) {
			dispatcher.notify();
		}
	}

	/**
	 * Quits gateway.
	 * <p>
	 * A running KNXnet/IP server is not stopped.
	 */
	public void quit()
	{
		trucking = false;
		synchronized (this) {
			notifyAll();
		}
	}

	/**
	 * Returns the name of this server gateway.
	 * <p>
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

	private synchronized FrameEvent getSubnetEvent()
	{
		replayPendingSubnetEvents();

		if (subnetEvents.isEmpty())
			return null;
		return subnetEvents.remove(0);
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
					logger.error("failed to replay frame event", e);
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
			logger.error("cannot launch " + server.getFriendlyName(), e);
			quit();
			throw e;
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

	private void onFrameReceived(final FrameEvent fe, final boolean fromServerSide)
	{
		final String s = fromServerSide ? "server-side " : "KNX subnet ";
		final CEMI frame = fe.getFrame();

		final boolean trace = logger.isTraceEnabled();
		if (trace)
			logger.trace(s + fe.getSource() + ": " + frame.toString());

		final int mc = frame.getMessageCode();
		if (frame instanceof CEMILData) {
			final CEMILData f = (CEMILData) frame;

			if (trace)
				logger.trace(f.getSource() + "->" + f.getDestination() + ": "
						+ DataUnitBuilder.decode(f.getPayload(), f.getDestination()));

			// we get L-data.ind if client uses routing protocol
			if (fromServerSide && (mc == CEMILData.MC_LDATA_REQ || mc == CEMILData.MC_LDATA_IND)) {
				// send confirmation on .req type
				if (mc == CEMILData.MC_LDATA_REQ) {
					CompletableFuture.runAsync(() -> {
						try {
							// TODO check for reasons to send negative L-Data.con
							final boolean error = false;
							logger.trace("send positive cEMI L_Data.con");
							final KNXnetIPConnection c = (KNXnetIPConnection) fe.getSource();
							c.send(createCon(f.getPayload(), f, error), WaitForAck);
						}
						catch (final Exception e) {
							throw new CompletionException(e);
						}
					}).exceptionally(t -> {
						logger.error("sending L_Data.con for {}",
								DataUnitBuilder.decode(f.getPayload(), f.getDestination()), t.getCause());
						return null;
					});
				}
				final CEMILData send = adjustHopCount(f);
				if (send != null)
					dispatchToSubnets(send);
			}
			else if (!fromServerSide && mc == CEMILData.MC_LDATA_IND) {
				final CEMILData send = adjustHopCount(f);
				if (send == null)
					return;
				// get connector of that subnet
				final SubnetConnector connector = getSubnetConnector((String) fe.getSource());
				if (connector != null) {
					recordEvent(connector, fe);
					dispatchToServer(connector, send, fe.id());
				}

				dispatchToOtherSubnets(send, connector);
			}
			else {
				final String type = mc == CEMILData.MC_LDATA_CON ? ".con" : " msg code 0x" + Integer.toString(mc, 16);
				logger.warn(s + " L-data" + type + " [" + DataUnitBuilder.toHex(f.toByteArray(), "") + "] - ignored");
			}
		}
		else if (mc == CEMIDevMgmt.MC_PROPREAD_REQ || mc == CEMIDevMgmt.MC_PROPWRITE_REQ
				|| mc == CEMIDevMgmt.MC_RESET_REQ)
			doDeviceManagement((KNXnetIPConnection) fe.getSource(), (CEMIDevMgmt) frame);
		else if (frame instanceof CEMIBusMon) {
			if (fromServerSide) {
				logger.error("received cEMI busmonitor frame by server-side client (unspecified)");
				return;
			}
			final SubnetConnector connector = getSubnetConnector((String) fe.getSource());
			if (connector == null)
				return;
			recordEvent(connector, fe);

			// create temporary array to not block concurrent access during iteration
			for (final KNXnetIPConnection c : serverConnections.toArray(new KNXnetIPConnection[0])) {
				// routing does not support busmonitor mode
				if (!(c instanceof KNXnetIPRouting)) {
					try {
						send(connector.getServiceContainer(), c, frame);
					}
					catch (final InterruptedException e) {}
				}
			}
		}
		else
			logger.warn("received unknown cEMI msg code 0x" + Integer.toString(mc, 16) + " - ignored");
	}

	private static CEMI createCon(final byte[] data, final CEMILData original, final boolean error)
		throws KNXFormatException
	{
		if (original instanceof CEMILDataEx) {
			final CEMILDataEx con = new CEMILDataEx(CEMILData.MC_LDATA_CON, original.getSource(),
					original.getDestination(), data, original.getPriority(), error);
			final List<AddInfo> l = ((CEMILDataEx) original).getAdditionalInfo();
			for (final Iterator<AddInfo> i = l.iterator(); i.hasNext();) {
				final CEMILDataEx.AddInfo info = i.next();
				con.addAdditionalInfo(info.getType(), info.getInfo());
			}
			return con;
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

	private void dispatchToOtherSubnets(final CEMILData f, final SubnetConnector exclude)
	{
		if (f.getDestination() instanceof IndividualAddress) {
			// deal with medium independent default individual address
			if (f.getDestination().getRawAddress() == 0xffff) {
				logger.trace("default individual address, dispatch to all active KNX subnets");
				for (final SubnetConnector subnet : connectors) {
					if (subnet.getServiceContainer().isActivated() && isNetworkLink(subnet)) {
						send((KNXNetworkLink) subnet.getSubnetLink(), f);
						incMsgTransmitted(true);
					}
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
				send(lnk, f);
		}
		else {
			// group destination address, check forwarding settings
			final int raw = f.getDestination().getRawAddress();
			if (raw <= 0x6fff && subGroupAddressConfig == 2)
				return;

			for (final Iterator<SubnetConnector> i = connectors.iterator(); i.hasNext();) {
				final SubnetConnector subnet = i.next();
				if (subnet.getServiceContainer().isActivated() && !subnet.equals(exclude))
					dispatchToSubnet(subnet, f, raw);
				else
					logger.trace("dispatching to KNX subnets: exclude subnet " + exclude.getName());
			}
		}
		incMsgTransmitted(true);
	}

	private void dispatchToSubnets(final CEMILData f)
	{
		dispatchToOtherSubnets(f, null);
	}

	private void dispatchToSubnet(final SubnetConnector subnet, final CEMILData f, final int rawAddress)
	{
		if (rawAddress <= 0x6fff) {
			final GroupAddress d = (GroupAddress) f.getDestination();
			if ((subGroupAddressConfig == 0 || subGroupAddressConfig == 3)
					&& !inGroupAddressTable(d, subnet.getGroupAddressTableObjectInstance())) {
				logger.warn("destination {} not in {} group address table - discard {}", d,
						subnet.getName(), f);
				return;
			}
		}
		if (isNetworkLink(subnet))
			send((KNXNetworkLink) subnet.getSubnetLink(), f);
	}

	// ensure we have a network link open (and no monitor link)
	private boolean isNetworkLink(final SubnetConnector subnet)
	{
		AutoCloseable link = subnet.getSubnetLink();
		if (link instanceof Link)
			link = ((Link<?>) link).target();
		if (!(link instanceof KNXNetworkLink)) {
			final IndividualAddress addr = subnet.getServiceContainer().getMediumSettings().getDeviceAddress();
			logger.warn("cannot dispatch to KNX subnet {}, no network link ({})", addr, link);
			return false;
		}
		return true;
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
					logger.trace("dispatch to KNX subnet {} ({} in service container {})",
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

	private void dispatchToServer(final SubnetConnector subnetConnector, final CEMILData f, final long eventId)
	{
		final ServiceContainer sc = subnetConnector.getServiceContainer();
		try {
			if (f.getDestination() instanceof IndividualAddress) {
				final KNXnetIPConnection c = findServerConnection((IndividualAddress) f.getDestination());
				if (c != null) {
					logger.debug("dispatch {}->{} using {}", f.getSource(), f.getDestination(), c);
					send(sc, c, f);
				}
				else {
					logger.warn("no active KNXnet/IP connection for destination {}, dispatch {}->{} "
							+ "to all server-side connections", f.getDestination(), f.getSource(), f.getDestination());
					// create temporary array to not block concurrent access during iteration
					for (final KNXnetIPConnection conn : serverConnections.toArray(new KNXnetIPConnection[0]))
						send(sc, conn, f);
				}
			}
			else {
				// group destination address
				final int raw = f.getDestination().getRawAddress();
				if (raw <= 0x6fff) {
					// check if forwarding requests us to block all frames
					if (mainGroupAddressConfig == 2)
						return;
					// check if forwarding requests us to use the filter table
					final int gatObjInst = subnetConnector.getGroupAddressTableObjectInstance();
					if ((mainGroupAddressConfig == 0 || mainGroupAddressConfig == 3)
							&& !inGroupAddressTable((GroupAddress) f.getDestination(), gatObjInst)) {
						logger.warn(f + ", destination not in group address table - throw away");
						return;
					}
				}

				logger.debug("dispatch {}->{} to all server-side connections", f.getSource(), f.getDestination());
				// create temporary array to not block concurrent access during iteration
				for (final KNXnetIPConnection c : serverConnections.toArray(new KNXnetIPConnection[0])) {
					// if we have a bus monitoring connection, but a subnet connector does not support busmonitor mode,
					// we serve that connection by converting cEMI L-Data -> cEMI BusMon
					final boolean monitoring = c.getName().toLowerCase().contains("monitor");
					final CEMI send = monitoring ? convertToBusmon(f, eventId, subnetConnector) : f;
					try {
						send(sc, c, send);
					}
					catch (final KNXIllegalArgumentException e) {
						// Occurs, for example, if we serve a management connection which expects only cEMI device mgmt
						// frames. Catch here, so we can continue serving other open connections.
						logger.warn("frame not accepted by {} ({}): {}", c.getName(), e.getMessage(), send);
					}
				}
			}
		}
		catch (KnxPropertyException | InterruptedException e) {
			logger.error("send to server-side failed for " + f.toString(), e);
		}
	}

	private KNXnetIPConnection findServerConnection(final IndividualAddress dst)
	{
		final KNXnetIPConnection c = serverDataConnections.get(dst);
		if (c != null)
			return c;
		for (final KNXnetIPConnection e : serverConnections)
			if (e instanceof KNXnetIPRouting)
				return e;
		return null;
	}

	// check whether we have to slow down or pause sending for routing flow control
	private void applyRoutingFlowControl(final KNXnetIPConnection c) throws InterruptedException
	{
		if (!(c instanceof KNXnetIPRouting) || routingBusyCounter.get() == 0)
			return;

		// we have to loop because a new arrival of routing busy might update timings
		while (true) {
			final Instant now = Instant.now();
			final Duration sleep = Duration.between(now, pauseSendingUntil);
			if (!sleep.isNegative()) {
				Thread.sleep(sleep.toMillis());
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
		throws InterruptedException
	{
		applyRoutingFlowControl(c);
		try {
			c.send(f, WaitForAck);
			setNetworkState(false, false);
			incMsgTransmitted(false);

			final ReplayBuffer<FrameEvent> buffer = subnetEventBuffers.get(svcContainer);
			if (buffer != null)
				buffer.completeEvent(c, recordFrameEvent);
		}
		catch (final KNXTimeoutException | KNXConnectionClosedException e) {
			logger.error("sending on {} failed: {} ({})", c, e.getMessage(), f.toString());
			setNetworkState(false, true);
		}
	}

	private void send(final KNXNetworkLink lnk, final CEMILData f)
	{
		try {
			final CEMILData ldata;
			final int mc = f.getMessageCode();

			// we have to adjust a possible routing .ind from server-side to .req,
			// or vice versa a .req to .ind if we use KNXnet/IP routing on the KNX subnet
			// ??? HACK: do we use routing on the KNX subnet
			AutoCloseable subnetLink = lnk;
			if (subnetLink instanceof Link)
				subnetLink = ((Link<?>) subnetLink).target();
			final boolean routing = subnetLink instanceof KNXNetworkLinkIP && subnetLink.toString().contains("routing");

			// adjust .ind: on every KNX subnet link (except routing links) we require an L-Data.req
			if (mc == CEMILData.MC_LDATA_IND && !routing)
				ldata = (CEMILData) CEMIFactory.create(CEMILData.MC_LDATA_REQ, null, f);
			// adjust .req: on KNX subnets with KNXnet/IP routing, we require an L-Data.ind
			else if (mc == CEMILData.MC_LDATA_REQ && routing)
				ldata = (CEMILData) CEMIFactory.create(CEMILData.MC_LDATA_IND, null, f);
			else
				ldata = f;

			lnk.send(ldata, true);
			setNetworkState(true, false);
		}
		catch (final KNXTimeoutException e) {
			setNetworkState(true, true);
			logger.warn("timeout sending to {}: {}", f.getDestination(), e);
		}
		catch (final KNXFormatException | KNXLinkClosedException e) {
			logger.error("error sending to {} on subnet {}", f.getDestination(), lnk.getName(), e);
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

	// implements KNX group address filtering using IOS addresstable object
	private boolean inGroupAddressTable(final GroupAddress addr, final int objectInstance)
	{
		final InterfaceObjectServer ios = server.getInterfaceObjectServer();
		try {
			final byte[] data = ios.getProperty(InterfaceObject.ADDRESSTABLE_OBJECT,
					objectInstance, PropertyAccess.PID.TABLE, 0, 1);
			final int elems = (data[0] & 0xff) << 8 | data[1] & 0xff;

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

	private void doDeviceManagement(final KNXnetIPConnection c, final CEMIDevMgmt f)
	{
		final int mc = f.getMessageCode();
		if (mc == CEMIDevMgmt.MC_PROPREAD_REQ || mc == CEMIDevMgmt.MC_PROPWRITE_REQ) {
			final boolean read = mc == CEMIDevMgmt.MC_PROPREAD_REQ;
			final InterfaceObjectServer ios = server.getInterfaceObjectServer();
			byte[] data = null;
			int elems = f.getElementCount();
			try {
				if (read) {
					data = ios.getProperty(f.getObjectType(), f.getObjectInstance(), f.getPID(),
							f.getStartIndex(), elems);
					// play it safe and set error code if property data was not found
					if (data == null) {
						data = new byte[] { CEMIDevMgmt.ErrorCodes.VOID_DP };
						elems = 0;
					}
				}
				else
					ios.setProperty(f.getObjectType(), f.getObjectInstance(), f.getPID(),
							f.getStartIndex(), elems, f.getPayload());
			}
			catch (final KnxPropertyException e) {
				logger.info(e.getMessage());
				data = new byte[] { (byte) e.errorCode() };
				elems = 0;
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
				logger.error("send failed", e);
			}
		}
		else if (mc == CEMIDevMgmt.MC_RESET_REQ) {
			// handle reset.req here since we have the connection name for logging
			logger.info("received reset request " + c.getName() + " - restarting " + server.getName());
			// corresponding launch is done in run()
			inReset = true;
			server.shutdown();
		}
	}

	// defaults to 1 for now
	private final int objectInstance = 1;

	private void incMsgTransmitted(final boolean toKnxNetwork)
	{
		final int pid = toKnxNetwork ? PID.MSG_TRANSMIT_TO_KNX : PID.MSG_TRANSMIT_TO_IP;
		// must be 4 byte unsigned
		// getPropertyOrDefault casts to int, but we just increment and store so it doesn't matter
		long transmit = getPropertyOrDefault(KNXNETIP_PARAMETER_OBJECT, objectInstance, pid, 0);
		try {
			server.getInterfaceObjectServer().setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance, pid, 1, 1,
					bytesFromInt(++transmit));
		}
		catch (final KnxPropertyException e) {
			logger.error("on increasing message transmit counter", e);
		}
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
		// if counter == 7, simply forward
		if (count == 7)
			return msg;
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
	private void setNetworkState(final boolean knxNetwork, final boolean faulty)
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
			server.getInterfaceObjectServer().setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance,
					PID.KNXNETIP_DEVICE_STATE, 1, 1, new byte[] { (byte) state });
		}
		catch (final KnxPropertyException e) {
			logger.error("on modifying network fault in device state", e);
		}
	}

	private CEMI convertToBusmon(final CEMILData ldata, final long eventId, final SubnetConnector connector)
	{
		// maintain busmon frame sequence using the event id
		if (eventId != connector.lastEventId) {
			connector.eventCounter++;
			connector.lastEventId = eventId;
		}
		final int seq = (int) (connector.eventCounter % 8);

		// provide 32 bit timestamp with 1 us precision
		final long timestamp = (System.nanoTime() / 1000) & 0xFFFFFFFFL;

		byte[] doa = new byte[2];
		final CEMILData copy = (CEMILData) CEMIFactory.copy(ldata);
		if (copy instanceof CEMILDataEx) {
			final CEMILDataEx ex = (CEMILDataEx) copy;
			doa = ex.getAdditionalInfo(CEMILDataEx.ADDINFO_PLMEDIUM);
			ex.getAdditionalInfo().forEach(i -> ex.removeAdditionalInfo(i.getType()));
		}

		final KNXMediumSettings settings = connector.getServiceContainer().getMediumSettings();
		final boolean hasDoA = settings.getMedium() == KNXMediumSettings.MEDIUM_PL110;
		final int doaLength = hasDoA ? 2 : 0;

		final byte[] src = copy.toByteArray();
		// -2 to remove msg code and add.info field, +length for DoA (if any), +1 for fcs
		final byte[] raw = new byte[src.length - 2 + doaLength + 1];
		System.arraycopy(src, 2, raw, 0, src.length - 2);
		if (hasDoA) {
			// insert DoA, we create an extended busmonitor frame, and put DoA after ctrl fields
			System.arraycopy(raw, 2, raw, 4, raw.length - 4);
			raw[2] = doa[0];
			raw[3] = doa[1];
		}

		final int extFrameFormatFlag = 0x80;
		raw[0] &= ~extFrameFormatFlag; // clear bit to indicate ext. frame format
		raw[raw.length - 1] = (byte) checksum(raw); // fcs

		return CEMIBusMon.newWithSequenceNumber(seq, timestamp, true, raw);
	}

	private static int checksum(final byte[] frame)
	{
		int cs = 0;
		for (final byte b : frame)
			cs ^= b;
		return ~cs;
	}

	private static long toUnsignedInt(final byte[] data)
	{
		if (data.length == 1)
			return (data[0] & 0xff);
		if (data.length == 2)
			return (data[0] & 0xff) << 8 | data[1] & 0xff;
		return (data[0] & 0xff) << 24 | (data[1] & 0xff) << 16 | (data[2] & 0xff) << 8 | data[3] & 0xff;
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
