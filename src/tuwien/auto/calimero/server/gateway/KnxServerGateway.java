/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2014 B. Malinowsky

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

package tuwien.auto.calimero.server.gateway;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.cemi.CEMIDevMgmt;
import tuwien.auto.calimero.cemi.CEMIFactory;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.cemi.CEMILDataEx;
import tuwien.auto.calimero.exception.KNXException;
import tuwien.auto.calimero.exception.KNXTimeoutException;
import tuwien.auto.calimero.knxnetip.KNXnetIPConnection;
import tuwien.auto.calimero.knxnetip.KNXnetIPRouting;
import tuwien.auto.calimero.knxnetip.LostMessageEvent;
import tuwien.auto.calimero.knxnetip.RoutingListener;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.NetworkLinkListener;
import tuwien.auto.calimero.log.LogLevel;
import tuwien.auto.calimero.log.LogManager;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.server.InterfaceObject;
import tuwien.auto.calimero.server.InterfaceObjectServer;
import tuwien.auto.calimero.server.KNXPropertyException;
import tuwien.auto.calimero.server.PropertyEvent;
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
	// Connection listener for accepted KNXnet/IP connections
	private final class ConnectionListener implements RoutingListener
	{
		final String name;
		final IndividualAddress addr;

		ConnectionListener(final String connectionName, final IndividualAddress device)
		{
			// same as calling ((KNXnetIPConnection) getSource()).getName()
			name = connectionName;
			addr = device;
		}

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

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.server.knxnetip.RoutingListener
		 * #lostMessage(tuwien.auto.calimero.server.knxnetip.LostMessageEvent)
		 */
		public void lostMessage(final LostMessageEvent e)
		{
			logger.warn("routing message loss of " + "KNXnet/IP router " + e.getSender()
					+ " increased to a total of " + e.getLostMessages());
		}

		public void connectionClosed(final CloseEvent e)
		{
			logger.info("remove " + name + " (" + e.getReason() + ")");
			serverConnections.remove(e.getSource());
			if (e.getSource() instanceof KNXnetIPRouting)
				routing = false;
			if (addr != null)
				synchronized (serverDataConnections) {
					serverDataConnections.remove(addr);
				}
		}
	}

	private final class KNXnetIPServerListener implements ServerListener
	{
		KNXnetIPServerListener()
		{}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.server.knxnetip.ServerListener
		 * #acceptDataConnection(tuwien.auto.calimero.server.knxnetip.KNXnetIPConnection)
		 */
		public boolean acceptDataConnection(final KNXnetIPConnection conn,
			final IndividualAddress assignedDeviceAddress)
		{
			conn.addConnectionListener(new ConnectionListener(conn.getName(), assignedDeviceAddress));
			serverConnections.add(conn);
			if (assignedDeviceAddress != null)
				synchronized (serverDataConnections) {
					serverDataConnections.put(assignedDeviceAddress, conn);
				}
			return true;
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.server.knxnetip.ServerListener
		 * #propertyChanged(tuwien.auto.calimero.server.knxnetip.PropertyEvent)
		 */
		public void onPropertyValueChanged(final PropertyEvent pe)
		{
			logger.trace("property id " + pe.getPropertyId() + " changed to ["
					+ DataUnitBuilder.toHex(pe.getNewData(), " ") + "]");

			if (pe.getNewData().length == 0)
				return;

			// update group address forwarding settings
			if (pe.getPropertyId() == MAIN_LCGRPCONFIG) {
				if (pe.getInterfaceObject().getType() == ROUTER_OBJECT) {
					mainGroupAddressConfig = pe.getNewData()[0] & 0x03;
					logger.info("main-line group address config changed to "
							+ mainGroupAddressConfig);
				}
			}
			else if (pe.getPropertyId() == SUB_LCGRPCONFIG) {
				if (pe.getInterfaceObject().getType() == ROUTER_OBJECT) {
					subGroupAddressConfig = pe.getNewData()[0] & 0x03;
					logger.info("sub-line group address config changed to " + subGroupAddressConfig);
				}
			}
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.server.knxnetip.ServerListener#
		 * onServiceContainerChange
		 * (tuwien.auto.calimero.server.knxnetip.ServiceContainerEvent)
		 */
		public void onServiceContainerChange(final ServiceContainerEvent sce)
		{
			final int event = sce.getEventType();
			final ServiceContainer sc = sce.getContainer();
			if (event == ServiceContainerEvent.ROUTING_SVC_STARTED) {
				final KNXnetIPConnection conn = sce.getConnection();
				logger.info(sc.getName() + " started " + conn.getName());
				conn.addConnectionListener(new ConnectionListener(conn.getName(), null));
				serverConnections.add(conn);
				routing = true;
				routingLoopback = ((KNXnetIPRouting) conn).usesMulticastLoopback();
			}
			else if (event == ServiceContainerEvent.ADDED_TO_SERVER) {
				logger.error("adding service container at runtime not yet implemented");
				// prevent Java unreachable code warning
				if (event != 0)
					return;
				// the following is not working!
				// XXX subnet link and group address table is missing!
				// what is the best way to get them here?
				final SubnetConnector connector = new SubnetConnector(sc, null, 1);
				connectors.add(connector);
				connector.setSubnetListener(new SubnetListener(connector.getName()));
			}
			else if (event == ServiceContainerEvent.REMOVED_FROM_SERVER) {
				for (final Iterator i = connectors.iterator(); i.hasNext();) {
					final SubnetConnector b = (SubnetConnector) i.next();
					if (b.getServiceContainer() == sc) {
						b.getSubnetLink().removeLinkListener(b.getSubnetListener());
						i.remove();
						break;
					}
				}
			}
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.server.knxnetip.ServerListener
		 * #resetRequest(tuwien.auto.calimero.server.knxnetip.ShutdownEvent)
		 */
		public void onResetRequest(final ShutdownEvent se)
		{}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.server.knxnetip.ServerListener
		 * #shutdown(tuwien.auto.calimero.server.knxnetip.ShutdownEvent)
		 */
		public void onShutdown(final ShutdownEvent se)
		{
			// shutdown is guaranteed to be called before server is shutdown, therefore
			// this flag status is correct
			if (inReset)
				return;
			final int i = se.getInitiator();
			final String s = i == CloseEvent.USER_REQUEST ? " user"
					: i == CloseEvent.CLIENT_REQUEST ? " client" : " server internal";
			logger.info(server.getName() + s + " request for shutdown");
			quit();
		}
	}

	private final class SubnetListener implements NetworkLinkListener
	{
		private final String scid;

		SubnetListener(final String svcContainerId)
		{
			scid = svcContainerId;
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.event.NetworkLinkListener
		 * #confirmation(tuwien.auto.calimero.FrameEvent)
		 */
		public void confirmation(final FrameEvent e)
		{}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.event.LinkListener
		 * #indication(tuwien.auto.calimero.FrameEvent)
		 */
		public void indication(final FrameEvent e)
		{
			logger.info("received " + scid + " subnet " + e.getFrame().toString());
			synchronized (KnxServerGateway.this) {
				if (subnetEvents.size() < maxEventQueueSize) {
					// In the dispatching to server side, we rely on having the
					// subnet link in the frame event source stored so to know where the
					// frame came from.
					// But this will not work if the sending link differs from the one
					// stored in this frame event, e.g., when when using a buffered link.
					// Therefore, I store the svcContainer in here for re-association.
					subnetEvents.add(new FrameEvent(scid, e.getFrame()));
					KnxServerGateway.this.notify();
				}
				else
					incMsgQueueOverflow(false);
			}
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.event.LinkListener
		 * #linkClosed(tuwien.auto.calimero.CloseEvent)
		 */
		public void linkClosed(final CloseEvent e)
		{
			logger.info("KNX subnet link closed (" + e.getReason() + ")");
		}
	}

	private final String name;
	private final LogService logger;

	private final KNXnetIPServer server;
	// connectors array is not sync'd throughout gateway
	private final List connectors = new ArrayList();
	private final boolean enableDiscovery = true;

	private final Map serverDataConnections = new HashMap();
	private final List serverConnections = Collections.synchronizedList(new ArrayList());

	private final int maxEventQueueSize = 200;
	private final List ipEvents = new LinkedList();
	private final List subnetEvents = new LinkedList();

	private boolean routing;
	private boolean routingLoopback;
	// This list is used for multicast packets in KNXnet/IP routing that are looped back
	// using the local loopback socket. Packets sent by us are buffered here, and
	// subsequently silently discarded when received again shortly after (and also removed
	// from this buffer again).
	// This list holds cEMI frames now, but can essentially might only keep data arrays.
	private final List loopbackFrames = new LinkedList();

	private volatile boolean trucking;
	private volatile boolean inReset;

	// Frame forwarding based on KNX address (AN031)
	// KNX properties to determine address routing and address filtering:
	// located in the Router Object Interface Object (Object Type 6)
	private static final int ROUTER_OBJECT = 6;
	// properties for individual address forwarding
	private static final int MAIN_LCCONFIG = 52;
	private static final int SUB_LCCONFIG = 53;
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

	private final Thread dispatcher = new Thread()
	{
		{
			setName("Gateway IP to subnet dispatcher");
		}

		public void run()
		{
			try {
				while (trucking) {
					while (!ipEvents.isEmpty())
						onFrameReceived((FrameEvent) ipEvents.remove(0), true);
					synchronized (this) {
						wait();
					}
				}
			}
			catch (final InterruptedException e) {}
		};
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
	public KnxServerGateway(final String gatewayName, final KNXnetIPServer s,
		final SubnetConnector[] subnetConnectors)
	{
		name = gatewayName;
		server = s;
		server.addServerListener(new KNXnetIPServerListener());
		connectors.addAll(Arrays.asList(subnetConnectors));
		for (final Iterator i = connectors.iterator(); i.hasNext();) {
			final SubnetConnector b = (SubnetConnector) i.next();
			b.setSubnetListener(new SubnetListener(b.getName()));
		}
		logger = LogManager.getManager().getLogService(name);

		// group address routing settings
		try {
			final byte[] data = server.getInterfaceObjectServer().getProperty(ROUTER_OBJECT,
					objectInstance, MAIN_LCGRPCONFIG, 1, 1);
			mainGroupAddressConfig = data[0] & 0x03;
			logger.info("main-line group address forward setting set to " + mainGroupAddressConfig);
		}
		catch (final KNXPropertyException e1) {
			e1.printStackTrace();
		}
		try {
			final byte[] data = server.getInterfaceObjectServer().getProperty(ROUTER_OBJECT,
					objectInstance, SUB_LCGRPCONFIG, 1, 1);
			subGroupAddressConfig = data[0] & 0x03;
			logger.info("sub-line group address forward setting set to " + subGroupAddressConfig);
		}
		catch (final KNXPropertyException e1) {
			e1.printStackTrace();
		}

		// init PID.PRIORITY_FIFO_ENABLED property to non-fifo message queue
		try {
			server.getInterfaceObjectServer().setProperty(
					InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance,
					PID.PRIORITY_FIFO_ENABLED, 1, 1, new byte[] { 0 });
		}
		catch (final KNXPropertyException e) {
			e.printStackTrace();
		}
		// init capability list of different routing features
		// bit field: bit 0: Queue overflow counter available
		// 1: Transmitted message counter available
		// 2: Support of priority/FIFO message queues
		// 3: Multiple KNX installations supported
		// 4: Group address mapping supported
		// other bits reserved
		final byte caps = 1 << 0 | 1 << 1;
		try {
			server.getInterfaceObjectServer().setProperty(
					InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance,
					PID.KNXNETIP_ROUTING_CAPABILITIES, 1, 1, new byte[] { caps });
		}
		catch (final KNXPropertyException e) {
			e.printStackTrace();
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.lang.Runnable#run()
	 */
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
				while (!subnetEvents.isEmpty())
					onFrameReceived((FrameEvent) subnetEvents.remove(0), false);

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
					if (ipEvents.isEmpty() && subnetEvents.isEmpty())
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

	private void launchServer()
	{
		try {
			server.setOption(KNXnetIPServer.OPTION_DISCOVERY_DESCRIPTION,
					Boolean.valueOf(enableDiscovery).toString());
			server.launch();
		}
		catch (final RuntimeException e) {
			logger.error("cannot launch " + server.getFriendlyName(), e);
			quit();
			throw e;
		}
	}

	private void onFrameReceived(final FrameEvent fe, final boolean fromServerSide)
	{
		final String s = fromServerSide ? "server-side " : "KNX subnet ";
		final CEMI frame = fe.getFrame();

		final boolean trace = logger.isLoggable(LogLevel.TRACE);
		if (trace)
			logger.trace(s + fe.getSource() + " " + frame.toString());

		if (fromServerSide && discardLoopedBackFrame(frame))
			return;

		final int mc = frame.getMessageCode();
		if (frame instanceof CEMILData) {
			final CEMILData f = (CEMILData) frame;

			if (trace)
				logger.trace("decoded service is "
						+ DataUnitBuilder.decode(f.getPayload(), f.getDestination()));

			// we get L-data.ind if client uses routing protocol
			if (fromServerSide && (mc == CEMILData.MC_LDATA_REQ || mc == CEMILData.MC_LDATA_IND))
				try {
					// send confirmation on .req type
					if (mc == CEMILData.MC_LDATA_REQ) {
						((KNXnetIPConnection) fe.getSource()).send(
								CEMIFactory.create(CEMILData.MC_LDATA_CON, f.getPayload(), f),
								KNXnetIPConnection.WAIT_FOR_ACK);
					}
					final CEMILData send = adjustHopCount(f);
					if (send == null)
						logger.info("hop count 0, discarded frame to " + f.getDestination());
					else {
						dispatchToSubnet(send);
					}
				}
				catch (final KNXException e) {
					logger.error("sending L-data confirmation of "
							+ DataUnitBuilder.decode(f.getPayload(), f.getDestination()), e);
					e.printStackTrace();
				}
			else if (!fromServerSide && mc == CEMILData.MC_LDATA_IND) {
				final CEMILData send = adjustHopCount(f);
				if (send == null)
					logger.info("hop count 0, discarded frame to " + f.getDestination());
				else {
					// get connector of that subnet
					SubnetConnector subnetConnector = null;
					for (final Iterator i = connectors.iterator(); i.hasNext();) {
						final SubnetConnector b = (SubnetConnector) i.next();
						// ??? using the sending link does not always work,
						// see listener indication for the reason of this workaround
						if (b.getServiceContainer().getName().equals(fe.getSource())) {
							subnetConnector = b;
							break;
						}
					}
					if (subnetConnector != null)
						dispatchToServer(subnetConnector, send);
					else
						logger.fatal("dispatch to server: no subnet connector found!");
				}
			}
			else {
				final String type = mc == CEMILData.MC_LDATA_CON ? ".con" : " msg code 0x"
						+ Integer.toString(mc, 16);
				logger.warn(s + " L-data" + type + " ["
						+ DataUnitBuilder.toHex(f.toByteArray(), "") + "] - ignored");
			}
		}
		else if (mc == CEMIDevMgmt.MC_PROPREAD_REQ || mc == CEMIDevMgmt.MC_PROPWRITE_REQ
				|| mc == CEMIDevMgmt.MC_RESET_REQ)
			doDeviceManagement((KNXnetIPConnection) fe.getSource(), (CEMIDevMgmt) frame);
		else
			logger.warn("received unknown cEMI msg code 0x" + Integer.toString(mc, 16)
					+ " - ignored");
	}

	private boolean discardLoopedBackFrame(final CEMI frame)
	{
		if (routing && routingLoopback) {
			final byte[] a1 = frame.toByteArray();
			synchronized (loopbackFrames) {
				for (final Iterator i = loopbackFrames.iterator(); i.hasNext();) {
					final byte[] a2 = ((CEMI) i.next()).toByteArray();
					if (a1.length == a2.length) {
						for (int k = 0; k < a1.length; ++k)
							if (a1[k] != a2[k])
								return false;
						if (logger.isLoggable(LogLevel.TRACE))
							logger.trace("discard routed cEMI frame received over "
									+ "local multicast loopback");
						i.remove();
						return true;
					}
					// limit max. loopback queue size
					else if (loopbackFrames.size() > maxEventQueueSize)
						i.remove();
				}
			}
		}
		return false;
	}

	private void dispatchToSubnet(final CEMILData f)
	{
		if (f.getDestination() instanceof IndividualAddress) {
			final KNXNetworkLink lnk = findSubnetLink((IndividualAddress) f.getDestination());
			if (lnk == null) {
				logger.warn("no subnet configured for destination " + f.getDestination() + " ("
						+ DataUnitBuilder.decode(f.getPayload(), f.getDestination())
						+ " received from " + f.getSource() + ")");
				return;
			}
			send(lnk, f);
		}
		else {
			// group destination address, check forwarding settings
			final int raw = f.getDestination().getRawAddress();
			// XXX cleanup  the two loops
			if (raw <= 0x6fff) {
				if (subGroupAddressConfig == 2)
					return;
				
				for (final Iterator i = connectors.iterator(); i.hasNext();) {
					final SubnetConnector subnet = (SubnetConnector) i.next();
					if (subnet.getServiceContainer().isActivated()) {
						
						if ((subGroupAddressConfig == 0 || subGroupAddressConfig == 3)
								&& !inGroupAddressTable((GroupAddress) f.getDestination(),
										subnet.getGroupAddressTableObjectInstance())) {
							logger.warn("destination " + f.getDestination()
									+ " not in group address table - skip frame");
						}
						else
							send(subnet.getSubnetLink(), f);
					}
				}
			}
			else {
				for (final Iterator i = connectors.iterator(); i.hasNext();) {
					final SubnetConnector b = (SubnetConnector) i.next();
					if (b.getServiceContainer().isActivated())
						send(b.getSubnetLink(), f);
				}
			}

		}
		incMsgTransmitted(true);
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
		for (final Iterator i = connectors.iterator(); i.hasNext();) {
			final SubnetConnector b = (SubnetConnector) i.next();
			final ServiceContainer c = b.getServiceContainer();
			if (c.isActivated()) {
				final IndividualAddress subnet = c.getSubnetAddress();
				if (matchesSubnet(dst, subnet)) {
					if (logger.isLoggable(LogLevel.TRACE))
						logger.trace("dispatch to KNX subnet " + subnet + " ("
								+ b.getSubnetLink().getName() + " in service container "
								+ b.getName() + ")");
					// assuming a proper address assignment of area/line coupler
					// addresses, this has to be the correct knx subnet link
					return b.getSubnetLink();
				}
				logger.trace("subnet=" + subnet + " dst=" + dst);
			}
		}
		return null;
	}

	private void dispatchToServer(final SubnetConnector subnetConnector, final CEMILData f)
	{
		try {
			if (f.getDestination() instanceof IndividualAddress) {
				final KNXnetIPConnection c = findServerConnection((IndividualAddress) f
						.getDestination());
				if (c != null) {
					if (logger.isLoggable(LogLevel.TRACE))
						logger.trace("send from " + f.getSource() + " to " + f.getDestination());
					c.send(f, KNXnetIPConnection.WAIT_FOR_ACK);
				}
			}
			else {
				final int raw = f.getDestination().getRawAddress();
				if (raw <= 0x6fff) {
					// group destination address, check forwarding settings
					if (mainGroupAddressConfig == 2)
						return;
					if ((mainGroupAddressConfig == 0 || mainGroupAddressConfig == 3)
							&& !inGroupAddressTable((GroupAddress) f.getDestination(),
									subnetConnector.getGroupAddressTableObjectInstance())) {
						logger.warn("destination " + f.getDestination()
								+ " not in group address table - skipped frame");
						return;
					}
				}

				// create temporary array to not block concurrent access during iteration
				final KNXnetIPConnection[] sca = (KNXnetIPConnection[]) serverConnections
						.toArray(new KNXnetIPConnection[serverConnections.size()]);
				for (int i = 0; i < sca.length; i++) {
					final KNXnetIPConnection c = sca[i];
					c.send(f, KNXnetIPConnection.WAIT_FOR_ACK);
				}

				if (routing && routingLoopback) {
					synchronized (loopbackFrames) {
						loopbackFrames.add(f);
						System.out.println("add to loopback frame buffer: " + f + " [" +
								DataUnitBuilder.toHex(f.toByteArray(), " ") + "]");
					}
				}
			}
			incMsgTransmitted(false);
			setNetworkState(false, false);
		}
		catch (final KNXException e) {
			logger.error("send to server-side failed for " + f.toString(), e);
			if (e instanceof KNXTimeoutException)
				setNetworkState(false, true);
		}
	}

	private KNXnetIPConnection findServerConnection(final IndividualAddress dst)
	{
		return (KNXnetIPConnection) serverDataConnections.get(dst);
	}

	private void send(final KNXNetworkLink lnk, final CEMILData f)
	{
		try {
			lnk.send(f, true);
			setNetworkState(true, false);
		}
		catch (final KNXTimeoutException e) {
			e.printStackTrace();
			setNetworkState(true, true);
		}
		catch (final KNXLinkClosedException e) {
			e.printStackTrace();
		}
	}

	// implements KNX group address filtering using IOS addresstable object
	private boolean inGroupAddressTable(final GroupAddress addr, final int objectInstance)
	{
		// ??? I tested lookup performance of properties vs using a local address set:
		// as expected, we get a considerable performance hit on large tables and
		// high numbers of lookups, compared to using a Set.
		// Might be worth using our own HashSet with GroupAddress entries if we
		// tend to use larger group address filter tables with lot of lookups.
		final InterfaceObjectServer ios = server.getInterfaceObjectServer();
		try {
			final byte[] data = ios.getProperty(InterfaceObject.ADDRESSTABLE_OBJECT,
					objectInstance, PropertyAccess.PID.TABLE, 0, 1);
			final int elems = (data[0] & 0xff) << 8 | data[1] & 0xff;

			// not sure if this is some common behavior:
			// if property exists but with zero length, allow every address
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
		catch (final KNXPropertyException e) {
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
			catch (final KNXPropertyException e) {
				logger.warn(e.getMessage() + ": " + CEMIDevMgmt.getErrorMessage(e.getStatusCode()));
				data = new byte[] { (byte) e.getStatusCode() };
				elems = 0;
			}
			final int con = read ? CEMIDevMgmt.MC_PROPREAD_CON : CEMIDevMgmt.MC_PROPWRITE_CON;
			final CEMIDevMgmt dm = read || data != null ? new CEMIDevMgmt(con, f.getObjectType(),
					f.getObjectInstance(), f.getPID(), f.getStartIndex(), elems, data)
					: new CEMIDevMgmt(con, f.getObjectType(), f.getObjectInstance(), f.getPID(),
							f.getStartIndex(), elems);
			try {
				c.send(dm, KNXnetIPConnection.WAIT_FOR_ACK);
			}
			catch (final KNXException e) {
				logger.error("send failed", e);
			}
		}
		else if (mc == CEMIDevMgmt.MC_RESET_REQ) {
			// handle reset.req here since we have the connection name for logging
			logger.info("received reset request " + c.getName() + " - restarting "
					+ server.getName());
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
		try {
			// must be 4 byte unsigned
			final byte[] data = server.getInterfaceObjectServer().getProperty(
					InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance, pid, 1, 1);
			long transmit = toUnsignedInt(data);
			++transmit;
			server.getInterfaceObjectServer().setProperty(
					InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance, pid, 1, 1,
					bytesFromInt(transmit));

		}
		catch (final KNXPropertyException e) {
			logger.error("on increasing message transmit counter", e);
		}
	}

	// support queue overflow statistics
	private void incMsgQueueOverflow(final boolean toKnxNetwork)
	{
		final int pid = toKnxNetwork ? PID.QUEUE_OVERFLOW_TO_KNX : PID.QUEUE_OVERFLOW_TO_IP;
		try {
			// 2 byte unsigned
			final byte[] data = server.getInterfaceObjectServer().getProperty(
					InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance, pid, 1, 1);
			int overflow = (int) toUnsignedInt(data);
			if (overflow == 0xffff) {
				logger.warn("queue overflow counter reached maximum, not incremented");
				return;
			}
			++overflow;
			server.getInterfaceObjectServer().setProperty(
					InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance, pid, 1, 1,
					bytesFromWord(overflow));

			// actual sending of routing lost message is done in KNXnetIPServer
			/*
			 * if (toKnxNetwork) { // query device state used in lost message notification
			 * final byte[] state = server.getInterfaceObjectServer().getProperty(
			 * InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance,
			 * PID.KNXNETIP_DEVICE_STATE, 1, 1); final RoutingLostMessage msg = new
			 * RoutingLostMessage(overflow, state[0] & 0xff); }
			 */
		}
		catch (final KNXPropertyException e) {
			logger.error("on increasing queue overflow counter", e);
		}
	}

	// returns null to indicate a discarded frame
	private CEMILData adjustHopCount(final CEMILData msg)
	{
		int count = msg.getHopCount();
		// if counter == 0, discard frame
		if (count == 0)
			return null;
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
		// set the corresponding bit in device state field
		try {
			// 1 byte bit field
			final byte[] data = server.getInterfaceObjectServer().getProperty(
					InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance,
					PID.KNXNETIP_DEVICE_STATE, 1, 1);
			// bit 0: KNX fault, bit 1: IP fault, others reserved
			if (knxNetwork)
				data[0] = (byte) (faulty ? data[0] | 1 : data[0] & 0xfe);
			else
				data[0] = (byte) (faulty ? data[0] | 2 : data[0] & 0xfd);

			server.getInterfaceObjectServer().setProperty(
					InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance,
					PID.KNXNETIP_DEVICE_STATE, 1, 1, data);
		}
		catch (final KNXPropertyException e) {
			logger.error("on modifying network fault in device state", e);
		}
	}

	private static long toUnsignedInt(final byte[] data)
	{
		if (data.length == 2)
			return (data[0] & 0xff) << 8 | data[1] & 0xff;
		return (data[0] & 0xff) << 24 | (data[1] & 0xff) << 16 | (data[2] & 0xff) << 8 | data[3]
				& 0xff;
	}

	private static byte[] bytesFromInt(final long value)
	{
		return new byte[] { (byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8),
			(byte) value };
	}

	private static byte[] bytesFromWord(final int word)
	{
		return new byte[] { (byte) (word >> 8), (byte) word };
	}
}
