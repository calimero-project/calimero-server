/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2015 B. Malinowsky

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

package tuwien.auto.calimero.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.buffer.Configuration;
import tuwien.auto.calimero.buffer.NetworkBuffer;
import tuwien.auto.calimero.buffer.StateFilter;
import tuwien.auto.calimero.datapoint.DatapointMap;
import tuwien.auto.calimero.datapoint.DatapointModel;
import tuwien.auto.calimero.exception.KNXException;
import tuwien.auto.calimero.knxnetip.KNXnetIPRouting;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.link.medium.PLSettings;
import tuwien.auto.calimero.link.medium.RFSettings;
import tuwien.auto.calimero.log.LogLevel;
import tuwien.auto.calimero.log.LogManager;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.log.LogStreamWriter;
import tuwien.auto.calimero.log.LogWriter;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.server.gateway.KnxServerGateway;
import tuwien.auto.calimero.server.gateway.SubnetConnector;
import tuwien.auto.calimero.server.knxnetip.DefaultServiceContainer;
import tuwien.auto.calimero.server.knxnetip.KNXnetIPServer;
import tuwien.auto.calimero.server.knxnetip.RoutingServiceContainer;
import tuwien.auto.calimero.server.knxnetip.ServiceContainer;
import tuwien.auto.calimero.xml.Element;
import tuwien.auto.calimero.xml.KNXMLException;
import tuwien.auto.calimero.xml.XMLFactory;
import tuwien.auto.calimero.xml.XMLReader;

/**
 * Contains the startup and execution logic for the KNX server gateway. The server configuration is
 * read from an XML resource. Either use method {@link #main(String[])}, or
 * {@link #Launcher(String)} together with {@link #run()}.
 *
 * @author B. Malinowsky
 */
public class Launcher implements Runnable
{
	/**
	 * Specifies the supported XML tags and attribute names for a server configuration. See also the
	 * example server configuration file.
	 */
	public static final class XmlConfiguration
	{
		/** */
		public static final String knxServer = "knxServer";
		/** */
		public static final String propDefs = "propertyDefinitions";
		/** */
		public static final String svcCont = "serviceContainer";
		/** */
		public static final String datapoints = "datapoints";
		/** */
		public static final String subnet = "knxSubnet";
		/** */
		public static final String grpAddrFilter = "groupAddressFilter";
		/** */
		public static final String routingMcast = "routingMcast";
		/** */
		public static final String discovery = "discovery";
		/** */
		public static final String addAddresses = "additionalAddresses";

		/** */
		public static final String attrName = "name";
		/** */
		public static final String attrFriendly = "friendlyName";
		/** */
		public static final String attrActivate = "activate";
		/** */
		public static final String attrRouting = "routing";
		/** */
		public static final String attrListenNetIf = "listenNetIf";
		/** */
		public static final String attrOutgoingNetIf = "outgoingNetIf";
		/** */
		public static final String attrUdpPort = "udpPort";
		/** */
		public static final String attrClass = "class";
		/** */
		public static final String attrReuseEP = "reuseCtrlEP";
		/** */
		public static final String attrMonitor = "allowNetworkMonitoring";
		/** KNX subnet type: ["ip", "knxip", "usb", "ft12", "virtual", "user-supplied"] */
		public static final String attrType = "type";
		/** KNX subnet communication medium: { "tp1", "pl110", "pl132", "knxip", "rf" } */
		public static final String attrMedium = "medium";
		/** KNX subnet domain address for power-line and RF, as hexadecimal value string */
		public static final String attrDoA = "domainAddress";
		/** */
		public static final String attrRef = "ref";

		// the service containers the KNX server will host
		private final List svcContainers = new ArrayList();

		// virtual links locally used with the KNX server for KNX subnet emulation
		private final List virtualLinks = new ArrayList();
		// in virtual KNX subnets, the subnetwork can be described by a datapoint model
		private final Map subnetDatapoints = new HashMap();

		// Holds the network interface for KNX IP subnets, if specified
		private final Map subnetNetIf = new HashMap();

		// Holds the class name of user-supplied subnet links, if specified
		private final Map subnetLinkClasses = new HashMap();

		// the following lists contain gateway information, in sequence of the svc containers

		private final List subnetTypes = new ArrayList();
		private final List subnetAddresses = new ArrayList();

		// list of group addresses used in the group address filter of the KNXnet/IP server
		private final Map groupAddressFilters = new HashMap();
		private final Map additionalAddresses = new HashMap();

		public Map load(final String serverConfigUri) throws KNXMLException
		{
			final XMLReader r = XMLFactory.getInstance().createXMLReader(serverConfigUri);

			if (r.read() != XMLReader.START_TAG
					|| !r.getCurrent().getName().equals(XmlConfiguration.knxServer))
				throw new KNXMLException("no valid KNX server configuration (no "
						+ XmlConfiguration.knxServer + " element)");

			final Map m = new HashMap();
			put(m, r, XmlConfiguration.attrName);
			put(m, r, XmlConfiguration.attrFriendly);

			while (r.read() != XMLReader.END_DOC) {
				final Element e = r.getCurrent();
				final String name = e.getName();
				if (r.getPosition() == XMLReader.START_TAG) {
					if (name.equals(XmlConfiguration.discovery)) {
						r.complete(e);
						put(m, r, XmlConfiguration.attrListenNetIf);
						put(m, r, XmlConfiguration.attrOutgoingNetIf);
						put(m, r, XmlConfiguration.attrActivate);
					}
					else if (name.equals(XmlConfiguration.propDefs)) {
						final String res = e.getAttribute(XmlConfiguration.attrRef);
						// NYI if resource is null, definitions are directly included in element
						if (res != null) {
							r.complete(e);
							if (m.containsKey(XmlConfiguration.attrRef))
								logger.warn("multiple property definition resources, ignore " + res
										+ ", " + "line " + r.getLineNumber());
							else
								m.put(XmlConfiguration.attrRef, res);
						}
					}
					else if (name.equals(XmlConfiguration.svcCont))
						readServiceContainer(r);
				}
			}
			return m;
		}

		private void readServiceContainer(final XMLReader r) throws KNXMLException
		{
			Element e = r.getCurrent();
			if (r.getPosition() != XMLReader.START_TAG
					|| !e.getName().equals(XmlConfiguration.svcCont))
				throw new KNXMLException("no service container element");

			final String attrActivate = e.getAttribute(XmlConfiguration.attrActivate);
			final boolean activate = attrActivate == null || Boolean.parseBoolean(attrActivate);
			final boolean routing = Boolean.parseBoolean(e.getAttribute(XmlConfiguration.attrRouting));
			final boolean reuse = Boolean.parseBoolean(e.getAttribute(XmlConfiguration.attrReuseEP));
			final boolean monitor = Boolean.parseBoolean(e.getAttribute(XmlConfiguration.attrMonitor));
			final int port = Integer.parseInt(e.getAttribute(XmlConfiguration.attrUdpPort));
			final NetworkInterface routingNetIf = routing ? getNetIf(e) : null;

			String addr = "";
			String subnetType = "";
			int subnetMedium = KNXMediumSettings.MEDIUM_TP1;
			byte[] subnetDoA = null;
			IndividualAddress subnet = null;
			NetworkInterface subnetKnxipNetif = null;
			InetAddress routingMcast = null;
			String subnetLinkClass = null;
			DatapointModel datapoints = null;
			List filter = Collections.emptyList();
			List indAddressPool = Collections.emptyList();

			try {
				routingMcast = InetAddress.getByName(KNXnetIPRouting.DEFAULT_MULTICAST);
			}
			catch (final UnknownHostException ignore) {}

			while (r.read() != XMLReader.END_DOC) {
				e = r.getCurrent();
				final String name = e.getName();
				if (r.getPosition() == XMLReader.START_TAG) {
					if (name.equals(XmlConfiguration.datapoints)) {
						final DatapointMap dps = new DatapointMap();
						final String res = e.getAttribute(XmlConfiguration.attrRef);
						final XMLReader dpReader = res != null ? XMLFactory.getInstance()
								.createXMLReader(res) : r;
						dps.load(dpReader);
						datapoints = dps;
					}
					else if (name.equals(XmlConfiguration.subnet)) {
						subnetType = e.getAttribute(XmlConfiguration.attrType);
						String medium = e.getAttribute(XmlConfiguration.attrMedium);
						if (medium == null)
							medium = "tp1";
						subnetMedium = KNXMediumSettings.getMedium(medium);

						final String doa = e.getAttribute(XmlConfiguration.attrDoA);
						if (doa != null) {
							long l = Long.parseLong(doa, 16);
							final int bytes = subnetMedium == KNXMediumSettings.MEDIUM_RF ? 6 : 2;
							subnetDoA = new byte[bytes];
							for (int i = subnetDoA.length; i-- > 0; l >>>= 8)
								subnetDoA[i] = (byte) l;
						}

						if (subnetType.equals("knxip"))
							subnetKnxipNetif = getNetIf(e);
						else if (subnetType.equals("user-supplied"))
							subnetLinkClass = e.getAttribute(XmlConfiguration.attrClass);
						r.complete(e);
						addr = e.getCharacterData();
					}
					else if (name.equals(XmlConfiguration.grpAddrFilter))
						filter = readGroupAddressFilter(r);
					else if (name.equals(XmlConfiguration.addAddresses))
						indAddressPool = readAdditionalAddresses(r);
					else if (name.equals(XmlConfiguration.routingMcast)) {
						r.complete(e);
						try {
							routingMcast = InetAddress.getByName(e.getCharacterData());
						}
						catch (final UnknownHostException uhe) {
							throw new KNXMLException(uhe.getMessage(), r);
						}
					}
					else {
						subnet = new IndividualAddress(r);
					}
				}
				else if (r.getPosition() == XMLReader.END_TAG) {
					if (name.equals(XmlConfiguration.svcCont)) {
						final DefaultServiceContainer sc;
						final KNXMediumSettings s = KNXMediumSettings.create(subnetMedium, subnet);
						if (s.getMedium() == KNXMediumSettings.MEDIUM_PL110)
							((PLSettings) s).setDomainAddress(subnetDoA);
						else if (s.getMedium() == KNXMediumSettings.MEDIUM_RF)
							((RFSettings) s).setDomainAddress(subnetDoA);

						if (routing)
							sc = new RoutingServiceContainer(addr, new HPAI((InetAddress) null,
									port), s, reuse, monitor, routingMcast, routingNetIf);
						else
							sc = new DefaultServiceContainer(addr, new HPAI((InetAddress) null,
									port), s, reuse, monitor);
						sc.setActivationState(activate);
						subnetTypes.add(subnetType);
						if ("virtual".equals(subnetType) && datapoints != null)
							subnetDatapoints.put(sc, datapoints);
						subnetAddresses.add(addr);
						svcContainers.add(sc);
						subnetNetIf.put(sc, subnetKnxipNetif);
						subnetLinkClasses.put(sc, subnetLinkClass);
						groupAddressFilters.put(sc, filter);
						additionalAddresses.put(sc, indAddressPool);
						return;
					}
				}
			}
		}

		private static List readGroupAddressFilter(final XMLReader r)
			throws KNXMLException
		{
			assert r.getCurrent().getName().equals(XmlConfiguration.grpAddrFilter);
			assert r.getPosition() == XMLReader.START_TAG;
			r.read();
			final List list = new ArrayList();
			while (!(r.getCurrent().getName().equals(XmlConfiguration.grpAddrFilter) && r
					.getPosition() == XMLReader.END_TAG)) {
				list.add(new GroupAddress(r));
				r.read();
			}
			return list;
		}

		private static List readAdditionalAddresses(final XMLReader r)
			throws KNXMLException
		{
			assert r.getCurrent().getName().equals(XmlConfiguration.addAddresses);
			assert r.getPosition() == XMLReader.START_TAG;
			r.read();
			final List list = new ArrayList();
			while (!(r.getCurrent().getName().equals(XmlConfiguration.addAddresses) && r
					.getPosition() == XMLReader.END_TAG)) {
				list.add(new IndividualAddress(r));
				r.read();
			}
			return list;
		}

		private static void put(final Map m, final XMLReader r, final String attr)
		{
			m.put(attr, r.getCurrent().getAttribute(attr));
		}

		private static NetworkInterface getNetIf(final Element e)
		{
			final String attr = e.getAttribute(XmlConfiguration.attrListenNetIf);
			if (attr != null) {
				try {
					final NetworkInterface netIf = NetworkInterface.getByName(attr);
					if (netIf != null)
						return netIf;
					logger.warn("network interface " + attr + " not found, using system default");
				}
				catch (final SocketException se) {
					logger.error("while searching for network interface " + attr, se);
				}
			}
			return null;
		}
	}

	private static final LogService logger = LogManager.getManager().getLogService(
			"calimero.server");

	private final KNXnetIPServer server;
	private KnxServerGateway gw;
	private final List virtualLinks;

	private XmlConfiguration xml;

	// are we directly started from main, and allow terminal-based termination
	private boolean terminal;

	/**
	 * Main entry routine for starting the KNX server gateway.
	 * <p>
	 *
	 * @param args the file name or URI to the KNX server XML configuration
	 */
	public static void main(final String[] args)
	{
		final LogWriter w = LogStreamWriter.newUnformatted(LogLevel.ALL, System.out, true, false);
		LogManager.getManager().addWriter("", w);
		if (args.length == 0) {
			logger.info("supply file name/URI for the KNX server configuration");
			return;
		}
		try {
			final Launcher sr = new Launcher(args[0]);
			sr.terminal = true;
			sr.run();
		}
		catch (final KNXException e) {
			logger.error("loading configuration from " + args[0], e);
		}
	}

	/**
	 * Launcher constructor
	 *
	 * @param configUri location/file of KNX server and gateway configuration
	 * @throws KNXException
	 */
	public Launcher(final String configUri) throws KNXException
	{
		xml = new XmlConfiguration();
		final Map config = xml.load(configUri);
		virtualLinks = xml.virtualLinks;

		server = new KNXnetIPServer(((String)config.get("name")), ((String) config.get("friendlyName")));
		// load property definitions
		final InterfaceObjectServer ios = server.getInterfaceObjectServer();
		if (config.containsKey("ref"))
			ios.loadDefinitions((String) config.get("ref"));
		final String netIfListen = (String) config.get(XmlConfiguration.attrListenNetIf);
		server.setOption(KNXnetIPServer.OPTION_DISCOVERY_INTERFACES, netIfListen);
		final String netIfOutgoing = (String) config.get(XmlConfiguration.attrOutgoingNetIf);
		server.setOption(KNXnetIPServer.OPTION_OUTGOING_INTERFACE, netIfOutgoing);
		final String runDiscovery;
		if (config.containsKey(XmlConfiguration.attrActivate))
			runDiscovery = (String) config.get(XmlConfiguration.attrActivate);
		else
			runDiscovery = "true";
		server.setOption(KNXnetIPServer.OPTION_DISCOVERY_DESCRIPTION, runDiscovery);

		// output the configuration we loaded
		logger.info("Discovery service network interfaces:");
		logger.info("    listen on " + netIfListen);
		logger.info("    outgoing " + netIfOutgoing);
		for (int i = 0; i < xml.svcContainers.size(); i++) {
			final ServiceContainer sc = (ServiceContainer) xml.svcContainers.get(i);
			logger.info("Service container " + sc.getName() + ": ");
			logger.info("    " + sc.getControlEndpoint() + " routing "
					+ (sc instanceof RoutingServiceContainer));

			final String type = (String) xml.subnetTypes.get(i);
			logger.info("    " + type + " connection, " + sc.getMediumSettings());
			if (xml.groupAddressFilters.containsKey(sc))
				logger.info("    GrpAddrFilter " + xml.groupAddressFilters.get(sc));
			if (xml.subnetDatapoints.containsKey(sc))
				logger.info("    Datapoints "
						+ ((DatapointMap) xml.subnetDatapoints.get(sc)).getDatapoints());
		}
	}

	/* (non-Javadoc)
	 * @see java.lang.Runnable#run()
	 */
	public void run()
	{
		final List connectors = new ArrayList();
		final List linksToClose = new ArrayList();

		try {
			connect(linksToClose, connectors);
			xml = null;
			final String name = "Calimero KNX server gateway";
			// create a gateway which forwards and answers most of the KNX stuff
			// if no connectors were created, gateway will throw
			gw = new KnxServerGateway(name, server,
					(SubnetConnector[]) connectors.toArray(new SubnetConnector[0]));

			if (terminal) {
				new Thread(gw, name).start();
				waitForTermination();
				quit();
			}
			else {
				Thread.currentThread().setName(name);
				gw.run();
			}
		}
		catch (final InterruptedException e) {
			logger.error("initialization of KNX server interrupted");
		}
		catch (final KNXException e) {
			logger.error("initialization of KNX server, " + e.getMessage());
		}
		finally {
			for (final Iterator i = linksToClose.iterator(); i.hasNext();)
				((KNXNetworkLink) i.next()).close();
		}
	}

	/**
	 * Quits a running server gateway launched by this launcher, and shuts down the KNX server.
	 */
	public void quit()
	{
		gw.quit();
		server.shutdown();
	}

	/**
	 * Returns the virtual links created to emulate virtual KNX subnets if requested in the
	 * configuration.
	 * <p>
	 *
	 * @return the server virtual links as array of type KNXNetworkLink, with array length equal to
	 *         the number of virtual links (length 0 for no virtual links used)
	 */
	public KNXNetworkLink[] getVirtualLinks()
	{
		return (KNXNetworkLink[]) virtualLinks.toArray(new KNXNetworkLink[virtualLinks.size()]);
	}

	private void connect(final List linksToClose,
		final List connectors) throws InterruptedException, KNXException
	{
		for (int i = 0; i < xml.svcContainers.size(); i++) {
			final ServiceContainer sc = (ServiceContainer) xml.svcContainers.get(i);

			final KNXNetworkLink link;
			final String subnetType = (String) xml.subnetTypes.get(i);
			if ("virtual".equals(subnetType)) {
				// use network buffer to emulate KNX subnet
				final NetworkBuffer nb = NetworkBuffer.createBuffer("Virtual " + sc.getName());
				final VirtualLink vl = new VirtualLink("virtual link",
						new IndividualAddress(new byte[] { 0, 0 }));
				virtualLinks.add(vl);
				final Configuration config = nb.addConfiguration(vl);
				config.setQueryBufferOnly(false);
				if (xml.subnetDatapoints.containsKey(sc))
					config.setDatapointModel((DatapointModel) xml.subnetDatapoints.get(sc));
				final StateFilter f = new StateFilter();
				config.setFilter(f, f);
				config.activate(true);
				link = config.getBufferedLink();

				final SubnetConnector connector = SubnetConnector.newWithInterfaceType(sc,
						subnetType, null, 1);
				connectors.add(connector);
			}
			else {
				final String subnetArgs = (String) xml.subnetAddresses.get(i);
				SubnetConnector connector;
				if ("knxip".equals(subnetType))
					connector = SubnetConnector.newWithRoutingLink(sc,
							(NetworkInterface) xml.subnetNetIf.get(sc), subnetArgs, 1);
				else if ("user-supplied".equals(subnetType))
					connector = SubnetConnector.newWithUserLink(sc,
							(String) xml.subnetLinkClasses.get(sc), subnetArgs, 1);
				else
					connector = SubnetConnector.newWithInterfaceType(sc, subnetType, subnetArgs, 1);

				logger.info("connect to " + subnetArgs);
				link = connector.openNetworkLink();
				connectors.add(connector);
			}

			server.addServiceContainer(sc);
			linksToClose.add(link);

			final InterfaceObjectServer ios = server.getInterfaceObjectServer();
			if (xml.additionalAddresses.containsKey(sc))
				setAdditionalIndividualAddresses(ios, i + 1, (List) xml.additionalAddresses.get(sc));
			if (xml.groupAddressFilters.containsKey(sc))
				setGroupAddressFilter(ios, i + 1, (List) xml.groupAddressFilters.get(sc));
		}
	}

	private void waitForTermination()
	{
		System.out.println("type 'stop' to stop the gateway and shutdown the server");
		final BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
		try {
			String line;
			while ((line = r.readLine()) != null) {
				if (line.equals("stop"))
					break;
			}
			System.out.println("request to stop server");
		}
		catch (final IOException e) {}
	}

	private void setGroupAddressFilter(final InterfaceObjectServer ios, final int objectInstance,
		final List filter) throws KNXPropertyException
	{
		// create byte array table
		final int size = filter.size();
		final byte[] table = new byte[size * 2];
		int idx = 0;
		for (int i = 0; i < size; i++) {
			final GroupAddress ga = (GroupAddress) filter.get(i);
			table[idx++] = (byte) (ga.getRawAddress() >> 8);
			table[idx++] = (byte) ga.getRawAddress();
		}

		if (table.length > 0) {
			// create interface object and set the address table object property
			ios.addInterfaceObject(InterfaceObject.ADDRESSTABLE_OBJECT);
			ios.setProperty(InterfaceObject.ADDRESSTABLE_OBJECT, objectInstance, PID.TABLE, 1,
					size, table);
		}

		// set the handling of group addressed frames, based on whether we have set a
		// group address filter table or not

		// TODO existence should be ensured in the KNXnet/IP router already?
		boolean routerObject = false;
		final InterfaceObject[] objects = ios.getInterfaceObjects();
		for (int i = 0; i < objects.length; i++) {
			final InterfaceObject io = objects[i];
			if (io.getType() == InterfaceObject.ROUTER_OBJECT)
				routerObject = true;
		}
		if (!routerObject)
			ios.addInterfaceObject(InterfaceObject.ROUTER_OBJECT);
		// TODO explain what the available values are and set them accordingly
		final int PID_MAIN_GROUPCONFIG = 54;
		final int PID_SUB_GROUPCONFIG = 55;
		ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, PID_MAIN_GROUPCONFIG, 1, 1,
				new byte[] { 0 });
		ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, PID_SUB_GROUPCONFIG, 1, 1,
				new byte[] { 0 });
	}

	// set KNXnet/IP server additional individual addresses assigned to individual connections
	private void setAdditionalIndividualAddresses(final InterfaceObjectServer ios,
		final int objectInstance, final List addresses)
		throws KNXPropertyException
	{
		for (int i = 0; i < addresses.size(); i++) {
			final IndividualAddress ia = (IndividualAddress) addresses.get(i);
			ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance,
					PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, i + 1, 1, ia.toByteArray());
		}
	}
}
