/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2018 B. Malinowsky

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

import static tuwien.auto.calimero.device.ios.InterfaceObject.KNXNETIP_PARAMETER_OBJECT;
import static tuwien.auto.calimero.mgmt.PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.datapoint.Datapoint;
import tuwien.auto.calimero.datapoint.DatapointMap;
import tuwien.auto.calimero.datapoint.DatapointModel;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KnxPropertyException;
import tuwien.auto.calimero.dptxlator.PropertyTypes;
import tuwien.auto.calimero.knxnetip.KNXnetIPRouting;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.link.medium.PLSettings;
import tuwien.auto.calimero.link.medium.RFSettings;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.server.gateway.KnxServerGateway;
import tuwien.auto.calimero.server.gateway.SubnetConnector;
import tuwien.auto.calimero.server.knxnetip.DefaultServiceContainer;
import tuwien.auto.calimero.server.knxnetip.KNXnetIPServer;
import tuwien.auto.calimero.server.knxnetip.RoutingServiceContainer;
import tuwien.auto.calimero.server.knxnetip.ServiceContainer;
import tuwien.auto.calimero.xml.KNXMLException;
import tuwien.auto.calimero.xml.XmlInputFactory;
import tuwien.auto.calimero.xml.XmlReader;

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
		public static final String disruptionBuffer = "disruptionBuffer";

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
		public static final String attrNetworkMonitoring = "networkMonitoring";
		/** KNX subnet type: ["ip", "knxip", "usb", "ft12", "tpuart", "virtual", "user-supplied"]. */
		public static final String attrType = "type";
		/** KNX subnet communication medium: { "tp1", "pl110", "knxip", "rf" }. */
		public static final String attrMedium = "medium";
		/** KNX subnet domain address for power-line and RF, as hexadecimal value string. */
		public static final String attrDoA = "domainAddress";
		/** */
		public static final String attrRef = "ref";
		/** */
		public static final String attrExpirationTimeout = "expirationTimeout";

		// the service containers the KNX server will host
		private final List<ServiceContainer> svcContainers = new ArrayList<>();

		// in virtual KNX subnets, the subnetwork can be described by a datapoint model
		private final Map<ServiceContainer, DatapointModel<Datapoint>> subnetDatapoints = new HashMap<>();

		// Holds the network interface for KNX IP subnets, if specified
		private final Map<ServiceContainer, NetworkInterface> subnetNetIf = new HashMap<>();

		// Holds the class name of user-supplied subnet links, if specified
		private final Map<ServiceContainer, String> subnetLinkClasses = new HashMap<>();

		// the following lists contain gateway information, in sequence of the svc containers

		private final List<String> subnetTypes = new ArrayList<>();
		private final List<String> subnetAddresses = new ArrayList<>();

		// list of group addresses used in the group address filter of the KNXnet/IP server
		private final Map<ServiceContainer, List<GroupAddress>> groupAddressFilters = new HashMap<>();
		private final Map<ServiceContainer, List<IndividualAddress>> additionalAddresses = new HashMap<>();
		private final Map<ServiceContainer, Boolean> tunnelingWithNat = new HashMap<>();

		public Map<String, String> load(final String serverConfigUri) throws KNXMLException
		{
			final XmlReader r = XmlInputFactory.newInstance().createXMLReader(serverConfigUri);

			if (r.nextTag() != XmlReader.START_ELEMENT || !r.getLocalName().equals(XmlConfiguration.knxServer))
				throw new KNXMLException(
						"no valid KNX server configuration (no " + XmlConfiguration.knxServer + " element)");

			final Map<String, String> m = new HashMap<>();
			put(m, r, XmlConfiguration.attrName);
			put(m, r, XmlConfiguration.attrFriendly);
			logger = LoggerFactory.getLogger("calimero.server." + r.getAttributeValue(null, XmlConfiguration.attrName));

			while (r.next() != XmlReader.END_DOCUMENT) {
				if (r.getEventType() == XmlReader.START_ELEMENT) {
					final String name = r.getLocalName();
					if (name.equals(XmlConfiguration.discovery)) {
						put(m, r, XmlConfiguration.attrListenNetIf);
						put(m, r, XmlConfiguration.attrOutgoingNetIf);
						put(m, r, XmlConfiguration.attrActivate);
					}
					else if (name.equals(XmlConfiguration.propDefs)) {
						final String res = r.getAttributeValue(null, XmlConfiguration.attrRef);
						// NYI if resource is null, definitions are directly included in element
						if (res != null) {
							if (m.containsKey(XmlConfiguration.attrRef))
								logger.warn("multiple property definition resources, ignore {}, "
										+ "line {}", res, r.getLocation().getLineNumber());
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

		private void readServiceContainer(final XmlReader r) throws KNXMLException
		{
			if (r.getEventType() != XmlReader.START_ELEMENT || !r.getLocalName().equals(XmlConfiguration.svcCont))
				throw new KNXMLException("no service container element");

			final String attrActivate = r.getAttributeValue(null, XmlConfiguration.attrActivate);
			final boolean activate = attrActivate == null || Boolean.parseBoolean(attrActivate);
			final boolean routing = Boolean.parseBoolean(r.getAttributeValue(null, XmlConfiguration.attrRouting));
			final boolean reuse = Boolean.parseBoolean(r.getAttributeValue(null, XmlConfiguration.attrReuseEP));
			if (routing && reuse)
				throw new KNXIllegalArgumentException("with routing activated, reusing control endpoint is not allowed");
			final boolean monitor = Boolean
					.parseBoolean(r.getAttributeValue(null, XmlConfiguration.attrNetworkMonitoring));
			final int port = Integer.parseInt(r.getAttributeValue(null, XmlConfiguration.attrUdpPort));
			final NetworkInterface netif = getNetIf(r);

			String addr = "";
			String subnetType = "";
			int subnetMedium = KNXMediumSettings.MEDIUM_TP1;
			byte[] subnetDoA = null;
			IndividualAddress subnet = null;
			NetworkInterface subnetKnxipNetif = null;
			InetAddress routingMcast = null;
			boolean useNat = false;
			String subnetLinkClass = null;
			DatapointModel<Datapoint> datapoints = null;
			List<GroupAddress> filter = Collections.emptyList();
			List<IndividualAddress> indAddressPool = Collections.emptyList();
			String expirationTimeout = "0";
			int disruptionBufferLowerPort = 0;
			int disruptionBufferUpperPort = 0;

			try {
				routingMcast = InetAddress.getByName(KNXnetIPRouting.DEFAULT_MULTICAST);
			}
			catch (final UnknownHostException ignore) {}

			while (r.nextTag() != XmlReader.END_DOCUMENT) {
				final String name = r.getLocalName();
				if (r.getEventType() == XmlReader.START_ELEMENT) {
					if (name.equals(XmlConfiguration.datapoints)) {
						final DatapointMap<Datapoint> dps = new DatapointMap<>();
						final String res = r.getAttributeValue(null, XmlConfiguration.attrRef);
						final XmlReader dpReader = res != null
								? XmlInputFactory.newInstance().createXMLReader(res) : r;
						dps.load(dpReader);
						datapoints = dps;
					}
					else if (name.equals(XmlConfiguration.subnet)) {
						subnetType = r.getAttributeValue(null, XmlConfiguration.attrType);
						String medium = r.getAttributeValue(null, XmlConfiguration.attrMedium);
						if (subnetType.equals("knxip"))
							medium = "knxip";
						else if (medium == null)
							medium = "tp1";
						subnetMedium = KNXMediumSettings.getMedium(medium);

						final String doa = r.getAttributeValue(null, XmlConfiguration.attrDoA);
						if (doa != null) {
							long l = Long.parseLong(doa, 16);
							final int bytes = subnetMedium == KNXMediumSettings.MEDIUM_RF ? 6 : 2;
							subnetDoA = new byte[bytes];
							for (int i = subnetDoA.length; i-- > 0; l >>>= 8)
								subnetDoA[i] = (byte) l;
						}

						if (subnetType.equals("ip")) {
							subnetKnxipNetif = getNetIf(r);
							final String attr = r.getAttributeValue(null, "useNat");
							useNat = attr != null && Boolean.parseBoolean(attr);
						}
						else if (subnetType.equals("knxip"))
							subnetKnxipNetif = getNetIf(r);
						else if (subnetType.equals("user-supplied"))
							subnetLinkClass = r.getAttributeValue(null, XmlConfiguration.attrClass);
						addr = r.getElementText();
					}
					else if (name.equals(XmlConfiguration.grpAddrFilter))
						filter = readGroupAddressFilter(r);
					else if (name.equals(XmlConfiguration.addAddresses))
						indAddressPool = readAdditionalAddresses(r);
					else if (name.equals(XmlConfiguration.routingMcast)) {
						try {
							routingMcast = InetAddress.getByName(r.getElementText());
						}
						catch (final UnknownHostException uhe) {
							throw new KNXMLException(uhe.getMessage(), r);
						}
					}
					else if (name.equals(XmlConfiguration.disruptionBuffer)) {
						expirationTimeout = r.getAttributeValue(null, attrExpirationTimeout);
						final Optional<String> ports = Optional.ofNullable(r.getAttributeValue(null, attrUdpPort));
						final String[] range = ports.orElse("0-65535").split("-", -1);
						disruptionBufferLowerPort = Integer.parseInt(range[0]);
						disruptionBufferUpperPort = Integer.parseInt(range.length > 1 ? range[1] : range[0]);
					}
					else {
						subnet = new IndividualAddress(r);
					}
				}
				else if (r.getEventType() == XmlReader.END_ELEMENT) {
					if (name.equals(XmlConfiguration.svcCont)) {
						final DefaultServiceContainer sc;
						final KNXMediumSettings s = KNXMediumSettings.create(subnetMedium, subnet);
						if (s.getMedium() == KNXMediumSettings.MEDIUM_PL110)
							((PLSettings) s).setDomainAddress(subnetDoA);
						else if (s.getMedium() == KNXMediumSettings.MEDIUM_RF)
							((RFSettings) s).setDomainAddress(subnetDoA);

						// try to get an IPv4 address from the optional netif
						InetAddress ia = null;
						if (netif != null)
							ia = Collections.list(netif.getInetAddresses()).stream()
									.filter(a -> a instanceof Inet4Address).findFirst().orElse(null);
						final HPAI hpai = new HPAI(ia, port);
						final String netifName = netif != null ? netif.getName() : "any";
						final String svcContName = addr.isEmpty() ? subnetType + "-" + subnet : addr;
						if (routing)
							sc = new RoutingServiceContainer(svcContName, netifName, hpai, s, monitor, routingMcast);
						else
							sc = new DefaultServiceContainer(svcContName, netifName, hpai, s, reuse, monitor);
						sc.setActivationState(activate);
						sc.setDisruptionBuffer(Duration.ofSeconds(Integer.parseInt(expirationTimeout)),
								disruptionBufferLowerPort, disruptionBufferUpperPort);
						subnetTypes.add(subnetType);
						if ("emulate".equals(subnetType) && datapoints != null)
							subnetDatapoints.put(sc, datapoints);
						subnetAddresses.add(addr);
						svcContainers.add(sc);
						subnetNetIf.put(sc, subnetKnxipNetif);
						subnetLinkClasses.put(sc, subnetLinkClass);
						groupAddressFilters.put(sc, filter);
						additionalAddresses.put(sc, indAddressPool);
						tunnelingWithNat.put(sc, useNat);
						return;
					}
				}
			}
		}

		private static List<GroupAddress> readGroupAddressFilter(final XmlReader r)
			throws KNXMLException
		{
			assert r.getLocalName().equals(XmlConfiguration.grpAddrFilter);
			assert r.getEventType() == XmlReader.START_ELEMENT;
			r.nextTag();
			final List<GroupAddress> list = new ArrayList<>();
			while (!(r.getLocalName().equals(XmlConfiguration.grpAddrFilter)
					&& r.getEventType() == XmlReader.END_ELEMENT)) {
				list.add(new GroupAddress(r));
				r.nextTag();
			}
			return list;
		}

		private static List<IndividualAddress> readAdditionalAddresses(final XmlReader r)
			throws KNXMLException
		{
			assert r.getLocalName().equals(XmlConfiguration.addAddresses);
			assert r.getEventType() == XmlReader.START_ELEMENT;
			final List<IndividualAddress> list = new ArrayList<>();
			while (r.nextTag() != XmlReader.END_ELEMENT && !(r.getLocalName().equals(XmlConfiguration.addAddresses))) {
				list.add(new IndividualAddress(r));
			}
			return list;
		}

		private static void put(final Map<String, String> m, final XmlReader r, final String attr)
		{
			m.put(attr, r.getAttributeValue(null, attr));
		}

		private static NetworkInterface getNetIf(final XmlReader r)
		{
			String attr = r.getAttributeValue(null, XmlConfiguration.attrListenNetIf);
			if (attr == null)
				attr = r.getAttributeValue(null, "netif");
			if (attr != null && !"any".equals(attr)) {
				try {
					final NetworkInterface netIf = NetworkInterface.getByName(attr);
					if (netIf != null)
						return netIf;
				}
				catch (final SocketException se) {
					logger.error("while searching for network interface '{}'", attr, se);
				}
				throw new KNXIllegalArgumentException(
						"no network interface found with the specified name '" + attr + "'");
			}
			return null;
		}
	}

	private static Logger logger = LoggerFactory.getLogger("calimero.server");

	private final KNXnetIPServer server;
	private KnxServerGateway gw;

	private XmlConfiguration xml;

	// are we directly started from main, and allow terminal-based termination
	private boolean terminal;

	/**
	 * Main entry routine for starting the KNX server gateway.
	 * <p>
	 * Supported options:
	 * <ul>
	 * <li>--no-stdin &nbsp; do not use STDIN, useful for running in detached mode</li>
	 * </ul>
	 *
	 * @param args server options, followed by the file name or URI to the KNX server XML configuration
	 */
	public static void main(final String[] args)
	{
		if (args.length == 0) {
			logger.info("supply file name/URI for the KNX server configuration");
			return;
		}
		final String configUri = args[args.length - 1];
		try {
			final Launcher sr = new Launcher(configUri);
			final boolean detached = "--no-stdin".equals(args[0]);
			sr.terminal = !detached;
			sr.run();
		}
		catch (final KNXException e) {
			logger.error("loading configuration from " + configUri, e);
		}
	}

	/**
	 * Launcher constructor.
	 *
	 * @param configUri location/file of KNX server and gateway configuration
	 * @throws KNXException on error loading property definitions from a resource (if specified in the configuration)
	 */
	public Launcher(final String configUri) throws KNXException
	{
		xml = new XmlConfiguration();
		final Map<String, String> config = xml.load(configUri);

		server = new KNXnetIPServer(config.get("name"), config.get("friendlyName"));
		// load property definitions
		final InterfaceObjectServer ios = server.getInterfaceObjectServer();
		if (config.containsKey("ref"))
			ios.loadDefinitions(config.get("ref"));
		final String netIfListen = config.get(XmlConfiguration.attrListenNetIf);
		server.setOption(KNXnetIPServer.OPTION_DISCOVERY_INTERFACES, netIfListen);
		final String netIfOutgoing = config.get(XmlConfiguration.attrOutgoingNetIf);
		server.setOption(KNXnetIPServer.OPTION_OUTGOING_INTERFACE, netIfOutgoing);
		final String runDiscovery = config.computeIfAbsent(XmlConfiguration.attrActivate, v -> "true");
		server.setOption(KNXnetIPServer.OPTION_DISCOVERY_DESCRIPTION, runDiscovery);

		// output the configuration we loaded
		logger.info("KNXnet/IP discovery network interfaces: listen on [{}], send on [{}]", netIfListen, netIfOutgoing);
		for (int i = 0; i < xml.svcContainers.size(); i++) {
			final ServiceContainer sc = xml.svcContainers.get(i);
			final String activated = sc.isActivated() ? "" : " [not activated]";
			String mcast = "disabled";
			if ((sc instanceof RoutingServiceContainer))
				mcast = "multicast group " + ((RoutingServiceContainer) sc).routingMulticastAddress().getHostAddress();
			final String type = xml.subnetTypes.get(i);
			String filter = "";
			if (xml.groupAddressFilters.containsKey(sc) && !xml.groupAddressFilters.get(sc).isEmpty())
				filter = "\n\tGroup address filter " + xml.groupAddressFilters.get(sc);
			String datapoints = "";
			if (xml.subnetDatapoints.containsKey(sc))
				datapoints = "\n\tDatapoints "
						+ ((DatapointMap<Datapoint>) xml.subnetDatapoints.get(sc)).getDatapoints();

			// @formatter:off
			final String info = String.format("Service container '%s'%s:%n"
					+ "\tlisten on %s, KNXnet/IP routing %s%n"
					+ "\t%s connection: %s%s%s",
					sc.getName(), activated, sc.networkInterface(), mcast, type, sc.getMediumSettings(), filter, datapoints);
			// @formatter:on
			logger.info(info);
		}
	}

	@Override
	public void run()
	{
		final List<SubnetConnector> connectors = new ArrayList<>();
		final List<KNXNetworkLink> linksToClose = new ArrayList<>();

		try {
			connect(linksToClose, connectors);
			xml = null;
			final String name = server.getName();
			// create a gateway which forwards and answers most of the KNX stuff
			// if no connectors were created, gateway will throw
			gw = new KnxServerGateway(name, server, connectors.toArray(new SubnetConnector[0]));

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
		catch (KNXException | RuntimeException e) {
			logger.error("initialization of KNX server failed", e);
		}
		finally {
			for (final Iterator<KNXNetworkLink> i = linksToClose.iterator(); i.hasNext();)
				i.next().close();
		}
	}

	/**
	 * Quits a running server gateway launched by this launcher, and shuts down the KNX server.
	 */
	public void quit()
	{
		if (gw != null)
			gw.quit();
	}

	/**
	 * Returns the KNX server gateway.
	 *
	 * @return the gateway
	 */
	public final KnxServerGateway getGateway()
	{
		return gw;
	}

	private void connect(final List<KNXNetworkLink> linksToClose,
		final List<SubnetConnector> connectors) throws InterruptedException, KNXException
	{
		for (int i = 0; i < xml.svcContainers.size(); i++) {
			final ServiceContainer sc = xml.svcContainers.get(i);
			final String subnetType = xml.subnetTypes.get(i);
			final String subnetArgs = xml.subnetAddresses.get(i);
			final String activated = sc.isActivated() ? "" : " [not activated]";
			logger.info("setup {} subnet '{}'{}", subnetType, subnetArgs, activated);

			final NetworkInterface netif = xml.subnetNetIf.get(sc);
			final SubnetConnector connector;

			if ("knxip".equals(subnetType))
				connector = SubnetConnector.newWithRoutingLink(sc, netif, subnetArgs);
			else if ("ip".equals(subnetType))
				connector = SubnetConnector.newWithTunnelingLink(sc, netif, xml.tunnelingWithNat.get(sc), subnetArgs);
			else if ("user-supplied".equals(subnetType))
				connector = SubnetConnector.newWithUserLink(sc, xml.subnetLinkClasses.get(sc), subnetArgs);
			else if ("emulate".equals(subnetType))
				connector = SubnetConnector.newCustom(sc, "emulate", xml.subnetDatapoints.get(sc));
			else
				connector = SubnetConnector.newWithInterfaceType(sc, subnetType, subnetArgs);

			if (sc.isActivated())
				linksToClose.add(connector.openNetworkLink());
			connectors.add(connector);
			server.addServiceContainer(sc);

			final int groupAddrTable = i + 1;
			final InterfaceObjectServer ios = server.getInterfaceObjectServer();
			if (xml.additionalAddresses.containsKey(sc))
				setAdditionalIndividualAddresses(ios, groupAddrTable, xml.additionalAddresses.get(sc));
			if (xml.groupAddressFilters.containsKey(sc))
				setGroupAddressFilter(ios, groupAddrTable, xml.groupAddressFilters.get(sc));
		}
	}

	private void waitForTermination()
	{
		System.out.println("type 'stop' to stop the gateway and shutdown the server");
		final BufferedReader r = new BufferedReader(new InputStreamReader(System.in, Charset.defaultCharset()));
		try {
			String line;
			while ((line = r.readLine()) != null) {
				if (line.equals("stop"))
					break;
				if (line.equals("stat"))
					System.out.println(gw);
			}
			System.out.println("request to stop server");
		}
		catch (final IOException e) {}
	}

	private enum RoutingConfig { Reserved, All, None, Table };

	private static void setGroupAddressFilter(final InterfaceObjectServer ios, final int objectInstance,
		final List<GroupAddress> filter) throws KnxPropertyException
	{
		// create byte array table
		final int size = filter.size();
		final byte[] table = new byte[size * 2];
		int idx = 0;
		for (int i = 0; i < size; i++) {
			final GroupAddress ga = filter.get(i);
			table[idx++] = (byte) (ga.getRawAddress() >> 8);
			table[idx++] = (byte) ga.getRawAddress();
		}

		if (table.length > 0) {
			ensureInterfaceObjectInstance(ios, InterfaceObject.ADDRESSTABLE_OBJECT, objectInstance);
			ios.setProperty(InterfaceObject.ADDRESSTABLE_OBJECT, objectInstance, PID.TABLE, 1, size, table);
		}

		ensureInterfaceObjectInstance(ios, InterfaceObject.ROUTER_OBJECT, objectInstance);

		// set the handling of group addressed frames, based on whether we have set a
		// group address filter table or not
		final RoutingConfig route = table.length > 0 ? RoutingConfig.Table : RoutingConfig.All;
		ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, PID.MAIN_LCGROUPCONFIG, 1, 1,
				(byte) (1 << 4 | RoutingConfig.All.ordinal() << 2 | route.ordinal()));
		// by default, we don't check the group address filter table for group frames from subnetworks
		ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, PID.SUB_LCGROUPCONFIG, 1, 1,
				(byte) (RoutingConfig.All.ordinal() << 2 | RoutingConfig.All.ordinal()));
	}

	private static void ensureInterfaceObjectInstance(final InterfaceObjectServer ios,
		final int interfaceType, final int instance)
	{
		long l = Arrays.asList(ios.getInterfaceObjects()).stream()
				.filter((io) -> io.getType() == interfaceType).collect(Collectors.counting());
		// create interface object and set the address table object property
		while (l++ < instance)
			ios.addInterfaceObject(interfaceType);
	}

	// set KNXnet/IP server additional individual addresses assigned to individual connections
	private void setAdditionalIndividualAddresses(final InterfaceObjectServer ios, final int objectInstance,
		final List<IndividualAddress> addresses) throws KnxPropertyException
	{
		final int objectIndex = objectIndex(KNXNETIP_PARAMETER_OBJECT, objectInstance);
		final int size = addresses.size();
		final Description d = new Description(objectIndex, KNXNETIP_PARAMETER_OBJECT, ADDITIONAL_INDIVIDUAL_ADDRESSES,
				0, PropertyTypes.PDT_UNSIGNED_INT, true, size, size, 3, 3);
		ios.setDescription(d, true);

		for (int i = 0; i < size; i++) {
			final IndividualAddress ia = addresses.get(i);
			ios.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance, ADDITIONAL_INDIVIDUAL_ADDRESSES, i + 1, 1,
					ia.toByteArray());
		}
	}

	private int objectIndex(final int objectType, final int objectInstance)
	{
		int instance = 0;
		for (final InterfaceObject io : server.getInterfaceObjectServer().getInterfaceObjects()) {
			if (io.getType() == objectType && ++instance == objectInstance)
				return io.getIndex();
		}
		return -1;
	}
}
