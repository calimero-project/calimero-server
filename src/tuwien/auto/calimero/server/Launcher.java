/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2020 B. Malinowsky

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

import static java.util.Optional.ofNullable;
import static tuwien.auto.calimero.device.ios.InterfaceObject.ADDRESSTABLE_OBJECT;
import static tuwien.auto.calimero.device.ios.InterfaceObject.KNXNETIP_PARAMETER_OBJECT;
import static tuwien.auto.calimero.mgmt.PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.Keyring;
import tuwien.auto.calimero.KnxRuntimeException;
import tuwien.auto.calimero.KnxSecureException;
import tuwien.auto.calimero.datapoint.Datapoint;
import tuwien.auto.calimero.datapoint.DatapointMap;
import tuwien.auto.calimero.datapoint.DatapointModel;
import tuwien.auto.calimero.datapoint.StateDP;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KnxPropertyException;
import tuwien.auto.calimero.dptxlator.DPTXlatorDate;
import tuwien.auto.calimero.dptxlator.DPTXlatorDateTime;
import tuwien.auto.calimero.dptxlator.DPTXlatorTime;
import tuwien.auto.calimero.dptxlator.PropertyTypes;
import tuwien.auto.calimero.knxnetip.SecureConnection;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.KNXNetworkLinkIP;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.link.medium.PLSettings;
import tuwien.auto.calimero.link.medium.RFSettings;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.server.ServerConfiguration.Container;
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
public class Launcher implements Runnable, AutoCloseable
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


		private final List<ServerConfiguration.Container> containers = new ArrayList<>();

		public static ServerConfiguration from(final URI serverConfigUri) {
			final var xmlConfiguration = new XmlConfiguration();
			final var config = xmlConfiguration.load(serverConfigUri.toString());
			final boolean discovery = Boolean.parseBoolean(config.get(attrActivate));
			final var name = config.get(attrName);
			final var friendly = config.get(attrFriendly);
			final var listen = List.of(config.get(attrListenNetIf).split(","));
			final var outgoing = List.of(config.get(attrOutgoingNetIf).split(","));
			return new ServerConfiguration(name, friendly, discovery, listen, outgoing, xmlConfiguration.containers);
		}

		public Map<String, String> load(final String serverConfigUri) throws KNXMLException
		{
			final XmlReader r = XmlInputFactory.newInstance().createXMLReader(serverConfigUri);

			if (r.nextTag() != XmlReader.START_ELEMENT || !r.getLocalName().equals(XmlConfiguration.knxServer))
				throw new KNXMLException("no valid KNX server configuration (no " + XmlConfiguration.knxServer + " element)");

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
			final boolean monitor = Boolean.parseBoolean(r.getAttributeValue(null, XmlConfiguration.attrNetworkMonitoring));
			final int port = Integer.parseUnsignedInt(r.getAttributeValue(null, XmlConfiguration.attrUdpPort));
			final NetworkInterface netif = getNetIf(r);

			final Function<String, String> expandHome = v -> v.replaceFirst("^~", System.getProperty("user.home"));

			// look for a server keyfile
			final Path keyfile = ofNullable(r.getAttributeValue(null, "keyfile")).map(expandHome).map(Paths::get)
					.orElse(null);
			// look for a keyring configuration
			final var keyring = ofNullable(r.getAttributeValue(null, "keyring")).map(expandHome)
					.map(Keyring::load).orElse(null);

			final String attrSecuredServices = r.getAttributeValue(null, "securedServices");
			final int securedServices = attrSecuredServices == null ? 0x3f : Integer.decode(attrSecuredServices);

			final boolean udpOnly = Boolean.parseBoolean(r.getAttributeValue(null, "udpOnly"));

			String addr = "";
			String subnetType = "";
			int subnetMedium = KNXMediumSettings.MEDIUM_TP1;
			byte[] subnetDoA = null;
			IndividualAddress subnet = null;
			NetworkInterface subnetKnxipNetif = null;
			InetAddress routingMcast = KNXNetworkLinkIP.DefaultMulticast;
			int latencyTolerance = 1000; // ms
			boolean useNat = false;
			String subnetLinkClass = null;
			// in virtual KNX subnets, the subnetwork can be described by a datapoint model
			DatapointModel<Datapoint> datapoints = null;
			List<GroupAddress> filter = Collections.emptyList();
			List<IndividualAddress> indAddressPool = new ArrayList<>();
			String expirationTimeout = "0";
			int disruptionBufferLowerPort = 0;
			int disruptionBufferUpperPort = 0;
			final var tunnelingUserToAddresses = new HashMap<Integer, List<IndividualAddress>>();

			final var timeServerDatapoints = new ArrayList<StateDP>();

			int objectInstance = 0;

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
					else if (name.equals("tunnelingUsers"))
						tunnelingUserToAddresses.putAll(readTunnelingUsers(r));
					else if (name.equals("routing")) {
						try {
							latencyTolerance = ofNullable(r.getAttributeValue(null, "latencyTolerance"))
									.map(Integer::parseUnsignedInt).orElse(2000);
							final String mcast = r.getElementText();
							if (!mcast.isEmpty())
								routingMcast = InetAddress.getByName(mcast);
						}
						catch (final UnknownHostException uhe) {
							throw new KNXMLException(uhe.getMessage(), r);
						}
						catch (final NumberFormatException e) {
							throw new KNXMLException("invalid latency tolerance", r);
						}
					}
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
						final Optional<String> ports = ofNullable(r.getAttributeValue(null, attrUdpPort));
						final String[] range = ports.orElse("0-65535").split("-", -1);
						disruptionBufferLowerPort = Integer.parseUnsignedInt(range[0]);
						disruptionBufferUpperPort = Integer.parseUnsignedInt(range.length > 1 ? range[1] : range[0]);
					}
					else if (name.equals("timeServer")) {
						final var formats = List.of(DPTXlatorDate.DPT_DATE.getID(),
								DPTXlatorTime.DPT_TIMEOFDAY.getID(), DPTXlatorDateTime.DPT_DATE_TIME.getID());
						while (r.nextTag() == XmlReader.START_ELEMENT) {
							final var datapoint = new StateDP(r);
							if (!formats.contains(datapoint.getDPT()))
								throw new KNXMLException("invalid time server datapoint type '" + datapoint.getDPT()
										+ "', supported are " + formats);
							timeServerDatapoints.add(datapoint);
						}
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
							sc = new RoutingServiceContainer(svcContName, netifName, hpai, s, monitor, udpOnly,
									routingMcast, Duration.ofMillis(latencyTolerance));
						else
							sc = new DefaultServiceContainer(svcContName, netifName, hpai, s, reuse, monitor, udpOnly);
						sc.setActivationState(activate);
						sc.setDisruptionBuffer(Duration.ofSeconds(Integer.parseUnsignedInt(expirationTimeout)),
								disruptionBufferLowerPort, disruptionBufferUpperPort);

						++objectInstance;
						final var connector = subnetConnector(sc, objectInstance, subnetType, addr, subnetKnxipNetif,
								useNat, subnetLinkClass, datapoints);
						var config = new Container(indAddressPool, connector, filter, timeServerDatapoints);

						if (keyring != null) {
							final var interfaces = keyring.interfaces().get(subnet);
							if (interfaces == null)
								throw new KnxSecureException("no interfaces found in keyring for host " + subnet);
							for (final var iface : interfaces) {
								tunnelingUserToAddresses.computeIfAbsent(iface.user(), ArrayList::new).add(iface.address());
								indAddressPool.add(iface.address());
							}
						}

						Map<String, byte[]> readKeyfile = null;
						if (keyfile != null)
							readKeyfile = readKeyfile(keyfile);

						if (keyring != null || readKeyfile != null)
							config = new Container(indAddressPool, securedServices, tunnelingUserToAddresses, keyring,
									readKeyfile, connector, filter, timeServerDatapoints);
						containers.add(config);
						return;
					}
				}
			}
		}

		private SubnetConnector subnetConnector(final ServiceContainer sc, final int objectInstance,
				final String subnetType, final String subnetArgs, final NetworkInterface netif, final boolean useNat,
				final String subnetLinkClass, final DatapointModel<Datapoint> datapoints) {

			switch (subnetType) {
			case "knxip": return SubnetConnector.newWithRoutingLink(sc, netif, subnetArgs);
			case "ip": return SubnetConnector.newWithTunnelingLink(sc, netif, useNat, subnetArgs);
			case "tpuart": return SubnetConnector.newWithTpuartLink(sc, subnetArgs);
			case "user-supplied": return SubnetConnector.newWithUserLink(sc, subnetLinkClass, subnetArgs);
			case "emulate":
				return datapoints != null ? SubnetConnector.newCustom(sc, "emulate", datapoints)
						: SubnetConnector.newCustom(sc, "emulate");
			default: return SubnetConnector.newWithInterfaceType(sc, subnetType, subnetArgs);
			}
		}

		private static Map<String, byte[]> readKeyfile(final Path keyfile) {
			try (var lines = Files.lines(keyfile)) {
				// ignore comments, limit keys to words with dot separator, require '='
				final var matcher = Pattern.compile("^[^/#][\\w\\.]+\\s*=.+$").asMatchPredicate();
				final Map<String, byte[]> keys = lines.filter(matcher)
						.map(line -> line.split("=", 2))
						.map(XmlConfiguration::hashDeviceOrUserPassword)
						.collect(Collectors.toMap(Entry::getKey, Entry::getValue));
				return keys;
			}
			catch (final IOException e) {
				throw new KNXMLException("reading key file '" + keyfile + "'", e);
			}
		}

		private static Entry<String, byte[]> hashDeviceOrUserPassword(final String[] entry) {
			final var key = entry[0].trim();
			final var value = entry[1].trim();
			final var chars = value.toCharArray();
			if ("keyring.pwd".equals(key))
				return Map.entry(key, value.getBytes(StandardCharsets.US_ASCII));
			if ("device.pwd".equals(key))
				return Map.entry("device.key", SecureConnection.hashDeviceAuthenticationPassword(chars));
			if (key.endsWith("pwd"))
				return Map.entry(key.replace(".pwd", ""), SecureConnection.hashUserPassword(chars));
			return Map.entry(key, DataUnitBuilder.fromHex(value));
		}

		private static List<GroupAddress> readGroupAddressFilter(final XmlReader r) throws KNXMLException
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

		private static List<IndividualAddress> readAdditionalAddresses(final XmlReader r) throws KNXMLException
		{
			assert r.getLocalName().equals(XmlConfiguration.addAddresses);
			assert r.getEventType() == XmlReader.START_ELEMENT;
			final List<IndividualAddress> list = new ArrayList<>();
			while (r.nextTag() != XmlReader.END_ELEMENT && !(r.getLocalName().equals(XmlConfiguration.addAddresses))) {
				list.add(new IndividualAddress(r));
			}
			return list;
		}

		private static Map<Integer, List<IndividualAddress>> readTunnelingUsers(final XmlReader r) {
			final var userToAddresses = new HashMap<Integer, List<IndividualAddress>>();
			while (r.nextTag() != XmlReader.END_ELEMENT && !r.getLocalName().equals("tunnelingUsers")) {
				final var user = Integer.parseUnsignedInt(r.getAttributeValue(null, "id"));
				userToAddresses.put(user, readTunnelingUserAddresses(r));
			}
			return userToAddresses;
		}

		private static List<IndividualAddress> readTunnelingUserAddresses(final XmlReader r) {
			final var addresses = new ArrayList<IndividualAddress>();
			while (r.nextTag() != XmlReader.END_ELEMENT && !r.getLocalName().equals("user"))
				addresses.add(new IndividualAddress(r));
			return addresses;
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

	private final ServerConfiguration config;

	private final KNXnetIPServer server;
	private KnxServerGateway gw;

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
		final boolean detached = "--no-stdin".equals(args[0]);
		try (var launcher = new Launcher(configUri)) {
			launcher.terminal = !detached;
			Runtime.getRuntime().addShutdownHook(new Thread(launcher::quit, launcher.server.getName() + " shutdown"));
			launcher.run();
		}
	}

	/**
	 * Launcher constructor.
	 *
	 * @param configUri location/file of KNX server and gateway configuration
	 */
	public Launcher(final String configUri)
	{
		config = XmlConfiguration.from(URI.create(configUri));
		server = new KNXnetIPServer(config);

		// output the configuration we loaded
		logger.info("{}", config);
		for (final var contConfig : config.containers()) {
			logger.info("{}", contConfig);
		}
	}

	@Override
	public void run()
	{
		final List<KNXNetworkLink> linksToClose = new ArrayList<>();

		try {
			connect(linksToClose, config.containers());
			gw = new KnxServerGateway(server, config);

			final String name = server.getName();
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
	 * Returns the KNX server gateway.
	 *
	 * @return the gateway
	 */
	public final KnxServerGateway getGateway() { return gw; }

	/**
	 * Quits a running server gateway launched by this launcher, and shuts down the KNX server.
	 */
	public void quit() {
		close();
	}

	/**
	 * Shuts down a running KNX server and gateway launched by this launcher.
	 */
	@Override
	public void close() {
		server.shutdown();
	}

	private void connect(final List<KNXNetworkLink> linksToClose, final List<Container> containers)
			throws InterruptedException, KNXException
	{
		int objectInstance = 0;

		for (final var container : containers) {
			final var connector = container.subnetConnector();
			final ServiceContainer sc = connector.getServiceContainer();
			server.addServiceContainer(sc);

			++objectInstance;
			final InterfaceObjectServer ios = server.getInterfaceObjectServer();
			ensureInterfaceObjectInstance(ios, InterfaceObject.ROUTER_OBJECT, objectInstance);
			ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, PID.LOAD_STATE_CONTROL, 1, 1, (byte) 1);
			ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, PID.MEDIUM_STATUS, 1, 1, (byte) 1);
			ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, PID.MAIN_LCCONFIG, 1, 1, (byte) 1);
			ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, PID.SUB_LCCONFIG, 1, 1, (byte) 1);
			ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, 56, 1, 1, (byte) 0);

			ios.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance, PID.KNXNETIP_DEVICE_STATE, 1, 1, (byte) 1);

			container.keyring().ifPresent(keyring -> decodeKeyring(sc, container));
			final var keyfile = container.keyfile();
			server.configureSecurity(sc, keyfile, container.securedServices());
			keyfile.values().forEach(key -> Arrays.fill(key, (byte) 0));

			final var additionalAddresses = container.additionalAddresses();
			if (!additionalAddresses.isEmpty())
				setAdditionalIndividualAddresses(ios, objectInstance, additionalAddresses);

			setGroupAddressFilter(ios, objectInstance, container.groupAddressFilter());

			final String subnetType = connector.interfaceType();
			final String subnetArgs = connector.linkArguments();
			final String activated = sc.isActivated() ? "" : " [not activated]";

			final String subnetName = subnetArgs.isEmpty()
					? subnetType + "-" + sc.getMediumSettings().getDeviceAddress() : subnetArgs;
			logger.info("setup {} subnet '{}'{}", subnetType, subnetName, activated);

			if ("tpuart".equals(subnetType)) {
				final int oi = objectInstance;
				connector.setAckOnTp(() -> acknowledgeOnTp(sc, oi));
			}

			if (sc.isActivated())
				linksToClose.add(connector.openNetworkLink());

			final boolean routing = sc instanceof RoutingServiceContainer;
			final boolean useServerAddress = !routing && sc.reuseControlEndpoint();
			final var tunnelingUsers = container.tunnelingUsers();
			if (!tunnelingUsers.isEmpty()) {
				final var serverAddress = useServerAddress ? sc.getMediumSettings().getDeviceAddress() : null;
				setTunnelingUsers(ios, objectInstance, tunnelingUsers, additionalAddresses, serverAddress);
			}
			else {
				// list all additional addresses as tunneling addresses
				var size = useServerAddress ? 1 : 0; // also reserve entry for server address if we're using it
				size += additionalAddresses.size();
				final byte[] addrIndices = new byte[size];
				var idx = useServerAddress ? 0 : 1;
				for (int k = 0; k < addrIndices.length; k++)
					addrIndices[k] = (byte) idx++;
				setTunnelingAddresses(ios, objectInstance, addrIndices);
			}
		}
	}

	private void decodeKeyring(final ServiceContainer sc, final Container config) {
		final var keyring = config.keyring().orElseThrow();
		final var keyfile = config.keyfile();
		char[] pwd = null;
		if (keyfile.containsKey("keyring.pwd")) {
			final var pwdBytes = keyfile.get("keyring.pwd");
			pwd = new char[pwdBytes.length];
			for (int k = 0; k < pwdBytes.length; k++) {
				final byte b = pwdBytes[k];
				pwd[k] = (char) b;
			}
		}
		else {
			final var console = System.console();
			if (console != null)
				pwd = console.readPassword("Keyring password: ");
		}
		if (pwd == null || pwd.length == 0) {
			logger.error("no keyring password (not in keyfile nor via console) -- exit");
			System.exit(-1);
		}

		final var host = sc.getMediumSettings().getDeviceAddress();
		final var device = keyring.devices().get(host);

		final var decrypted = new HashMap<String, byte[]>();

		final var authKey = SecureConnection
				.hashDeviceAuthenticationPassword(keyring.decryptPassword(device.authentication(), pwd));
		decrypted.put("device.key", authKey);
		final var mgmtKey = SecureConnection.hashUserPassword(keyring.decryptPassword(device.password(), pwd));
		decrypted.put("user.1", mgmtKey);

		if (sc instanceof RoutingServiceContainer) {
			final RoutingServiceContainer rsc = (RoutingServiceContainer) sc;

			final var enc = (byte[]) keyring.configuration().get(rsc.routingMulticastAddress());
			final var groupKey = keyring.decryptKey(enc, pwd);
			decrypted.put("group.key", groupKey);
		}

		final var interfaces = keyring.interfaces().get(host);
		for (final var iface : interfaces) {
			final var key = SecureConnection.hashUserPassword(keyring.decryptPassword(iface.password(), pwd));
			decrypted.put("user." + iface.user(), key);
		}

		keyfile.putAll(decrypted);
		Arrays.fill(pwd, (char) 0);
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
				0, PropertyTypes.PDT_UNSIGNED_INT, true, size, Math.max(size, 30), 3, 3);
		ios.setDescription(d, true);

		for (int i = 0; i < size; i++) {
			final IndividualAddress ia = addresses.get(i);
			ios.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance, ADDITIONAL_INDIVIDUAL_ADDRESSES, i + 1, 1,
					ia.toByteArray());
		}
	}

	private static final int pidTunnelingAddresses = 79;
	private static final int pidTunnelingUsers = 97;

	private void setTunnelingUsers(final InterfaceObjectServer ios, final int objectInstance,
		final Map<Integer, List<IndividualAddress>> userToAddresses, final List<IndividualAddress> additionalAddresses,
		final IndividualAddress ctrlEndpoint) {

		// address indices are sorted in natural order
		final var addrIndices = userToAddresses.entrySet().stream().map(Entry::getValue).flatMap(List::stream)
				.map(addr -> addressIndex(addr, additionalAddresses, ctrlEndpoint)).sorted().distinct()
				.collect(ByteArrayOutputStream::new, ByteArrayOutputStream::write, (r1, r2) -> {}).toByteArray();
		setTunnelingAddresses(ios, objectInstance, addrIndices);

		// tunneling user entries are sorted first by user <, then by tunneling addr idx <
		final var userToAddrIdx = new ByteArrayOutputStream();
		for (final var user : new TreeMap<>(userToAddresses).entrySet()) {
			final var tunnelingIndicesSet = new TreeSet<Integer>();
			for (final IndividualAddress addr : user.getValue()) {
				final var idx = additionalAddresses.indexOf(addr);
				final var tunnelingIdx = idx == -1 ? 0 : Arrays.binarySearch(addrIndices, (byte) (idx + 1));
				tunnelingIndicesSet.add(tunnelingIdx + 1);
			}
			// create sorted mapping for user -> tunneling idx
			for (final var idx : tunnelingIndicesSet) {
				userToAddrIdx.write(user.getKey());
				userToAddrIdx.write(idx);
			}
		}
		ios.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance, pidTunnelingUsers, 1, userToAddrIdx.size() / 2,
				userToAddrIdx.toByteArray());
	}

	private void setTunnelingAddresses(final InterfaceObjectServer ios, final int objectInstance,
		final byte[] addrIndices) {
		ios.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance, pidTunnelingAddresses, 1, addrIndices.length,
				addrIndices);
	}

	// ctrlEndpoint of null indicates we can't use the server ctrlEndpoint address (i.e., routing enabled)
	private static int addressIndex(final IndividualAddress addr, final List<IndividualAddress> additionalAddresses,
		final IndividualAddress ctrlEndpoint) {
		final var idx = additionalAddresses.indexOf(addr);
		if (idx == -1 && !addr.equals(ctrlEndpoint))
			throw new KnxRuntimeException("tunneling address " + addr + " is not an additional address");
		return idx + 1;
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

	private List<KNXAddress> acknowledgeOnTp(final ServiceContainer sc, final int objectInstance) {
		final var ack = new ArrayList<KNXAddress>();
		ack.add(sc.getMediumSettings().getDeviceAddress());
		final var ios = server.getInterfaceObjectServer();
		try {
			var buf = ByteBuffer.wrap(ios.getProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance,
					ADDITIONAL_INDIVIDUAL_ADDRESSES, 1, Integer.MAX_VALUE));
			while (buf.hasRemaining())
				ack.add(new IndividualAddress(buf.getShort() & 0xffff));

			buf = ByteBuffer
					.wrap(ios.getProperty(ADDRESSTABLE_OBJECT, objectInstance, PID.TABLE, 1, Integer.MAX_VALUE));
			while (buf.hasRemaining())
				ack.add(new GroupAddress(buf.getShort() & 0xffff));
		}
		catch (final KnxPropertyException e) {
			logger.warn("querying default acknowledge addresses for TP-UART ({})", e.getMessage());
		}

		return ack;
	}
}
