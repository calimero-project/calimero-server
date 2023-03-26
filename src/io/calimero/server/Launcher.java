/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2023 B. Malinowsky

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

package io.calimero.server;

import static io.calimero.device.ios.InterfaceObject.ADDRESSTABLE_OBJECT;
import static io.calimero.device.ios.InterfaceObject.KNXNETIP_PARAMETER_OBJECT;
import static io.calimero.mgmt.PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES;

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
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
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

import io.calimero.DataUnitBuilder;
import io.calimero.GroupAddress;
import io.calimero.IndividualAddress;
import io.calimero.KNXAddress;
import io.calimero.KNXFormatException;
import io.calimero.KNXIllegalArgumentException;
import io.calimero.KnxRuntimeException;
import io.calimero.datapoint.Datapoint;
import io.calimero.datapoint.DatapointMap;
import io.calimero.datapoint.DatapointModel;
import io.calimero.datapoint.StateDP;
import io.calimero.device.ios.InterfaceObject;
import io.calimero.device.ios.InterfaceObjectServer;
import io.calimero.device.ios.KnxPropertyException;
import io.calimero.device.ios.KnxipParameterObject;
import io.calimero.dptxlator.DPTXlatorDate;
import io.calimero.dptxlator.DPTXlatorDateTime;
import io.calimero.dptxlator.DPTXlatorTime;
import io.calimero.dptxlator.PropertyTypes;
import io.calimero.internal.Executor;
import io.calimero.knxnetip.SecureConnection;
import io.calimero.knxnetip.util.HPAI;
import io.calimero.knxnetip.util.ServiceFamiliesDIB.ServiceFamily;
import io.calimero.link.KNXNetworkLinkIP;
import io.calimero.link.medium.KNXMediumSettings;
import io.calimero.link.medium.PLSettings;
import io.calimero.link.medium.RFSettings;
import io.calimero.mgmt.Description;
import io.calimero.mgmt.PropertyAccess.PID;
import io.calimero.secure.Keyring;
import io.calimero.secure.KnxSecureException;
import io.calimero.secure.Security;
import io.calimero.server.ServerConfiguration.Container;
import io.calimero.server.gateway.KnxServerGateway;
import io.calimero.server.gateway.SubnetConnector;
import io.calimero.server.knxnetip.DefaultServiceContainer;
import io.calimero.server.knxnetip.KNXnetIPServer;
import io.calimero.server.knxnetip.RoutingServiceContainer;
import io.calimero.server.knxnetip.ServiceContainer;
import io.calimero.xml.KNXMLException;
import io.calimero.xml.XmlInputFactory;
import io.calimero.xml.XmlReader;

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
		public static final String svcCont = "serviceContainer";
		/** */
		public static final String grpAddrFilter = "groupAddressFilter";
		/** */
		public static final String addAddresses = "additionalAddresses";
		/** */
		public static final String attrActivate = "activate";
		/** */
		public static final String attrListenNetIf = "listenNetIf";
		/** */
		public static final String attrUdpPort = "udpPort";
		/** KNX subnet type: ["ip", "knxip", "usb", "ft12", "tpuart", "virtual", "user-supplied"]. */
		public static final String attrType = "type";
		/** KNX subnet communication medium: { "tp1", "pl110", "knxip", "rf" }. */
		public static final String attrMedium = "medium";

		private static final Function<String, String> expandHome = v -> v.replaceFirst("^~",
				System.getProperty("user.home"));

		private final URI uri;
		private final List<ServerConfiguration.Container> containers = new ArrayList<>();
		private Path appData;


		public static ServerConfiguration from(final URI serverConfigUri) {
			return new XmlConfiguration(serverConfigUri).load();
		}

		private XmlConfiguration(final URI serverConfigUri) { uri = serverConfigUri; }

		private ServerConfiguration load() {
			final XmlReader r = XmlInputFactory.newInstance().createXMLReader(uri.toString());
			if (r.nextTag() != XmlReader.START_ELEMENT || !r.getLocalName().equals(XmlConfiguration.knxServer))
				throw new KNXMLException("no valid KNX server configuration (no " + XmlConfiguration.knxServer + " element)");

			final var serverName = attr(r, "name").orElseThrow();
			final String friendly = attr(r, "friendlyName").orElseThrow();
			appData = attr(r, "appData").map(expandHome).map(Path::of).orElse(Path.of("")).toAbsolutePath();

			boolean discovery = true;
			var listen = "";
			var outgoing = "";

			while (r.next() != XmlReader.END_DOCUMENT) {
				if (r.getEventType() == XmlReader.START_ELEMENT) {
					switch (r.getLocalName()) {
						case "discovery" -> {
							discovery = attr(r, XmlConfiguration.attrActivate).map(Boolean::parseBoolean).orElse(true);
							listen = attr(r, XmlConfiguration.attrListenNetIf).orElse("");
							outgoing = attr(r, "outgoingNetIf").orElse("");
						}
						case XmlConfiguration.svcCont -> readServiceContainer(r);
					}
				}
			}
			final URI iosResource = appData.resolve(serverName + "-ios.xml").normalize().toUri();
			return new ServerConfiguration(serverName, friendly, discovery, List.of(listen.split(",")),
					List.of(outgoing.split(",")), containers, iosResource, new char[0]);
		}

		private static Optional<String> attr(final XmlReader r, final String name) {
			return Optional.ofNullable(r.getAttributeValue(null, name));
		}

		private static int attr(final XmlReader r, final String name, final int def) {
			return Optional.ofNullable(r.getAttributeValue(null, name)).map(Integer::parseInt).orElse(def);
		}

		private void readServiceContainer(final XmlReader r) throws KNXMLException
		{
			if (r.getEventType() != XmlReader.START_ELEMENT || !r.getLocalName().equals(XmlConfiguration.svcCont))
				throw new KNXMLException("no service container element");

			final boolean activate = attr(r, XmlConfiguration.attrActivate).map(Boolean::parseBoolean).orElse(true);
			final boolean routing = Boolean.parseBoolean(r.getAttributeValue(null, "routing"));
			final boolean reuse = Boolean.parseBoolean(r.getAttributeValue(null, "reuseCtrlEP"));
			if (routing && reuse)
				throw new KNXIllegalArgumentException("with routing activated, reusing control endpoint is not allowed");
			final boolean monitor = Boolean.parseBoolean(r.getAttributeValue(null, "networkMonitoring"));
			final int port = attr(r, XmlConfiguration.attrUdpPort).map(Integer::parseUnsignedInt).orElse(3671);
			final NetworkInterface netif = getNetIf(r);

			// look for a server keyfile
			final var keyfile = attr(r, "keyfile").map(file -> appData.resolve(file)).map(XmlConfiguration::readKeyfile)
					.orElse(Map.of());
			// look for a keyring configuration
			final var keyring = attr(r, "keyring").map(file -> appData.resolve(file).toString()).map(Keyring::load).orElse(null);

			final var secureServices = decodeSecuredServicecs(attr(r, "securedServices").orElse("0"));
			final boolean udpOnly = Boolean.parseBoolean(r.getAttributeValue(null, "udpOnly"));

			String subnetArgs = "";
			String interfaceType = "";
			String msgFormat = "";
			int subnetMedium = KNXMediumSettings.MEDIUM_TP1;
			byte[] subnetDoA = null;
			IndividualAddress overrideSrcAddress = null;
			IndividualAddress tunnelingAddress = null;
			IndividualAddress host = null;
			int user = 0;
			Duration subnetLatencyTolerance = Duration.ofMillis(0);

			IndividualAddress subnet = null;
			NetworkInterface subnetKnxipNetif = null;
			InetAddress routingMcast = KNXNetworkLinkIP.DefaultMulticast;
			Duration latencyTolerance = Duration.ofMillis(1000);
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

			while (r.nextTag() != XmlReader.END_DOCUMENT) {
				final String name = r.getLocalName();
				if (r.getEventType() == XmlReader.START_ELEMENT) {
					switch (name) {
						case "datapoints" -> {
							final DatapointMap<Datapoint> dps = new DatapointMap<>();
							final XmlReader dpReader = attr(r, "ref")
									.map(XmlInputFactory.newInstance()::createXMLReader).orElse(r);
							dps.load(dpReader);
							datapoints = dps;
						}
						case "knxSubnet" -> {
							interfaceType = r.getAttributeValue(null, XmlConfiguration.attrType);
							msgFormat = attr(r, "format").orElse("");
							String medium = r.getAttributeValue(null, XmlConfiguration.attrMedium);
							if (interfaceType.equals("knxip"))
								medium = "knxip";
							else if (medium == null)
								medium = "tp1";
							subnetMedium = KNXMediumSettings.getMedium(medium);
							// KNX subnet domain address for power-line and RF, as hexadecimal value string
							final String doa = r.getAttributeValue(null, "domainAddress");
							if (doa != null) {
								long l = Long.parseLong(doa, 16);
								final int bytes = subnetMedium == KNXMediumSettings.MEDIUM_RF ? 6 : 2;
								subnetDoA = new byte[bytes];
								for (int i = subnetDoA.length; i-- > 0; l >>>= 8)
									subnetDoA[i] = (byte) l;
							}
							overrideSrcAddress = indAddress(r, "knxAddress");
							switch (interfaceType) {
								case "ip" -> {
									subnetKnxipNetif = getNetIf(r);
									useNat = Boolean.parseBoolean(r.getAttributeValue(null, "useNat"));
								}
								case "tcp" -> {
									tunnelingAddress = indAddress(r, "tunnelingAddress");
									host = indAddress(r, "host");
									user = attr(r, "user", 0);
									if (user < 0 || user > 127)
										throw new KNXIllegalArgumentException(
												"KNX IP Secure user ID " + user + " out of range [1..127]");
								}
								case "knxip" -> {
									subnetKnxipNetif = getNetIf(r);
									subnetLatencyTolerance = latencyTolerance(r);
								}
								case "user-supplied" ->
										subnetLinkClass = r.getAttributeValue(null, "class");
							}
							subnetArgs = r.getElementText();
						}
						case XmlConfiguration.grpAddrFilter -> filter = readGroupAddressFilter(r);
						case XmlConfiguration.addAddresses -> indAddressPool = readAdditionalAddresses(r);
						case "tunnelingUsers" -> tunnelingUserToAddresses.putAll(readTunnelingUsers(r));
						case "routing" -> {
							try {
								latencyTolerance = latencyTolerance(r);
								final String mcast = r.getElementText();
								if (!mcast.isEmpty())
									routingMcast = InetAddress.getByName(mcast);
							} catch (final UnknownHostException uhe) {
								throw new KNXMLException(uhe.getMessage(), r);
							} catch (final NumberFormatException e) {
								throw new KNXMLException("invalid latency tolerance", r);
							}
						}
						case "routingMcast" -> {
							try {
								routingMcast = InetAddress.getByName(r.getElementText());
							} catch (final UnknownHostException uhe) {
								throw new KNXMLException(uhe.getMessage(), r);
							}
						}
						case "disruptionBuffer" -> {
							expirationTimeout = r.getAttributeValue(null, "expirationTimeout");
							final String[] range = attr(r, attrUdpPort).orElse("0-65535").split("-", -1);
							disruptionBufferLowerPort = Integer.parseUnsignedInt(range[0]);
							disruptionBufferUpperPort = Integer.parseUnsignedInt(range.length > 1 ? range[1] : range[0]);
						}
						case "timeServer" -> {
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
						default -> subnet = new IndividualAddress(r);
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
						final String svcContName = subnetArgs.isEmpty() ? interfaceType + "-" + subnet : subnetArgs;
						final boolean baosSupport = "baos".equals(msgFormat);
						if (routing)
							sc = new RoutingServiceContainer(svcContName, netifName, hpai, s, monitor, udpOnly,
									routingMcast, latencyTolerance, baosSupport);
						else
							sc = new DefaultServiceContainer(svcContName, netifName, hpai, s, reuse, monitor, udpOnly,
									baosSupport);
						sc.setActivationState(activate);
						sc.setDisruptionBuffer(Duration.ofSeconds(Integer.parseUnsignedInt(expirationTimeout)),
								disruptionBufferLowerPort, disruptionBufferUpperPort);

						final var connector = switch (interfaceType) {
							case "knxip"   -> SubnetConnector.newWithRoutingLink(sc, subnetKnxipNetif, subnetArgs,
									subnetLatencyTolerance);
							case "ip"      -> SubnetConnector.newWithTunnelingLink(sc, subnetKnxipNetif, useNat,
									msgFormat, overrideSrcAddress, subnetArgs);
							case "tcp"     -> SubnetConnector.withTcp(sc, subnetArgs, tunnelingAddress, user, host);
							case "tpuart"  -> SubnetConnector.newWithTpuartLink(sc, overrideSrcAddress, subnetArgs);
							case "emulate" -> datapoints != null ? SubnetConnector.newCustom(sc, "emulate", datapoints)
									: SubnetConnector.newCustom(sc, "emulate");
							case "user-supplied" ->
									SubnetConnector.newWithUserLink(sc, subnetLinkClass, overrideSrcAddress, subnetArgs);
							default        -> SubnetConnector.newWithInterfaceType(sc, interfaceType, msgFormat,
									overrideSrcAddress, subnetArgs);
						};
						var config = new Container(indAddressPool, connector, filter, timeServerDatapoints);

						if (keyring != null) {
							final var interfaces = keyring.interfaces().getOrDefault(subnet, List.of());
							for (final var iface : interfaces) {
								tunnelingUserToAddresses.computeIfAbsent(iface.user(), ArrayList::new).add(iface.address());
								indAddressPool.add(iface.address());
							}
							config = new Container(indAddressPool, tunnelingUserToAddresses, connector, filter,
									timeServerDatapoints, secureServices, keyfile, keyring);
						}
						else
							config = new Container(indAddressPool, tunnelingUserToAddresses, connector, filter,
									timeServerDatapoints, secureServices, keyfile);
						containers.add(config);
						return;
					}
				}
			}
		}

		private static IndividualAddress indAddress(final XmlReader r, final String name) {
			final var attr = r.getAttributeValue(null, name);
			if (attr == null)
				return null;
			try {
				return new IndividualAddress(attr);
			}
			catch (final KNXFormatException e) {
				throw new IllegalArgumentException(e.getMessage());
			}
		}

		private static Duration latencyTolerance(final XmlReader r) {
			final int tolerance = attr(r, "latencyTolerance").map(Integer::parseUnsignedInt).orElse(0);
			return Duration.ofMillis(tolerance);
		}

		private static EnumSet<ServiceFamily> decodeSecuredServicecs(final String svcs) {
			try {
				return toEnumSet(Integer.decode(svcs));
			}
			catch (final NumberFormatException e) {
				final String[] split = svcs.replaceAll(" +", "").split(",| +", 0);
				final var set = EnumSet.noneOf(ServiceFamily.class);
				for (final var s : split) {
					switch (s) {
						case "optional" -> {
							return EnumSet.of(ServiceFamily.Security);
						}
						case "tunneling" -> set.add(ServiceFamily.Tunneling);
						case "devmgmt" -> set.add(ServiceFamily.DeviceManagement);
						case "routing" -> set.add(ServiceFamily.Routing);
						default -> throw new KNXIllegalArgumentException("unknown secure service '" + s + "'");
					}
				}
				return set;
			}
		}

		private static EnumSet<ServiceFamily> toEnumSet(final int secureServices) {
			final var set = EnumSet.noneOf(ServiceFamily.class);
			for (final var serviceFamily : ServiceFamily.values())
				if ((secureServices & (1 << serviceFamily.id())) != 0)
					set.add(serviceFamily);
			return set;
		}

		private static Map<String, byte[]> readKeyfile(final Path keyfile) {
			try (var lines = Files.lines(keyfile)) {
				// ignore comments, limit keys to words with dot separator, require '='
				final var matcher = Pattern.compile("^[^/#][\\w[\\[\\d+\\]]\\.]+\\s*=.+$").asMatchPredicate();
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
			if (key.endsWith("device.pwd"))
				return Map.entry(key.replace(".pwd", ".key"), SecureConnection.hashDeviceAuthenticationPassword(chars));
			if (key.endsWith("pwd"))
				return Map.entry(key.replace(".pwd", ".key"), SecureConnection.hashUserPassword(chars));
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

		private static NetworkInterface getNetIf(final XmlReader r)
		{
			final String attr = attr(r, XmlConfiguration.attrListenNetIf).or(() -> attr(r, "netif")).orElse(null);
			if (attr != null && !"any".equals(attr)) {
				try {
					final NetworkInterface netIf = NetworkInterface.getByName(attr);
					if (netIf != null)
						return netIf;
				}
				catch (final SocketException se) {
					throw new KnxRuntimeException("while searching for network interface '" + attr + "'", se);
				}
				throw new KNXIllegalArgumentException(
						"no network interface found with the specified name '" + attr + "'");
			}
			return null;
		}
	}

	private final Logger logger;

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
			System.out.println("supply file name/URI for the KNX server configuration");
			return;
		}

		// we have to set the command-line option for log level before first logger lookup
		int optIdx = 0;
		if (args[0].startsWith("-v")) {
			final String vs = args[0];
			final String level = vs.startsWith("-vvv") ? "trace" : vs.startsWith("-vv") ? "debug" : "info";
			System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", level);
			optIdx++;
		}

		final String configUri = args[args.length - 1];
		final boolean detached = "--no-stdin".equals(args[optIdx]);
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
		logger = LoggerFactory.getLogger("calimero.server." + config.name());
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
		try {
			setupContainers(config.containers());
			gw = new KnxServerGateway(server, config);

			final String name = server.getName();
			if (terminal) {
				Executor.execute(gw, name);
				waitForTermination();
				quit();
			}
			else {
				Thread.currentThread().setName(name);
				gw.run();
			}
		}
		catch (final RuntimeException e) {
			logger.error("initialization of KNX server failed", e);
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

	private void setupContainers(final List<Container> containers) {
		int objectInstance = 0;

		for (final var container : containers) {
			final var connector = container.subnetConnector();

			++objectInstance;
			final InterfaceObjectServer ios = server.getInterfaceObjectServer();
			ensureInterfaceObjectInstance(ios, InterfaceObject.ROUTER_OBJECT, objectInstance);
			ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, PID.LOAD_STATE_CONTROL, 1, 1, (byte) 1);
			ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, PID.MEDIUM_STATUS, 1, 1, (byte) 1);
			ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, PID.MAIN_LCCONFIG, 1, 1, (byte) 1);
			ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, PID.SUB_LCCONFIG, 1, 1, (byte) 1);
			ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, 56, 1, 1, (byte) 0);

			ios.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance, PID.KNXNETIP_DEVICE_STATE, 1, 1, (byte) 1);

			final ServiceContainer sc = connector.getServiceContainer();

			final var keyfile = container.keyring().map(keyring -> decodeKeyring(sc, container)).orElse(container.keyfile());
			server.configureSecurity(sc, keyfile, container.securedServices());

			// configure security for subnet if required
			switch (connector.interfaceType()) {
				case "tcp" -> {
					if (connector.user().isPresent()) {
						final var userKey = keyfile.get("subnet.tunneling.key");
						final var deviceAuthCode = keyfile.get("subnet.device.key");
						connector.setIpSecure(userKey, deviceAuthCode);
					}
				}
				case "knxip" -> {
					if (connector.knxipSecure()) {
						final var groupKey = keyfile.get("subnet.group.key");
						if (groupKey == null)
							throw new KnxSecureException("KNX subnet " + connector.getName() + ": no group key configured");
						connector.setGroupKey(groupKey);
					}
				}
			}

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
			logger.debug("setup {} subnet '{}'{}", subnetType, subnetName, activated);

			if ("tpuart".equals(subnetType)) {
				final int oi = objectInstance;
				connector.setAckOnTp(() -> acknowledgeOnTp(sc, oi));
			}

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

	private Map<String, byte[]> decodeKeyring(final ServiceContainer sc, final Container config) {
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

		logger.debug("decrypt knx secure keys...");

		final var decrypted = new HashMap<String, byte[]>();

		final var host = sc.getMediumSettings().getDeviceAddress();
		final var device = keyring.devices().get(host);
		if (device != null) {
			final var authKey = SecureConnection
					.hashDeviceAuthenticationPassword(keyring.decryptPassword(device.authentication().get(), pwd));
			decrypted.put("device.key", authKey);
			final var mgmtKey = SecureConnection
					.hashUserPassword(keyring.decryptPassword(device.password().get(), pwd));
			decrypted.put("user[1].key", mgmtKey);
		}

		if (sc instanceof final RoutingServiceContainer rsc) {
			final var backbone = keyring.backbone().filter(bb -> bb.multicastGroup().equals(rsc.routingMulticastAddress()));
			if (backbone.isPresent() && backbone.get().groupKey().isPresent()) {
				final var enc = backbone.get().groupKey().get();
				final var groupKey = keyring.decryptKey(enc, pwd);
				decrypted.put("group.key", groupKey);
			}
			else
				logger.warn("KNX IP routing is not secured");
		}

		final var interfaces = keyring.interfaces().getOrDefault(host, List.of());
		for (final var iface : interfaces) {
			if (iface.password().isEmpty())
				continue;
			final var key = SecureConnection.hashUserPassword(keyring.decryptPassword(iface.password().get(), pwd));
			decrypted.put("user[" + iface.user() + "].key", key);
		}

		for (final var entry : keyring.groups().entrySet())
			Security.defaultInstallation().groupKeys().put(entry.getKey(), keyring.decryptKey(entry.getValue(), pwd));

		// check subnet security configuration
		final var connector = config.subnetConnector();
		// tunneling
		if (connector.user().isPresent()) {
			final int user = connector.user().get();
			final var subnetHost = connector.host().orElse(host);
			final var iface = Optional.ofNullable(keyring.interfaces().get(subnetHost)).orElse(List.of()).stream()
					.filter(intf -> intf.user() == user).findFirst().orElseThrow(() -> new KnxSecureException(
							connector.getName() + ": no keyring interface found for host " + subnetHost + " user " + user));
			if (iface.password().isEmpty())
				throw new KnxSecureException(connector.getName() + ": keyring interface for host " + subnetHost + " user "
						+ user + " does not have a password configured");
			final var key = SecureConnection.hashUserPassword(keyring.decryptPassword(iface.password().get(), pwd));
			decrypted.put("subnet.tunneling.key", key);

			final var subnetDevice = keyring.devices().get(subnetHost);
			if (subnetDevice != null) {
				final var authKey = SecureConnection
						.hashDeviceAuthenticationPassword(keyring.decryptPassword(subnetDevice.authentication().get(), pwd));
				decrypted.put("subnet.device.key", authKey);
			}
			else
				decrypted.put("subnet.device.key", new byte[0]);
		}
		if (connector.knxipSecure()) {
			final var backbone = keyring.backbone().filter(bb -> bb.multicastGroup().getHostAddress().equals(connector.linkArguments()));
			if (backbone.isPresent() && backbone.get().groupKey().isPresent()) {
				final var enc = backbone.get().groupKey().get();
				final var groupKey = keyring.decryptKey(enc, pwd);
				decrypted.put("subnet.group.key", groupKey);
			}
		}

		final var allKeys = new HashMap<>(keyfile);
		allKeys.putAll(decrypted);

		Arrays.fill(pwd, (char) 0);
		return allKeys;
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

	private enum RoutingConfig { Reserved, All, None, Table }

	private static void setGroupAddressFilter(final InterfaceObjectServer ios, final int objectInstance,
			final List<GroupAddress> filter) throws KnxPropertyException {
		if (!filter.isEmpty()) {
			final var buf = ByteBuffer.allocate(2 * filter.size());
			filter.forEach(ga -> buf.putShort((short) ga.getRawAddress()));

			ensureInterfaceObjectInstance(ios, ADDRESSTABLE_OBJECT, objectInstance);
			ios.setProperty(ADDRESSTABLE_OBJECT, objectInstance, PID.TABLE, 1, filter.size(), buf.array());
		}

		ensureInterfaceObjectInstance(ios, InterfaceObject.ROUTER_OBJECT, objectInstance);

		// set the handling of group addressed frames, based on whether we have set a
		// group address filter table or not
		final RoutingConfig route = filter.isEmpty() ? RoutingConfig.All : RoutingConfig.Table;
		ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, PID.MAIN_LCGROUPCONFIG, 1, 1,
				(byte) (1 << 4 | RoutingConfig.All.ordinal() << 2 | route.ordinal()));
		// by default, we don't check the group address filter table for group frames from subnetworks
		ios.setProperty(InterfaceObject.ROUTER_OBJECT, objectInstance, PID.SUB_LCGROUPCONFIG, 1, 1,
				(byte) (RoutingConfig.All.ordinal() << 2 | RoutingConfig.All.ordinal()));
	}

	private static void ensureInterfaceObjectInstance(final InterfaceObjectServer ios,
		final int interfaceType, final int instance)
	{
		long l = Arrays.stream(ios.getInterfaceObjects())
				.filter((io) -> io.getType() == interfaceType).count();
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
		final var addrIndices = userToAddresses.values().stream().flatMap(List::stream)
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

	private static void setTunnelingAddresses(final InterfaceObjectServer ios, final int objectInstance,
			final byte[] addrIndices) {
		final int idx = ios.lookup(KNXNETIP_PARAMETER_OBJECT, objectInstance).getIndex();
		final var d = new Description(idx, KNXNETIP_PARAMETER_OBJECT, pidTunnelingAddresses, 0, 0, true, 0,
				addrIndices.length, 3, 3);
		ios.setDescription(d, true);
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
		final var knxipObject = KnxipParameterObject.lookup(ios, objectInstance);
		ack.addAll(knxipObject.additionalAddresses());
		try {
			final var buf = ByteBuffer
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
