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

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.function.Supplier;
import java.util.stream.Stream;

import io.calimero.DataUnitBuilder;
import io.calimero.IndividualAddress;
import io.calimero.KNXAddress;
import io.calimero.KNXException;
import io.calimero.KNXIllegalArgumentException;
import io.calimero.Priority;
import io.calimero.baos.BaosLinkAdapter;
import io.calimero.baos.ip.BaosLinkIp;
import io.calimero.buffer.Configuration;
import io.calimero.buffer.NetworkBuffer;
import io.calimero.buffer.StateFilter;
import io.calimero.cemi.CEMILData;
import io.calimero.datapoint.Datapoint;
import io.calimero.datapoint.DatapointMap;
import io.calimero.datapoint.DatapointModel;
import io.calimero.dptxlator.DPTXlator;
import io.calimero.dptxlator.TranslatorTypes;
import io.calimero.knxnetip.TcpConnection;
import io.calimero.link.Connector;
import io.calimero.link.Connector.TSupplier;
import io.calimero.link.KNXNetworkLink;
import io.calimero.link.KNXNetworkLinkFT12;
import io.calimero.link.KNXNetworkLinkIP;
import io.calimero.link.KNXNetworkLinkTpuart;
import io.calimero.link.KNXNetworkLinkUsb;
import io.calimero.link.KNXNetworkMonitor;
import io.calimero.link.KNXNetworkMonitorFT12;
import io.calimero.link.KNXNetworkMonitorIP;
import io.calimero.link.KNXNetworkMonitorTpuart;
import io.calimero.link.KNXNetworkMonitorUsb;
import io.calimero.link.medium.KNXMediumSettings;
import io.calimero.link.medium.RFSettings;
import io.calimero.link.medium.TPSettings;
import io.calimero.server.VirtualLink;
import io.calimero.server.gateway.KnxServerGateway.SubnetListener;
import io.calimero.server.knxnetip.ServiceContainer;

/**
 * Contains information necessary to connect a server-side service container to a KNX subnet. A gateway uses subnet
 * connectors to lookup associations of service containers and KNX subnets as well as subnet link management.
 *
 * @author B. Malinowsky
 */
public final class SubnetConnector
{
	public enum InterfaceType { Udp, Tcp, Knxip, Tpuart, Usb, Ft12, Emulate, Virtual, User, Unknown }

	private final ServiceContainer sc;
	private final InterfaceType interfaceType;
	private final String msgFormat;
	private final IndividualAddress overrideInterfaceAddress;
	private final String linkArgs;
	private final NetworkInterface netif;
	private final String className;
	private final Object[] args;

	private AutoCloseable subnetLink;
	private SubnetListener listener;

	private Supplier<List<KNXAddress>> acknowledge = List::of;

	// count received subnet frames for busmon sequence, using the last processed frame event
	volatile long lastEventId;
	long eventCounter;

	private volatile boolean requestBaos;

	private byte[] groupKey;
	private byte[] userKey;
	private byte[] deviceAuthCode;

	/**
	 * Creates a new subnet connector using a KNXnet/IP Routing or KNX IP subnet link.
	 *
	 * @param container service container
	 * @param routingNetif the network interface used for routing messages
	 * @param subnetArgs the arguments to create the KNX IP link
	 * @return the new subnet connector
	 */
	public static SubnetConnector newWithRoutingLink(final ServiceContainer container,
		final NetworkInterface routingNetif, final String subnetArgs)
	{
		return new SubnetConnector(container, InterfaceType.Knxip, "", null, routingNetif, null, subnetArgs);
	}

	public static SubnetConnector newWithRoutingLink(final ServiceContainer container,
		final NetworkInterface routingNetif, final String subnetArgs, final Duration latencyTolerance)
	{
		return new SubnetConnector(container, InterfaceType.Knxip, "", null, routingNetif, null, subnetArgs, latencyTolerance);
	}

	/**
	 * Creates a new subnet connector with KNXnet/IP Tunneling as subnet link.
	 *
	 * @param container service container
	 * @param netif the network interface used for the tunneling connection
	 * @param useNat use network address translation (NAT)
	 * @param msgFormat messaging formt, one of "" (default), "cemi", "baos"
	 * @param overrideSrcAddress force specific address (or absence) of knx source address
	 * @param subnetArgs the arguments to create the KNX link
	 * @return the new subnet connector
	 */
	public static SubnetConnector newWithTunnelingLink(final ServiceContainer container, final NetworkInterface netif,
			final boolean useNat, final String msgFormat, final IndividualAddress overrideSrcAddress,
			final String subnetArgs) {
		return new SubnetConnector(container, InterfaceType.Udp, msgFormat, overrideSrcAddress, netif, null, subnetArgs, useNat);
	}

	public static SubnetConnector newWithTpuartLink(final ServiceContainer container,
			final IndividualAddress overrideSrcAddress, final String subnetArgs) {
		return new SubnetConnector(container, InterfaceType.Tpuart, "", overrideSrcAddress, null, null, subnetArgs);
	}

	/**
	 * Creates a new subnet connector using a user-supplied subnet link.
	 *
	 * @param container service container
	 * @param className the class name of to the user subnet link
	 * @param overrideSrcAddress force specific address (or absence) of knx source address
	 * @param subnetArgs the arguments to create the subnet link
	 * @return the new subnet connector
	 */
	public static SubnetConnector newWithUserLink(final ServiceContainer container, final String className,
			final IndividualAddress overrideSrcAddress, final String subnetArgs) {
		return new SubnetConnector(container, InterfaceType.User, "", overrideSrcAddress, null, className, subnetArgs);
	}

	public static SubnetConnector withTcp(final ServiceContainer container, final String subnetArgs,
			final IndividualAddress tunnelingAddress, final int user, final IndividualAddress host) {
		return new SubnetConnector(container, InterfaceType.Tcp, "", new IndividualAddress(0), null, null, subnetArgs,
				tunnelingAddress, user, host);
	}

	/**
	 * Creates a new subnet connector using an interface type identifier for the KNX subnet interface.
	 *
	 * @param container service container
	 * @param interfaceType the interface type
	 * @param subnetArgs the arguments to create the subnet link
	 * @return the created subnet connector
	 */
	public static SubnetConnector newWithInterfaceType(final ServiceContainer container, final InterfaceType interfaceType,
		final String subnetArgs)
	{
		return newWithInterfaceType(container, interfaceType, "", null, subnetArgs);
	}

	/**
	 * Creates a new subnet connector using an interface type identifier for the KNX subnet interface.
	 *
	 * @param container service container
	 * @param interfaceType the interface type
	 * @param msgFormat one of "" (default), "cemi", "baos"
	 * @param overrideSrcAddress force specific address (or absence) of knx source address
	 * @param subnetArgs the arguments to create the subnet link
	 * @return the created subnet connector
	 */
	public static SubnetConnector newWithInterfaceType(final ServiceContainer container, final InterfaceType interfaceType,
			final String msgFormat, final IndividualAddress overrideSrcAddress, final String subnetArgs)
	{
		return new SubnetConnector(container, interfaceType, msgFormat, overrideSrcAddress, null, null, subnetArgs);
	}

	/**
	 * Creates a new subnet connector using an interface type identifier for the KNX subnet interface.
	 *
	 * @param container service container
	 * @param interfaceType the interface type
	 * @param subnetArgs the arguments to create the subnet link
	 * @return the created subnet connector
	 */
	public static SubnetConnector newCustom(final ServiceContainer container, final InterfaceType interfaceType,
			final Object... subnetArgs)
	{
		return new SubnetConnector(container, interfaceType, "", null, null, null, "", subnetArgs);
	}

	private SubnetConnector(final ServiceContainer container, final InterfaceType interfaceType, final String msgFormat,
		final IndividualAddress overrideSrcAddress,
		final NetworkInterface routingNetif, final String className, final String subnetArgs, final Object... args)
	{
		sc = container;
		this.interfaceType = interfaceType;
		this.msgFormat = msgFormat;
		this.overrideInterfaceAddress = overrideSrcAddress;
		netif = routingNetif;
		this.className = className;
		linkArgs = subnetArgs;
		this.args = args;
	}

	/**
	 * Returns this subnet connector name.
	 * <p>
	 * The name equals the service container name.
	 *
	 * @return the subnet connector name
	 */
	public String getName()
	{
		return sc.getName();
	}

	/**
	 * Returns the service container this connector is used with.
	 *
	 * @return the service container
	 */
	public ServiceContainer getServiceContainer()
	{
		return sc;
	}

	/**
	 * Returns the KNX network or monitor link of the KNX subnet the service container is connected
	 * to, if any.
	 *
	 * @return a KNX network or monitor link representing the KNX subnet connection, or
	 *         <code>null</code>
	 */
	public synchronized AutoCloseable getSubnetLink()
	{
		return subnetLink;
	}

	public KNXNetworkLink openNetworkLink() throws KNXException, InterruptedException
	{
		final KNXMediumSettings settings = mediumSettings();
		final TSupplier<KNXNetworkLink> ts = switch (interfaceType) {
			case Udp -> {
				// find IPv4 address for local socket address
				final InetAddress ia = Optional.ofNullable(netif).map(ni -> ni.inetAddresses()).orElse(Stream.empty())
						.filter(Inet4Address.class::isInstance).findFirst().orElse(null);
				final InetSocketAddress local = new InetSocketAddress(ia, 0);
				final boolean useNat = (Boolean) this.args[0];
				final var server = parseRemoteEndpoint();
				if (requestBaos)
					yield () -> BaosLinkIp.newUdpLink(local, server);
				yield () -> KNXNetworkLinkIP.newTunnelingLink(local, server, useNat, settings);
			}
			case Tcp -> {
				if (requestBaos)
					yield () -> BaosLinkIp.newTcpLink(newTcpConnection());

				// check if we have a tunneling address specified
				KNXMediumSettings tunnelingSettings;
				if (args.length > 0 && args[0] instanceof final IndividualAddress ia)
					tunnelingSettings = new ReplaceInterfaceAddressProxy(settings, ia);
				else
					tunnelingSettings = settings;

				if (args.length > 0 && args[1] instanceof final Integer user && userKey != null) {
					yield () -> KNXNetworkLinkIP.newSecureTunnelingLink(
							newTcpConnection().newSecureSession(user, userKey.clone(), deviceAuthCode.clone()),
							tunnelingSettings);
				}
				yield () -> KNXNetworkLinkIP.newTunnelingLink(newTcpConnection(), tunnelingSettings);
			}
			case Knxip -> {
				try {
					final InetAddress mcGroup = InetAddress.getByName(linkArgs);
					if (args.length > 0 && args[0] instanceof final Duration latencyTolerance && groupKey != null)
						yield () -> KNXNetworkLinkIP.newSecureRoutingLink(netif, mcGroup, groupKey.clone(),
								latencyTolerance, settings);
					yield () -> KNXNetworkLinkIP.newRoutingLink(netif, mcGroup, settings);
				}
				catch (final UnknownHostException e) {
					throw new KNXException("open network link (KNXnet/IP routing): invalid multicast group " + linkArgs,
							e);
				}
			}
			case Usb -> {
				// ignore configured device address with USB on TP1/RF and always use 0.0.0
				final var adjustedSettings = settings instanceof ReplaceInterfaceAddressProxy ? settings
						: settings instanceof final TPSettings tp ? new UsbTpSettingsProxy(tp) :
						  settings instanceof final RFSettings rf ? new UsbRfSettingsProxy(rf) : settings;
				if (requestBaos)
					yield () -> BaosLinkAdapter.asBaosLink(new KNXNetworkLinkUsb(linkArgs, adjustedSettings));
				yield () -> new KNXNetworkLinkUsb(linkArgs, adjustedSettings);
			}
			case Ft12 -> {
				if ("cemi".equals(msgFormat))
					yield () -> KNXNetworkLinkFT12.newCemiLink(linkArgs, settings);
				if (requestBaos)
					yield () -> BaosLinkAdapter.asBaosLink(new KNXNetworkLinkFT12(linkArgs, settings));
				yield () -> new KNXNetworkLinkFT12(linkArgs, settings);
			}
			case Tpuart -> () -> new KNXNetworkLinkTpuart(linkArgs, settings, acknowledge.get());
			case User -> () -> newLinkUsing(className, linkArgs.split("[,|]"));
			case Emulate -> {
				final NetworkBuffer nb = NetworkBuffer.createBuffer(sc.getName());
				final VirtualLink vl = new VirtualLink(sc.getName(), settings);
				final Configuration config = nb.addConfiguration(vl);
				config.setQueryBufferOnly(false);
				if (args.length > 0 && args[0] instanceof DatapointModel) {
					@SuppressWarnings("unchecked")
					final DatapointModel<Datapoint> model = (DatapointModel<Datapoint>) args[0];
					config.setDatapointModel(model);
				}
				final StateFilter f = new StateFilter();
				config.setFilter(f, f);
				config.activate(true);
				// necessary to get .ind/.con notification for the buffer
				final IndividualAddress device = new IndividualAddress(0);
				vl.createDeviceLink(device);
				if (config.getDatapointModel() instanceof DatapointMap<?>) {
					// init all emulated datapoints with their default value
					for (final Datapoint dp : ((DatapointMap<?>) config.getDatapointModel()).getDatapoints()) {
						final DPTXlator t = TranslatorTypes.createTranslator(dp.getDPT());
						final byte[] tpdu = t.getTypeSize() == 0
								? DataUnitBuilder.createLengthOptimizedAPDU(0x80, t.getData())
								: DataUnitBuilder.createAPDU(0x80, t.getData());
						final CEMILData msg = new CEMILData(CEMILData.MC_LDATA_REQ, device, dp.getMainAddress(), tpdu,
								Priority.LOW);
						config.getBufferedLink().send(msg, true);
					}
				}
				yield config::getBufferedLink;
			}
			case Virtual -> () -> new VirtualLink(linkArgs, settings);
			case Unknown -> throw new KNXException(
					"network link: unsupported KNX subnet interface type '" + interfaceType + "'");
		};

		final KNXNetworkLink link = new Connector().reconnectOn(true, true, true)
				.reconnectDelay(Duration.ofSeconds(10)).connectionStatusNotifier(this::connectionStatusChanged).newLink(ts);
		setSubnetLink(link);
		return link;
	}

	public KNXNetworkMonitor openMonitorLink() throws KNXException, InterruptedException
	{
		if (interfaceType == InterfaceType.Virtual || interfaceType == InterfaceType.Emulate)
			return null;

		final KNXMediumSettings settings = sc.getMediumSettings();
		final TSupplier<KNXNetworkMonitor> ts = switch (interfaceType) {
			case Udp -> () -> new KNXNetworkMonitorIP(new InetSocketAddress(0), parseRemoteEndpoint(), false, settings);
			case Tcp -> () -> KNXNetworkMonitorIP.newMonitorLink(newTcpConnection(), settings);
			case Usb -> () -> new KNXNetworkMonitorUsb(linkArgs, settings);
			case Ft12 -> () -> "cemi".equals(msgFormat)
					? KNXNetworkMonitorFT12.newCemiMonitor(linkArgs, settings)
					: new KNXNetworkMonitorFT12(linkArgs, settings);
			case Tpuart -> () -> new KNXNetworkMonitorTpuart(linkArgs, false);
			case User -> () -> newLinkUsing(className, linkArgs.split("[,|]"));
			case Knxip, Emulate, Virtual, Unknown ->
					throw new KNXException("monitor link: unsupported KNX subnet interface type '" + interfaceType + "'");
		};

		final Connector c = new Connector().reconnectOn(true, true, true)
				.reconnectDelay(Duration.ofSeconds(10)).connectionStatusNotifier(this::connectionStatusChanged);
		final KNXNetworkMonitor link = c.newMonitor(ts);
		setSubnetLink(link);
		return link;
	}

	private TcpConnection newTcpConnection() {
		final InetAddress ia = Optional.ofNullable(netif).map(ni -> ni.inetAddresses()).orElse(Stream.empty())
				.filter(Inet4Address.class::isInstance).findFirst().orElse(null);
		final InetSocketAddress local = new InetSocketAddress(ia, 0);
		final var server = parseRemoteEndpoint();
		return TcpConnection.newTcpConnection(local, server);
	}

	private InetSocketAddress parseRemoteEndpoint() {
		final String[] args = linkArgs.split(":", -1);
		final String ip = args[0];
		final int port = args.length > 1 ? Integer.parseUnsignedInt(args[1]) : 3671;
		return new InetSocketAddress(ip, port);
	}

	public InterfaceType interfaceType() { return interfaceType; }

	public String format() { return msgFormat; }

	Optional<IndividualAddress> interfaceAddress() { return Optional.ofNullable(overrideInterfaceAddress); }

	public String linkArguments() { return linkArgs; }

	public void setAckOnTp(final Supplier<List<KNXAddress>> ackOnTp) {
		acknowledge = ackOnTp;
	}

	public void setIpSecure(final byte[] userKey, final byte[] deviceAuthCode) {
		this.userKey = userKey.clone();
		this.deviceAuthCode = deviceAuthCode.clone();
	}

	public void setGroupKey(final byte[] groupKey) { this.groupKey = groupKey.clone(); }

	public Optional<Integer> user() {
		if (args.length > 1 && args[1] instanceof final Integer i && i > 0)
			return Optional.of(i);
		return Optional.empty();
	}

	public Optional<IndividualAddress> host() {
		if (args.length > 2 && args[2] instanceof final IndividualAddress ia)
			return Optional.of(ia);
		return Optional.empty();
	}

	public boolean knxipSecure() {
		return args.length > 0 && args[0] instanceof final Duration d && !d.isZero();
	}

	@Override
	public String toString() {
		final var joiner = new StringJoiner(" ");
		joiner.add(interfaceType.toString());
		if (subnetLink != null)
			return joiner.add(subnetLink.toString()).toString();

		if (!linkArgs.isBlank())
			joiner.add(linkArgs);
		if (!msgFormat.isBlank())
			joiner.add(msgFormat);
		return joiner.toString();
	}

	void setSubnetListener(final SubnetListener subnetListener)
	{
		listener = subnetListener;
		final AutoCloseable link = getSubnetLink();
		if (link instanceof final KNXNetworkLink networkLink)
			networkLink.addLinkListener(listener);
		if (link instanceof final KNXNetworkMonitor monitor)
			monitor.addMonitorListener(listener);
	}

	void requestBaos(final boolean baos) {
		if ("baos".equals(msgFormat))
			requestBaos = baos;
	}

	private void connectionStatusChanged(final boolean connected) {
		if (listener != null)
			listener.connectionStatus(connected);
	}

	private static <T> T newLinkUsing(final String className, final String[] initArgs)
	{
		try {
			@SuppressWarnings("unchecked")
			final Class<? extends T> c = (Class<? extends T>) Class.forName(className);
			final Class<?>[] paramTypes = new Class<?>[] { Object[].class };
			final Object[] args = new Object[] { initArgs };
			return c.getConstructor(paramTypes).newInstance(args);
		}
		catch (final ReflectiveOperationException | RuntimeException e) {
			// ClassNotFoundException, InstantiationException, IllegalAccessException,
			// InvocationTargetException, ClassCastException, IllegalArgumentException,
			// SecurityException
			throw new KNXIllegalArgumentException("error loading link resource " + className, e);
		}
	}

	private synchronized void setSubnetLink(final AutoCloseable link)
	{
		subnetLink = link;
		if (listener != null)
			setSubnetListener(listener);
	}

	// always use device address 0.0.0 with USB TP1 interface
	private static final class UsbTpSettingsProxy extends TPSettings {
		private final TPSettings delegate;

		UsbTpSettingsProxy(final TPSettings settings) {
			this.delegate = settings;
		}

		@Override
		public void setMaxApduLength(final int maxApduLength) {
			super.setMaxApduLength(maxApduLength);
			delegate.setMaxApduLength(maxApduLength);
		}
	}

	// always use device address 0.0.0 with USB RF interface
	private static final class UsbRfSettingsProxy extends RFSettings {
		private final RFSettings delegate;

		UsbRfSettingsProxy(final RFSettings settings) {
			super(BackboneRouter, settings.getDomainAddress(), settings.serialNumber(), settings.isUnidirectional());
			this.delegate = settings;
		}

		@Override
		public void setMaxApduLength(final int maxApduLength) {
			super.setMaxApduLength(maxApduLength);
			delegate.setMaxApduLength(maxApduLength);
		}

		// TODO override setDomainAddress
		// TODO override setDeviceAddress?
	}

	private KNXMediumSettings mediumSettings() {
		final var settings = sc.getMediumSettings();
		return interfaceAddress().map(ia -> (KNXMediumSettings) new ReplaceInterfaceAddressProxy(settings, ia))
				.orElse(settings);
	}

	private static final class ReplaceInterfaceAddressProxy extends TPSettings {
		private final KNXMediumSettings delegate;

		ReplaceInterfaceAddressProxy(final KNXMediumSettings settings, final IndividualAddress replacement) {
			super(replacement);
			this.delegate = settings;
		}

		@Override
		public void setMaxApduLength(final int maxApduLength) {
			super.setMaxApduLength(maxApduLength);
			delegate.setMaxApduLength(maxApduLength);
		}
	}
}
