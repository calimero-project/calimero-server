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

package io.calimero.server.gateway;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Stream;

import io.calimero.DataUnitBuilder;
import io.calimero.IndividualAddress;
import io.calimero.KNXAddress;
import io.calimero.KNXException;
import io.calimero.KNXFormatException;
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
	private final ServiceContainer sc;
	private final String interfaceType;
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
		return new SubnetConnector(container, "knxip", "", "", routingNetif, null, subnetArgs);
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
		final boolean useNat, final String msgFormat, final String overrideSrcAddress, final String subnetArgs)
	{
		return new SubnetConnector(container, "ip", msgFormat, overrideSrcAddress, netif, null, subnetArgs, useNat);
	}

	public static SubnetConnector newWithTpuartLink(final ServiceContainer container, final String overrideSrcAddress,
			final String subnetArgs) {
		return new SubnetConnector(container, "tpuart", "", overrideSrcAddress, null, null, subnetArgs);
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
	public static SubnetConnector newWithUserLink(final ServiceContainer container,
		final String className, final String overrideSrcAddress, final String subnetArgs)
	{
		return new SubnetConnector(container, "user-supplied", "", overrideSrcAddress, null, className, subnetArgs);
	}

	/**
	 * Creates a new subnet connector using an interface type identifier for the KNX subnet interface.
	 *
	 * @param container service container
	 * @param interfaceType the interface type, use on of "ip", "usb", "tpuart", or "ft12".
	 * @param subnetArgs the arguments to create the subnet link
	 * @return the created subnet connector
	 */
	public static SubnetConnector newWithInterfaceType(final ServiceContainer container, final String interfaceType,
		final String subnetArgs)
	{
		return newWithInterfaceType(container, interfaceType, "", "", subnetArgs);
	}

	/**
	 * Creates a new subnet connector using an interface type identifier for the KNX subnet interface.
	 *
	 * @param container service container
	 * @param interfaceType the interface type, use on of "ip", "usb", "tpuart", or "ft12".
	 * @param msgFormat one of "" (default), "cemi", "baos"
	 * @param overrideSrcAddress force specific address (or absence) of knx source address
	 * @param subnetArgs the arguments to create the subnet link
	 * @return the created subnet connector
	 */
	public static SubnetConnector newWithInterfaceType(final ServiceContainer container, final String interfaceType,
			final String msgFormat, final String overrideSrcAddress, final String subnetArgs)
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
	public static SubnetConnector newCustom(final ServiceContainer container, final String interfaceType,
		final Object... subnetArgs)
	{
		return new SubnetConnector(container, interfaceType, "", "", null, null, interfaceType, subnetArgs);
	}

	private SubnetConnector(final ServiceContainer container, final String interfaceType, final String msgFormat,
		final String overrideSrcAddress,
		final NetworkInterface routingNetif, final String className, final String subnetArgs, final Object... args)
	{
		sc = container;
		this.interfaceType = interfaceType;
		this.msgFormat = msgFormat;
		try {
			this.overrideInterfaceAddress = overrideSrcAddress.isEmpty() ? null : new IndividualAddress(overrideSrcAddress);
		}
		catch (final KNXFormatException e) {
			throw new KNXIllegalArgumentException(overrideSrcAddress + " is not a valid KNX individual address");
		}
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
		final TSupplier<KNXNetworkLink> ts;
		// can cause a delay of connection timeout in the worst case
		if ("ip".equals(interfaceType)) {
			// find IPv4 address for local socket address
			final InetAddress ia = Optional.ofNullable(netif).map(ni -> ni.inetAddresses()).orElse(Stream.empty())
				.filter(Inet4Address.class::isInstance).findFirst().orElse(null);
			final InetSocketAddress local = new InetSocketAddress(ia, 0);
			final boolean useNat = (Boolean) this.args[0];

			final var server = parseRemoteEndpoint();
			if (requestBaos)
				ts = () -> BaosLinkIp.newUdpLink(local, server);
			else
				ts = () -> KNXNetworkLinkIP.newTunnelingLink(local, server, useNat, settings);
		}
		else if ("tcp".equals(interfaceType)) {
			final InetAddress ia = Optional.ofNullable(netif).map(ni -> ni.inetAddresses()).orElse(Stream.empty())
					.filter(Inet4Address.class::isInstance).findFirst().orElse(null);
			final InetSocketAddress local = new InetSocketAddress(ia, 0);
			final var server = parseRemoteEndpoint();

			if (requestBaos)
				ts = () -> BaosLinkIp.newTcpLink(TcpConnection.newTcpConnection(local, server));
			else
				ts = () -> KNXNetworkLinkIP.newTunnelingLink(TcpConnection.newTcpConnection(local, server), settings);
		}
		else if ("knxip".equals(interfaceType)) {
			try {
				final InetAddress mcGroup = InetAddress.getByName(linkArgs);
				ts = () -> KNXNetworkLinkIP.newRoutingLink(netif, mcGroup, settings);
			}
			catch (final UnknownHostException e) {
				throw new KNXException("open network link (KNXnet/IP routing): invalid multicast group " + linkArgs, e);
			}
		}
		else if ("usb".equals(interfaceType)) {
			// ignore configured device address with USB on TP1 and always use 0.0.0
			final var adjustForTP1 = settings instanceof ReplaceInterfaceAddressProxy ? settings
					: settings instanceof TPSettings ? new UsbSettingsProxy(settings) : settings;
			if (requestBaos)
				ts = () -> BaosLinkAdapter.asBaosLink(new KNXNetworkLinkUsb(linkArgs, adjustForTP1));
			else
				ts = () -> new KNXNetworkLinkUsb(linkArgs, adjustForTP1);
		}
		else if ("ft12".equals(interfaceType)) {
			if ("cemi".equals(msgFormat))
				ts = () -> KNXNetworkLinkFT12.newCemiLink(linkArgs, settings);
			else if (requestBaos)
				ts = () -> BaosLinkAdapter.asBaosLink(new KNXNetworkLinkFT12(linkArgs, settings));
			else
				ts = () -> new KNXNetworkLinkFT12(linkArgs, settings);
		}
		else if ("ft12-cemi".equals(interfaceType))
			ts = () -> KNXNetworkLinkFT12.newCemiLink(linkArgs, settings);
		else if ("tpuart".equals(interfaceType))
			ts = () -> new KNXNetworkLinkTpuart(linkArgs, settings, acknowledge.get());
		else if ("user-supplied".equals(interfaceType))
			ts = () -> newLinkUsing(className, linkArgs.split(",|\\|"));
		else if ("virtual".equals(interfaceType)) {
			// if we use connector, we cannot cast link to VirtualLink for creating device links
			final KNXNetworkLink link = new VirtualLink(linkArgs, settings);
			setSubnetLink(link);
			return link;
		}
		else if ("emulate".equals(interfaceType)) {
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
					final byte[] tpdu = t.getTypeSize() == 0 ? DataUnitBuilder.createLengthOptimizedAPDU(0x80, t.getData())
							: DataUnitBuilder.createAPDU(0x80, t.getData());
					final CEMILData msg = new CEMILData(CEMILData.MC_LDATA_REQ, device, dp.getMainAddress(), tpdu, Priority.LOW);
					config.getBufferedLink().send(msg, true);
				}
			}

			ts = () -> config.getBufferedLink();
		}
		else
			throw new KNXException("network link: unknown KNX subnet specifier '" + interfaceType + "'");

		final Connector c = new Connector().reconnectOn(true, true, true)
				.reconnectDelay(Duration.ofSeconds(10)).connectionStatusNotifier(this::connectionStatusChanged);
		final KNXNetworkLink link = c.newLink(ts);
		setSubnetLink(link);
		return link;
	}

	public KNXNetworkMonitor openMonitorLink() throws KNXException, InterruptedException
	{
		final KNXMediumSettings settings = sc.getMediumSettings();
		final TSupplier<KNXNetworkMonitor> ts;
		// can cause a delay of connection timeout in the worst case
		if ("ip".equals(interfaceType))
			ts = () -> new KNXNetworkMonitorIP(new InetSocketAddress(0), parseRemoteEndpoint(), false, settings);
		else if ("usb".equals(interfaceType))
			ts = () -> new KNXNetworkMonitorUsb(linkArgs, settings);
		else if ("ft12".equals(interfaceType))
			ts = () -> new KNXNetworkMonitorFT12(linkArgs, settings);
		else if ("ft12-cemi".equals(interfaceType))
			ts = () -> KNXNetworkMonitorFT12.newCemiMonitor(linkArgs, settings);
		else if ("tpuart".equals(interfaceType))
			ts = () -> new KNXNetworkMonitorTpuart(linkArgs, false);
		else if ("user-supplied".equals(interfaceType))
			ts = () -> newLinkUsing(className, linkArgs.split(",|\\|"));
		else if ("virtual".equals(interfaceType) || "emulate".equals(interfaceType))
			return null;
		else
			throw new KNXException("monitor link: unknown KNX subnet specifier " + interfaceType);

		final Connector c = new Connector().reconnectOn(true, true, true)
				.reconnectDelay(Duration.ofSeconds(10)).connectionStatusNotifier(this::connectionStatusChanged);
		final KNXNetworkMonitor link = c.newMonitor(ts);
		setSubnetLink(link);
		return link;
	}

	private InetSocketAddress parseRemoteEndpoint() {
		final String[] args = linkArgs.split(":", -1);
		final String ip = args[0];
		final int port = args.length > 1 ? Integer.parseInt(args[1]) : 3671;
		return new InetSocketAddress(ip, port);
	}

	public String interfaceType() { return interfaceType; }

	public String format() { return msgFormat; }

	Optional<IndividualAddress> interfaceAddress() { return Optional.ofNullable(overrideInterfaceAddress); }

	String getInterfaceType()
	{
		return interfaceType;
	}

	public String linkArguments() { return linkArgs; }

	public void setAckOnTp(final Supplier<List<KNXAddress>> ackOnTp) {
		acknowledge = ackOnTp;
	}

	@Override
	public String toString() {
		final Object linkDesc = subnetLink != null ? subnetLink : (linkArgs + " " + msgFormat);
		return (interfaceType + " " + linkDesc).trim(); // trim because linkDesc might be empty
	}

	void setSubnetListener(final SubnetListener subnetListener)
	{
		listener = subnetListener;
		final AutoCloseable link = getSubnetLink();
		if (link instanceof KNXNetworkLink)
			((KNXNetworkLink) link).addLinkListener(listener);
		if (link instanceof KNXNetworkMonitor)
			((KNXNetworkMonitor) link).addMonitorListener(listener);
	}

	private volatile boolean requestBaos;

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

	// always use device address 0.0.0 with USB interface on TP1
	private static final class UsbSettingsProxy extends TPSettings {
		private final KNXMediumSettings delegate;

		UsbSettingsProxy(final KNXMediumSettings settings) {
			this.delegate = settings;
		}

		@Override
		public void setMaxApduLength(final int maxApduLength) {
			super.setMaxApduLength(maxApduLength);
			delegate.setMaxApduLength(maxApduLength);
		}
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
