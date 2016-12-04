/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2016 B. Malinowsky

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

import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.buffer.Configuration;
import tuwien.auto.calimero.buffer.NetworkBuffer;
import tuwien.auto.calimero.buffer.StateFilter;
import tuwien.auto.calimero.datapoint.Datapoint;
import tuwien.auto.calimero.datapoint.DatapointModel;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.link.Connector;
import tuwien.auto.calimero.link.Connector.TSupplier;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.KNXNetworkLinkFT12;
import tuwien.auto.calimero.link.KNXNetworkLinkIP;
import tuwien.auto.calimero.link.KNXNetworkLinkTpuart;
import tuwien.auto.calimero.link.KNXNetworkLinkUsb;
import tuwien.auto.calimero.link.KNXNetworkMonitor;
import tuwien.auto.calimero.link.KNXNetworkMonitorFT12;
import tuwien.auto.calimero.link.KNXNetworkMonitorIP;
import tuwien.auto.calimero.link.KNXNetworkMonitorTpuart;
import tuwien.auto.calimero.link.KNXNetworkMonitorUsb;
import tuwien.auto.calimero.link.LinkListener;
import tuwien.auto.calimero.link.NetworkLinkListener;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.server.VirtualLink;
import tuwien.auto.calimero.server.knxnetip.ServiceContainer;

/**
 * Contains information necessary to connect a server-side service container to a KNX subnet. A
 * gateway uses subnet connectors to lookup associations of service containers and KNX subnets. It
 * provides information for, e.g., message filtering based on group address tables.
 *
 * @author B. Malinowsky
 */
public class SubnetConnector
{
	private final ServiceContainer sc;
	private final String subnetType;
	private final String linkArgs;
	private final NetworkInterface netif;
	private final String className;
	private final int gatoi;
	private final Object[] args;

	private AutoCloseable subnetLink;
	private LinkListener listener;

	/**
	 * Creates a new subnet connector using a KNXnet/IP routing (KNX IP) subnet link.
	 *
	 * @param container service container
	 * @param routingNetif the network interface used for routing messages
	 * @param subnetArgs the arguments to create the KNX IP link
	 * @param groupAddrTableInstance instance of the server group address table in the
	 *        {@link InterfaceObjectServer} the connection will use for group address filtering
	 * @return the new subnet connector
	 */
	public static final SubnetConnector newWithRoutingLink(final ServiceContainer container,
		final NetworkInterface routingNetif, final String subnetArgs,
		final int groupAddrTableInstance)
	{
		return new SubnetConnector(container, "knxip", routingNetif, null, subnetArgs,
				groupAddrTableInstance);
	}

	/**
	 * Creates a new subnet connector using a user-supplied subnet link.
	 *
	 * @param container service container
	 * @param className the class name of to the user subnet link
	 * @param subnetArgs the arguments to create the subnet link
	 * @param groupAddrTableInstance instance of the server group address table in the
	 *        {@link InterfaceObjectServer} the connection will use for group address filtering
	 * @return the new subnet connector
	 */
	public static final SubnetConnector newWithUserLink(final ServiceContainer container,
		final String className, final String subnetArgs, final int groupAddrTableInstance)
	{
		return new SubnetConnector(container, "user-supplied", null, className, subnetArgs,
				groupAddrTableInstance);
	}

	/**
	 * Creates a new subnet connector using an interface type identifier for the KNX subnet interface.
	 *
	 * @param container service container
	 * @param interfaceType the interface type, use on of "ip", "usb", or "ft12".
	 * @param subnetArgs the arguments to create the subnet link
	 * @param groupAddrTableInstance instance of the server group address table in the {@link InterfaceObjectServer} the
	 *        connection will use for group address filtering
	 * @return the created subnet connector
	 */
	public static final SubnetConnector newWithInterfaceType(final ServiceContainer container,
		final String interfaceType, final String subnetArgs, final int groupAddrTableInstance)
	{
		return new SubnetConnector(container, interfaceType, null, null, subnetArgs, groupAddrTableInstance);
	}

	/**
	 * Creates a new subnet connector using an interface type identifier for the KNX subnet interface.
	 *
	 * @param container service container
	 * @param interfaceType the interface type
	 * @param groupAddrTableInstance instance of the server group address table in the {@link InterfaceObjectServer} the
	 *        connection will use for group address filtering
	 * @param subnetArgs the arguments to create the subnet link
	 * @return the created subnet connector
	 */
	public static final SubnetConnector newCustom(final ServiceContainer container, final String interfaceType,
		final int groupAddrTableInstance, final Object... subnetArgs)
	{
		return new SubnetConnector(container, interfaceType, null, null, interfaceType, groupAddrTableInstance,
				subnetArgs);
	}

	private SubnetConnector(final ServiceContainer container, final String interfaceType,
		final NetworkInterface routingNetif, final String className, final String subnetArgs,
		final int groupAddrTableInstance, final Object... args)
	{
		sc = container;
		subnetType = interfaceType;
		netif = routingNetif;
		this.className = className;
		linkArgs = subnetArgs;
		gatoi = groupAddrTableInstance;
		this.args = args;
	}

	/**
	 * Returns this subnet connector name.
	 * <p>
	 * The name equals the service container name.
	 *
	 * @return the subnet connector name
	 */
	public final String getName()
	{
		return sc.getName();
	}

	/**
	 * Returns the service container this connector is used with.
	 *
	 * @return the service container
	 */
	public final ServiceContainer getServiceContainer()
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
	public synchronized final AutoCloseable getSubnetLink()
	{
		return subnetLink;
	}

	public KNXNetworkLink openNetworkLink() throws KNXException, InterruptedException
	{
		final KNXMediumSettings settings = sc.getMediumSettings();
		final TSupplier<KNXNetworkLink> ts;
		// can cause a delay of connection timeout in the worst case
		if ("ip".equals(subnetType)) {
			final String[] args = linkArgs.split(":");
			final String ip = args[0];
			final int port = args.length > 1 ? Integer.parseInt(args[1]) : 3671;
			ts = () -> new KNXNetworkLinkIP(KNXNetworkLinkIP.TUNNELING, null,
					new InetSocketAddress(ip, port), false, settings);
		}
		else if ("knxip".equals(subnetType))
			ts = () -> new KNXNetworkLinkIP(netif, new InetSocketAddress(linkArgs, 0).getAddress(),
					settings);
		else if ("usb".equals(subnetType))
			ts = () -> new KNXNetworkLinkUsb(linkArgs, settings);
		else if ("ft12".equals(subnetType))
			ts = () -> new KNXNetworkLinkFT12(linkArgs, settings);
		else if ("tpuart".equals(subnetType)) {
			// TODO workaround for the only case when server ctrl endpoint address is reused!!
			final List<KNXAddress> ack = Arrays.asList(sc.getMediumSettings().getDeviceAddress());
			ts = () -> new KNXNetworkLinkTpuart(linkArgs, settings, ack);
		}
		else if ("user-supplied".equals(subnetType))
			ts = () -> newLinkUsing(className, linkArgs.split(",|\\|"));
		else if ("virtual".equals(subnetType)) {
			// if we use connector, we cannot cast link to VirtualLink for creating device links
			final KNXNetworkLink link = new VirtualLink(linkArgs, settings);
			setSubnetLink(link);
			return link;
		}
		else if ("emulate".equals(subnetType)) {
			final NetworkBuffer nb = NetworkBuffer.createBuffer(sc.getName());
			final VirtualLink vl = new VirtualLink(linkArgs, settings);
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
			vl.createDeviceLink(new IndividualAddress(0));

			ts = () -> config.getBufferedLink();
		}
		else
			throw new KNXException("network link: unknown KNX subnet specifier " + subnetType);

		final Connector c = new Connector().reconnectOn(true, true, true)
				.reconnectWait(10, TimeUnit.SECONDS).maxConnectAttempts(Connector.NoMaxAttempts);
		final KNXNetworkLink link = c.newLink(ts);
		setSubnetLink(link);
		return link;
	}

	public KNXNetworkMonitor openMonitorLink() throws KNXException, InterruptedException
	{
		final KNXMediumSettings settings = sc.getMediumSettings();
		final TSupplier<KNXNetworkMonitor> ts;
		// can cause a delay of connection timeout in the worst case
		if ("ip".equals(subnetType)) {
			final String[] args = linkArgs.split(":");
			final String ip = args[0];
			final int port = args.length > 1 ? Integer.parseInt(args[1]) : 3671;
			ts = () -> new KNXNetworkMonitorIP(null, new InetSocketAddress(ip, port), false,
					settings);
		}
		else if ("usb".equals(subnetType))
			ts = () -> new KNXNetworkMonitorUsb(linkArgs, settings);
		else if ("ft12".equals(subnetType))
			ts = () -> new KNXNetworkMonitorFT12(linkArgs, settings);
		else if ("tpuart".equals(subnetType))
			ts = () -> new KNXNetworkMonitorTpuart(linkArgs, false);
		else if ("user-supplied".equals(subnetType))
			ts = () -> newLinkUsing(className, linkArgs.split(",|\\|"));
		else if ("virtual".equals(subnetType) || "emulate".equals(subnetType))
			return null;
		else
			throw new KNXException("monitor link: unknown KNX subnet specifier " + subnetType);

		final Connector c = new Connector().reconnectOn(true, true, true)
				.reconnectWait(10, TimeUnit.SECONDS).maxConnectAttempts(Connector.NoMaxAttempts);
		final KNXNetworkMonitor link = c.newMonitor(ts);
		setSubnetLink(link);
		return link;
	}

	final String getInterfaceType()
	{
		return subnetType;
	}

	final String getLinkArguments()
	{
		return linkArgs;
	}

	final void setSubnetListener(final LinkListener subnetListener)
	{
		listener = subnetListener;
		final AutoCloseable link = getSubnetLink();
		if (link instanceof KNXNetworkLink)
			((KNXNetworkLink) link).addLinkListener((NetworkLinkListener) listener);
		if (link instanceof KNXNetworkMonitor)
			((KNXNetworkMonitor) link).addMonitorListener(listener);
	}

	int getGroupAddressTableObjectInstance()
	{
		return gatoi;
	}

	private <T> T newLinkUsing(final String className, final String[] initArgs)
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
			// InvocationTargetException, // ClassCastException, IllegalArgumentException,
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
}
