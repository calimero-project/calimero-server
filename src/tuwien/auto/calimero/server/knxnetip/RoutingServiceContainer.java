/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2011 B. Malinowsky

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

package tuwien.auto.calimero.server.knxnetip;

import java.net.InetAddress;
import java.net.NetworkInterface;

import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.exception.KNXIllegalArgumentException;
import tuwien.auto.calimero.knxnetip.KNXnetIPRouting;
import tuwien.auto.calimero.knxnetip.util.HPAI;

/**
 * A service container supporting configuration for a routing endpoint.
 * <p>
 * This class implements the interface {@link RoutingEndpoint}, to access the configuration for
 * KNXnet/IP routing. When this service container is handed to a KNXnet/IP server, the server will
 * access the configured KNXnet/IP routing configuration, and initialize its service container to
 * providing routing services to the clients.
 * 
 * @author B. Malinowsky
 */
public class RoutingServiceContainer extends DefaultServiceContainer implements RoutingEndpoint
{
	private final InetAddress mcast;
	private final NetworkInterface netIf;

	/**
	 * Creates a new service container configuration with support for a KNXnet/IP routing endpoint.
	 * <p>
	 * 
	 * @param name see {@link DefaultServiceContainer}
	 * @param controlEndpoint see {@link DefaultServiceContainer}
	 * @param knxMedium see {@link DefaultServiceContainer}
	 * @param knxSubnet see {@link DefaultServiceContainer}
	 * @param reuseCtrlEndpt see {@link DefaultServiceContainer}
	 * @param allowNetworkMonitoring see {@link DefaultServiceContainer}
	 * @param routingMulticast the routing multicast address this service container should use for
	 *        KNXnet/IP routing; if you are unsure about a supported multicast address, use
	 *        {@link KNXnetIPRouting#DEFAULT_MULTICAST}
	 * @param routingInterface the network interface this service container should use for KNXnet/IP
	 *        routing, might be <code>null</code> to use the system default. Note that choosing a
	 *        particular interface can be tied to the selected routing multicast address parameter
	 *        <code>routingMulticast</code>.
	 */
	public RoutingServiceContainer(final String name, final HPAI controlEndpoint,
		final int knxMedium, final IndividualAddress knxSubnet, final boolean reuseCtrlEndpt,
		final boolean allowNetworkMonitoring, final InetAddress routingMulticast,
		final NetworkInterface routingInterface)
	{
		super(name, controlEndpoint, knxMedium, knxSubnet, reuseCtrlEndpt, allowNetworkMonitoring);
		if (!KNXnetIPRouting.isValidRoutingMulticast(routingMulticast))
			throw new KNXIllegalArgumentException(routingMulticast
					+ " is not a valid KNX routing multicast address");
		mcast = routingMulticast;
		netIf = routingInterface;
	}

	/**
	 * @param name see {@link DefaultServiceContainer}
	 * @param controlEndpoint see {@link DefaultServiceContainer}
	 * @param knxMedium see {@link DefaultServiceContainer}
	 * @param knxSubnet see {@link DefaultServiceContainer}
	 * @param routingMulticast the routing multicast address this service container should use for
	 *        KNXnet/IP routing; if you are unsure about a supported multicast address, use
	 *        {@link KNXnetIPRouting#DEFAULT_MULTICAST}
	 * @param routingInterface the network interface this service container should use for KNXnet/IP
	 *        routing, might be <code>null</code> to use the system default. Note that choosing a
	 *        particular interface can be tied to the routing multicast address parameter
	 *        <code>routingMulticast</code>.
	 */
	public RoutingServiceContainer(final String name, final HPAI controlEndpoint,
		final int knxMedium, final IndividualAddress knxSubnet, final InetAddress routingMulticast,
		final NetworkInterface routingInterface)
	{
		super(name, controlEndpoint, knxMedium, knxSubnet);
		if (!KNXnetIPRouting.isValidRoutingMulticast(routingMulticast))
			throw new KNXIllegalArgumentException(routingMulticast
					+ " is not a valid KNX routing multicast address");
		mcast = routingMulticast;
		netIf = routingInterface;
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.server.knxnetip.RoutingEndpoint#getRoutingMulticastAddress()
	 */
	public InetAddress getRoutingMulticastAddress()
	{
		return mcast;
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.server.knxnetip.RoutingEndpoint#getRoutingInterface()
	 */
	public NetworkInterface getRoutingInterface()
	{
		return netIf;
	}
}
