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

package tuwien.auto.calimero.server.knxnetip;

import java.net.InetAddress;
import java.net.NetworkInterface;

import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.knxnetip.KNXnetIPRouting;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;

/**
 * A service container supporting configuration for a routing endpoint.
 * <p>
 * When this service container is handed to a KNXnet/IP server, the server will
 * access the configured KNXnet/IP routing configuration, and initialize its service container to
 * providing routing services to the clients.
 *
 * @author B. Malinowsky
 */
public class RoutingServiceContainer extends DefaultServiceContainer
{
	private final InetAddress mcast;

	/**
	 * Creates a new service container configuration with support for a KNXnet/IP routing endpoint.
	 *
	 * @param name see {@link DefaultServiceContainer}
	 * @param controlEndpoint see {@link DefaultServiceContainer}
	 * @param subnet KNX medium settings of the KNX subnet this service container is connected to
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
		final KNXMediumSettings subnet, final boolean reuseCtrlEndpt,
		final boolean allowNetworkMonitoring, final InetAddress routingMulticast,
		final NetworkInterface routingInterface)
	{
		super(name, routingInterface != null ? routingInterface.getName() : "any", controlEndpoint, subnet,
				reuseCtrlEndpt, allowNetworkMonitoring);
		if (!KNXnetIPRouting.isValidRoutingMulticast(routingMulticast))
			throw new KNXIllegalArgumentException(routingMulticast
					+ " is not a valid KNX routing multicast address");
		mcast = routingMulticast;
	}

	public final InetAddress routingMulticastAddress()
	{
		return mcast;
	}

	@Deprecated
	public InetAddress getRoutingMulticastAddress()
	{
		return mcast;
	}
}
