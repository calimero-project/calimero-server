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

package tuwien.auto.calimero.server.knxnetip;

import java.net.InetAddress;
import java.time.Duration;
import java.util.Optional;

import tuwien.auto.calimero.IndividualAddress;
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
	private final byte[] secureGroupKey;
	private final Duration latency;

	/**
	 * @deprecated Use {@link #RoutingServiceContainer(String, String, HPAI, KNXMediumSettings, boolean, InetAddress)}.
	 * @param name see {@link DefaultServiceContainer}
	 * @param netif network interface name this service container should use for KNXnet/IP routing, might be
	 *        <code>"any"</code> to use system default
	 * @param controlEndpoint see {@link DefaultServiceContainer}
	 * @param subnet KNX medium settings of the KNX subnet this service container is connected to
	 * @param allowNetworkMonitoring see {@link DefaultServiceContainer}
	 * @param reuseCtrlEndpt not used
	 * @param routingMulticast the routing multicast address this service container should use for KNXnet/IP routing; if
	 *        you are unsure about a supported multicast address, use {@link KNXnetIPRouting#DEFAULT_MULTICAST}
	 */
	@Deprecated
	public RoutingServiceContainer(final String name, final String netif, final HPAI controlEndpoint,
		final KNXMediumSettings subnet, final boolean reuseCtrlEndpt, final boolean allowNetworkMonitoring,
		final InetAddress routingMulticast)
	{
		this(name, netif, controlEndpoint, subnet, allowNetworkMonitoring, routingMulticast, null, Duration.ofMillis(0));
	}

	/**
	 * Creates a new service container configuration with support for a KNXnet/IP routing endpoint.
	 *
	 * @param name see {@link DefaultServiceContainer}
	 * @param netif network interface name this service container should use for KNXnet/IP routing, might be
	 *        <code>"any"</code> to use system default
	 * @param controlEndpoint see {@link DefaultServiceContainer}
	 * @param subnet KNX medium settings of the KNX subnet this service container is connected to
	 * @param allowNetworkMonitoring see {@link DefaultServiceContainer}
	 * @param routingMulticast the routing multicast address this service container should use for KNXnet/IP routing; if
	 *        you are unsure about a supported multicast address, use {@link KNXnetIPRouting#DEFAULT_MULTICAST}
	 */
	public RoutingServiceContainer(final String name, final String netif, final HPAI controlEndpoint,
		final KNXMediumSettings subnet, final boolean allowNetworkMonitoring,
		final InetAddress routingMulticast)
	{
		this(name, netif, controlEndpoint, subnet, allowNetworkMonitoring, routingMulticast, null, Duration.ofMillis(0));
	}

	/**
	 * Creates a new service container configuration equal to
	 * {@link #RoutingServiceContainer(String, String, HPAI, KNXMediumSettings, boolean, InetAddress)} with
	 * options for knx secure routing.
	 *
	 * @param name see {@link DefaultServiceContainer}
	 * @param netif network interface name this service container should use for KNXnet/IP routing, might be
	 *        <code>"any"</code> to use system default
	 * @param controlEndpoint see {@link DefaultServiceContainer}
	 * @param subnet KNX medium settings of the KNX subnet this service container is connected to
	 * @param allowNetworkMonitoring see {@link DefaultServiceContainer}
	 * @param routingMulticast the routing multicast address this service container should use for KNXnet/IP routing; if
	 *        you are unsure about a supported multicast address, use {@link KNXnetIPRouting#DEFAULT_MULTICAST}
	 * @param secureGroupKey KNX IP Secure group key (backbone key), <code>groupKey.length == 16</code>
	 * @param latencyTolerance time window for accepting secure multicasts, depending on max. end-to-end network latency
	 *        (typically 500 ms to 5000 ms), <code>latencyTolerance.toMillis() &gt; 0</code>
	 */
	public RoutingServiceContainer(final String name, final String netif, final HPAI controlEndpoint, final KNXMediumSettings subnet,
		final boolean allowNetworkMonitoring, final InetAddress routingMulticast, final byte[] secureGroupKey,
		final Duration latencyTolerance) {
		super(name, netif, controlEndpoint, subnet, false, allowNetworkMonitoring);
		final IndividualAddress addr = subnet.getDeviceAddress();
		if (addr.getDevice() != 0)
			throw new KNXIllegalArgumentException(
					"KNXnet/IP router requires coupler/backbone individual address x.y.0 (not " + addr + ")");
		if (!KNXnetIPRouting.isValidRoutingMulticast(routingMulticast))
			throw new KNXIllegalArgumentException(routingMulticast + " is not a valid KNX routing multicast address");
		mcast = routingMulticast;
		this.secureGroupKey = secureGroupKey;
		this.latency = latencyTolerance;
	}

	public final InetAddress routingMulticastAddress()
	{
		return mcast;
	}

	public final Optional<byte[]> secureGroupKey() {
		return Optional.ofNullable(secureGroupKey).map(byte[]::clone);
	}

	Duration latencyTolerance() {
		return latency;
	}
}
