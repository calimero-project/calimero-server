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

/**
 * 
 */

package tuwien.auto.calimero.server.knxnetip;

import java.net.InetAddress;
import java.net.NetworkInterface;

/**
 * Specifies the mix-in interface for service containers supporting KNXnet/IP Routing.
 * <p>
 * A service container which wants to provide a KNXnet/IP Routing service end-point to clients has
 * to implement this interface.
 * 
 * @author B. Malinowsky
 */
public interface RoutingEndpoint
{
	/**
	 * Returns the KNXnet/IP routing multicast address on which the routing service will receive and
	 * multicast its routing datagrams.
	 * <p>
	 * 
	 * @return an InetAddress with the routing multicast address
	 */
	InetAddress getRoutingMulticastAddress();

	/**
	 * Returns the local network interface used to join for multicasting KNXnet/IP routing
	 * datagrams.
	 * <p>
	 * This method is useful on multi-homed platforms.
	 * 
	 * @return a NetworkInterface identifying a local network interface
	 */
	NetworkInterface getRoutingInterface();
}
