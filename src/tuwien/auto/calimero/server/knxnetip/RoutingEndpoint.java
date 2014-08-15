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
