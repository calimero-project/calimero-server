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

package tuwien.auto.calimero.server.gateway;

import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.NetworkLinkListener;
import tuwien.auto.calimero.server.InterfaceObjectServer;
import tuwien.auto.calimero.server.knxnetip.ServiceContainer;

/**
 * Contains information necessary to connect a server-side service container to a KNX subnet.
 * <p>
 * A gateway is using subnet connectors to lookup associations of service containers and KNX
 * subnets. It provides information for, e.g., message filtering based on group address tables.
 * 
 * @author B. Malinowsky
 */
public class SubnetConnector
{
	private final ServiceContainer sc;
	private final KNXNetworkLink subnet;
	private NetworkLinkListener nll;
	private final int gatoi;

	/**
	 * Creates a new subnet connector.
	 * <p>
	 * 
	 * @param container service container
	 * @param subnetLink subnetLink sets the network link representing the connection to the KNX
	 *        subnet
	 * @param groupAddrTableInstance instance of the server group address table in the
	 *        {@link InterfaceObjectServer} the connection will use for group address filtering
	 */
	public SubnetConnector(final ServiceContainer container, final KNXNetworkLink subnetLink,
		final int groupAddrTableInstance)
	{
		sc = container;
		subnet = subnetLink;
		gatoi = groupAddrTableInstance;
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
	 * Returns the service container this connector is used for.
	 * <p>
	 * 
	 * @return the service container
	 */
	public final ServiceContainer getServiceContainer()
	{
		return sc;
	}

	/**
	 * Returns the KNX network link of the KNX subnet the service container is connected to.
	 * <p>
	 * 
	 * @return a KNX network link representing the KNX subnet connection
	 */
	public final KNXNetworkLink getSubnetLink()
	{
		return subnet;
	}

	// used by gateway: sets the subnet listener and stores the listener reference
	final void setSubnetListener(final NetworkLinkListener subnetListener)
	{
		nll = subnetListener;
		getSubnetLink().addLinkListener(nll);
	}

	// used by gateway to store its subnet listener
	NetworkLinkListener getSubnetListener()
	{
		return nll;
	}

	int getGroupAddressTableObjectInstance()
	{
		return gatoi;
	}
}
