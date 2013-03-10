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

import java.net.InetSocketAddress;

import tuwien.auto.calimero.CloseEvent;

/**
 * Event informing about a planned or requested shutdown of a {@link KNXnetIPServer}
 * instance.
 * <p>
 * An example for a shutdown request would be a reset request received with a cEMI device
 * management message by the server from a KNXnet/IP client.
 * 
 * @author B. Malinowsky
 */
public class ShutdownEvent extends CloseEvent
{
	private static final long serialVersionUID = 1L;

	private final InetSocketAddress ctrlEndpt;

	/**
	 * Creates a new shutdown event.
	 * <p>
	 * 
	 * @param source the KNXnet/IP server instance
	 * @param initiator initiator of the close event, one of {@link #USER_REQUEST},
	 *        {@link #CLIENT_REQUEST} or {@link #INTERNAL}
	 * @param reason brief textual description
	 */
	public ShutdownEvent(final KNXnetIPServer source, final int initiator,
		final String reason)
	{
		super(source, initiator, reason);
		ctrlEndpt = null;
	}

	/**
	 * Creates a new client-requested shutdown event initiated by a received reset
	 * message, using server endpoint information.
	 * <p>
	 * 
	 * @param source the KNXnet/IP server instance
	 * @param endpointName name of the server-side endpoint of the connection the client request
	 *        was received
	 * @param ctrlEndpoint control endpoint of the service container with the client
	 *        connection
	 */
	public ShutdownEvent(final KNXnetIPServer source, final String endpointName,
		final InetSocketAddress ctrlEndpoint)
	{
		super(source, CLIENT_REQUEST, "server reset request by " + endpointName);
		ctrlEndpt = ctrlEndpoint;
	}
}
