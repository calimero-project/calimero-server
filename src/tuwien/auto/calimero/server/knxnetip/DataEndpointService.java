/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2016 B. Malinowsky

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

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.log.LogService.LogLevel;
import tuwien.auto.calimero.server.knxnetip.DataEndpointServiceHandler.ServiceCallback;

final class DataEndpointService extends ServiceLooper implements ServiceCallback
{
	// KNX receive timeout in seconds
	private static final int MAX_RECEIVE_INTERVAL = 120;

	DataEndpointServiceHandler svcHandler;
	private final ServiceCallback callback;

	DataEndpointService(final KNXnetIPServer server, final ServiceCallback callback,
		final DatagramSocket localCtrlEndpt)
	{
		super(server, newSocketUsingIp(localCtrlEndpt), 512, MAX_RECEIVE_INTERVAL * 1000);
		this.callback = callback;
		logger.debug("created socket on " + s.getLocalSocketAddress());
	}

	@Override
	public void connectionClosed(final DataEndpointServiceHandler h, final IndividualAddress assigned)
	{
		quit();
		callback.connectionClosed(h, assigned);
	}

	@Override
	public void resetRequest(final DataEndpointServiceHandler h)
	{
		final InetSocketAddress ctrlEndpoint = null;
		fireResetRequest(h.getName(), ctrlEndpoint);
	}

	@Override
	protected void onTimeout()
	{
		// at first check if control endpoint received a connection-state request in
		// the meantime and updated the last msg timestamp
		final long now = System.currentTimeMillis();
		if (now - svcHandler.getLastMsgTimestamp() >= MAX_RECEIVE_INTERVAL * 1000)
			svcHandler.close(CloseEvent.SERVER_REQUEST, "server connection timeout", LogLevel.WARN, null);
		else
			setTimeout();
	}

	@Override
	void cleanup(final LogLevel level, final Throwable t)
	{
		if (t != null)
			svcHandler.cleanup(CloseEvent.INTERNAL, "communication failure", level, t);
	};

	@Override
	boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset, final InetAddress src,
		final int port) throws KNXFormatException, IOException
	{
		try {
			return svcHandler.handleDataServiceType(h, data, offset);
		}
		finally {
			setTimeout();
		}
	}

	private void setTimeout()
	{
		// don't allow timeout 0, otherwise socket will have infinite timeout
		final long elapsed = System.currentTimeMillis() - svcHandler.getLastMsgTimestamp();
		final int timeout = Math.max((int) (MAX_RECEIVE_INTERVAL * 1000 - elapsed), 250);
		try {
			s.setSoTimeout(timeout);
		}
		catch (final SocketException e) {}
	}

	private static DatagramSocket newSocketUsingIp(final DatagramSocket localCtrlEndpt)
	{
		try {
			return new DatagramSocket(0, localCtrlEndpt.getLocalAddress());
		}
		catch (final SocketException e) {
			throw new RuntimeException(e);
		}
	}
}
