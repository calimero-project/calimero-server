/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2016, 2024 B. Malinowsky

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

package io.calimero.server.knxnetip;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Set;

import io.calimero.KNXFormatException;
import io.calimero.KnxRuntimeException;
import io.calimero.internal.UdpSocketLooper;
import io.calimero.knxnetip.KNXnetIPConnection;
import io.calimero.knxnetip.servicetype.ErrorCodes;
import io.calimero.knxnetip.servicetype.KNXnetIPHeader;
import io.calimero.knxnetip.util.HPAI;

abstract class ServiceLooper extends UdpSocketLooper implements Runnable
{
	final KNXnetIPServer server;
	final Logger logger;
	boolean useNat;

	ServiceLooper(final KNXnetIPServer server, final DatagramSocket socket, final int receiveBufferSize,
		final int socketTimeout)
	{
		super(socket, true, receiveBufferSize, socketTimeout, 0);
		this.server = server;
		this.logger = server.logger;
	}

	ServiceLooper(final KNXnetIPServer server, final DatagramSocket socket, final boolean closeSocket,
		final int receiveBufferSize, final int socketTimeout)
	{
		super(socket, closeSocket, receiveBufferSize, socketTimeout, 0);
		this.server = server;
		this.logger = server.logger;
	}

	@Override
	public void run()
	{
		try {
			loop();
			cleanup(DEBUG, null);
		}
		catch (IOException | UncheckedIOException e) {
			cleanup(ERROR, e);
		}
		catch (final RuntimeException e) {
			final Object id = s != null && !s.isClosed() ? s.getLocalSocketAddress() : Thread.currentThread().getName();
			logger.log(ERROR, "runtime exception in service loop of " + id, e);
			cleanup(INFO, null);
		}
	}

	@Override
	public void onReceive(final InetSocketAddress source, final byte[] data, final int offset, final int length)
		throws IOException
	{
		try {
			final KNXnetIPHeader h = KNXnetIPHeader.from(data, offset);
			if (!sanitize(h, length))
				return;
			if (!handleServiceType(h, data, offset + h.getStructLength(), new EndpointAddress(source))) {
				final int svc = h.getServiceType();
				if (!ignoreServices.contains(svc))
					logger.log(INFO, "received packet from {0} with unknown service type 0x{1} - ignored", source,
							Integer.toHexString(svc));
			}
		}
		catch (final KNXFormatException e) {
			logger.log(WARNING, "received invalid frame", e);
		}
	}

	private static final Set<Integer> ignoreServices = Set.of(
			KNXnetIPHeader.SEARCH_RES,
			KNXnetIPHeader.SearchResponse);

	@Override
	protected void onTimeout()
	{
		logger.log(ERROR, "socket timeout - ignored, but should not happen");
	}

	boolean checkVersion(final KNXnetIPHeader h)
	{
		final boolean ok = h.getVersion() == KNXnetIPConnection.KNXNETIP_VERSION_10;
		if (!ok)
			logger.log(WARNING, "KNXnet/IP " + (h.getVersion() >> 4) + "." + (h.getVersion() & 0xf) + " "
					+ ErrorCodes.getErrorMessage(ErrorCodes.VERSION_NOT_SUPPORTED));
		return ok;
	}

	record EndpointAddress(InetSocketAddress inet) {
		@Override
		public final String toString() {
			return hostPort(inet);
		}
	}

	abstract boolean handleServiceType(KNXnetIPHeader h, byte[] data, int offset, EndpointAddress src)
		throws KNXFormatException, IOException;

	void cleanup(final Level level, final Throwable t)
	{
		logger.log(level, "cleanup {0}", Thread.currentThread().getName(), t);
	}

	DatagramSocket getSocket()
	{
		return s;
	}

	// logEndpointType: 0 = don't log, 1 = ctrl endpt, 2 = data endpt
	EndpointAddress createResponseAddress(final HPAI endpoint, final EndpointAddress sender,
			final int logEndpointType) {
		final String type = logEndpointType == 1 ? "control" : logEndpointType == 2 ? "data" : "";

		// if we once decided on NAT aware communication, we will stick to it,
		// regardless whether subsequent HPAIs contain useful information
		if (useNat) {
			if (logEndpointType != 0)
				logger.log(DEBUG, "responses use route-back {0} endpoint {1}", type, sender);
			return sender;
		}

		// in NAT aware mode, if the data EP is incomplete or left
		// empty, we fall back to the IP address and port of the sender
		if (endpoint.nat()) {
			useNat = true;
			if (logEndpointType != 0)
				logger.log(DEBUG, "responses to client use route-back {0} endpoint {1}", type, sender);
			return sender;
		}

		if (logEndpointType == 2)
			logger.log(TRACE, "using client-assigned {0} endpoint {1} for responses", type, hostPort(endpoint.endpoint()));
		return new EndpointAddress(endpoint.endpoint());
	}

	void fireResetRequest(final String endpointName, final InetSocketAddress ctrlEndpoint)
	{
		final ShutdownEvent se = new ShutdownEvent(server, endpointName, ctrlEndpoint);
		server.listeners().fire(l -> l.onResetRequest(se));
	}

	static RuntimeException wrappedException(final Exception e)
	{
		if (e instanceof RuntimeException)
			return (RuntimeException) e;
		final var rte = new KnxRuntimeException(e.getMessage(), e);
		rte.setStackTrace(e.getStackTrace());
		return rte;
	}

	static String hostPort(final InetSocketAddress addr) {
		return addr.getAddress().getHostAddress() + ":" + addr.getPort();
	}

	private boolean sanitize(final KNXnetIPHeader h, final int length)
	{
		if (h.getTotalLength() > length)
			logger.log(WARNING, "received frame with expected length {0} does not match actual length {1} - ignored",
					h.getTotalLength(), length);
		else if (h.getServiceType() == 0)
			// check service type for 0 (invalid type), so unused service types of us can stay 0 by default
			logger.log(WARNING, "received frame with service type 0 - ignored");
		else
			return true;
		return false;
	}
}
