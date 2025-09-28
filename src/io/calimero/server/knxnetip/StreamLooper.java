/*
    Calimero 3 - A library for KNX network access
    Copyright (c) 2024, 2024 B. Malinowsky

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

import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.WARNING;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.time.Duration;

import io.calimero.CloseEvent;
import io.calimero.KNXFormatException;
import io.calimero.KnxRuntimeException;
import io.calimero.knxnetip.EndpointAddress;
import io.calimero.knxnetip.servicetype.KNXnetIPHeader;

abstract sealed class StreamLooper implements Runnable, AutoCloseable
		permits UnixDomainSocketEndpoint.Looper, TcpEndpoint.Looper  {
	final ControlEndpointService ces;
	final EndpointAddress endpoint;
	private final SocketChannel channel;
	private final Logger logger;

	private final boolean baos;
	private boolean closing;

	StreamLooper(final ControlEndpointService ces, final EndpointAddress endpoint, final SocketChannel channel, final boolean baos) {
		this.ces = ces;
		this.endpoint = endpoint;
		this.channel = channel;
		this.baos = baos;
		this.logger = ces.logger;
	}

	@Override
	public void run() {
		final String name = Thread.currentThread().getName();

		try {
			if (baos) {
				if (!ces.setupBaosStreamEndpoint(endpoint))
					return;
			}

			logger.log(INFO, "accepted {0}", name);

			final int rcvBufferSize = 512;
			final byte[] data = new byte[rcvBufferSize];
			int offset = 0;

			while (connected()) {
				if (offset >= 6) {
					try {
						final KNXnetIPHeader h = new KNXnetIPHeader(data, 0);
						if (sanitize(h, offset)) {
							final var leftover = offset - h.getTotalLength();
							offset = leftover;
							onReceive(h, data, h.getStructLength());
							if (leftover > 0) {
								System.arraycopy(data, h.getTotalLength(), data, 0, leftover);
								continue;
							}
						}
						// skip bodies which do not fit into rcv buffer
						else if (h.getTotalLength() > rcvBufferSize) {
							int skip = h.getTotalLength() - offset;
							while (skip-- > 0 && read(new byte[1], 0) != -1);
							offset = 0;
						}
					}
					catch (final KNXFormatException e) {
						logger.log(WARNING, "received invalid frame", e);
						break;
					}
				}

				try {
					final int read = read(data, offset);
					if (read == -1)
						return;
					offset += read;
				}
				catch (final SocketTimeoutException e) {
					if (inactive()) {
						close("no active secure session or client connection");
						return;
					}
				}
			}
		}
		catch (final InterruptedIOException e) {
			Thread.currentThread().interrupt();
		}
		catch (final KnxRuntimeException e) {
			logger.log(WARNING, name + " error", e);
		}
		catch (IOException | RuntimeException e) {
			if (connected())
				logger.log(ERROR, "connection error to " + endpoint, e);
		}
		finally {
			close();
		}
	}

	public final void send(final byte[] data) throws IOException {
		try {
			write(data);
		}
		catch (final IOException e) {
			close("I/O error: " + e.getMessage());
			throw e;
		}
	}

	@Override
	public final void close() { close(""); }

	void close(final String reason) {
		synchronized (this) {
			if (closing)
				return;
			closing = true;
		}
		final String suffix = reason.isEmpty() ? "" : " (" + reason + ")";
		logger.log(INFO, "close connection to {0}{1}", endpoint, suffix);

		// Make sure we clean up any left-overs from active datapoints within this connection if the client
		// didn't close them properly (even if the channel got already closed!).
		// Close data endpoints in parallel to avoid scaling effect of timeouts.
		try (var scope = new TaskScope("data connection closer for " + endpoint, Duration.ofSeconds(12))) {
			for (final var ep : ces.connections().values()) {
				if (ep.remoteAddress().equals(endpoint))
					scope.execute(() -> ep.close(CloseEvent.SERVER_REQUEST,
							reason.isEmpty() ? "connection closing" : reason, Level.DEBUG, null));
			}
		}

		try {
			channel.close();
		}
		catch (final IOException ignore) {}
	}

	private boolean connected() { return channel.isConnected(); }

	// does this channel have any open knx secure sessions or knx ip data connections
	private boolean inactive() { return !ces.sessions.anyMatch(endpoint) && !ces.anyMatchDataConnection(endpoint); }

	private int read(final byte[] data, final int offset) throws IOException {
		return channel.read(ByteBuffer.wrap(data, offset, data.length - offset));
	}

	private void write(final byte[] data) throws IOException { channel.write(ByteBuffer.wrap(data)); }

	private void onReceive(final KNXnetIPHeader h, final byte[] data, final int offset)
			throws IOException, KNXFormatException {
		if (!ces.handleServiceType(h, data, offset, endpoint)) {
			final int svc = h.getServiceType();
			logger.log(INFO, "received packet from {0} with unknown service type 0x{1} - ignored", endpoint,
					Integer.toHexString(svc));
		}
	}

	private boolean sanitize(final KNXnetIPHeader h, final int length) {
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
