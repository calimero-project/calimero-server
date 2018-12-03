/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2018 B. Malinowsky

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
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.slf4j.Logger;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.knxnetip.util.HPAI;

final class TcpLooper implements Runnable, AutoCloseable {

	private final ControlEndpointService ctrlEndpoint;
	private final Socket socket;
	private final Logger logger;

	static final Map<SocketAddress, TcpLooper> connections = new ConcurrentHashMap<>();

	private static final ExecutorService pool = Executors.newCachedThreadPool(r -> {
		final Thread t = new Thread(r);
		t.setDaemon(true);
		return t;
	});

	private TcpLooper(final ControlEndpointService ces, final Socket conn) {
		ctrlEndpoint = ces;
		socket = conn;
		logger = ctrlEndpoint.logger;
	}

	static void start(final ControlEndpointService ctrlEndpoint) {
		pool.execute(tcpEndpoint(ctrlEndpoint));
	}

	private static Runnable tcpEndpoint(final ControlEndpointService ces) {
		return () -> {
			final String name = ces.server.getName() + " tcp service " + ces.getServiceContainer().getName();
			Thread.currentThread().setName(name);

			final HPAI endpoint = ces.getServiceContainer().getControlEndpoint();
			try (ServerSocket s = new ServerSocket(endpoint.getPort(), 50, endpoint.getAddress())) {
				while (true) {
					final Socket conn = s.accept();
					final TcpLooper looper = new TcpLooper(ces, conn);
					connections.put(looper.socket.getRemoteSocketAddress(), looper);
					pool.execute(looper);
				}
			}
			catch (final IOException e) {
				ces.logger.error("socket error in TCP control endpoint", e);
			}
		};
	}

	static boolean send(final byte[] buf, final InetSocketAddress address) throws IOException {
		final TcpLooper looper = connections.get(address);
		if (looper == null)
			return false;

		looper.send(buf);
		return true;
	}

	@Override
	public void run() {
		final String name = ctrlEndpoint.server.getName() + " data endpoint " + socket.getRemoteSocketAddress() + " (tcp)";
		Thread.currentThread().setName(name);

		try (InputStream in = socket.getInputStream()) {
			final byte[] data = new byte[512];
			int offset = 0;
			while (!socket.isClosed()) {
				final int read = in.read(data, offset, data.length - offset);
				if (read == -1)
					break;
				offset += read;

				if (offset > 6) {
					try {
						final KNXnetIPHeader h = new KNXnetIPHeader(data, 0);
						if (sanitize(h, offset)) {
							final int length = offset - h.getStructLength();
							offset = 0;
							onReceive(h, data, h.getStructLength(), length);
						}
					}
					catch (final KNXFormatException e) {
						logger.warn("received invalid frame", e);
					}
				}
			}
		}
		catch (final InterruptedIOException e) {
			Thread.currentThread().interrupt();
		}
		catch (IOException | RuntimeException e) {
			logger.error("close connection to {}", socket.getRemoteSocketAddress(), e);
		}
		finally {
			close();
			Thread.currentThread().setName("idle tcp looper");
		}
	}

	public void send(final byte[] data) throws IOException {
		try {
			final OutputStream out = socket.getOutputStream();
			out.write(data);
			out.flush();
		}
		catch (final IOException e) {
			socket.close();
			throw e;
		}
	}

	@Override
	public void close() {
		try {
			socket.close();
		}
		catch (final IOException ignore) {}
		connections.remove(socket.getRemoteSocketAddress());
	}

	private void onReceive(final KNXnetIPHeader h, final byte[] data, final int offset, final int length)
		throws IOException, KNXFormatException {
		final InetSocketAddress remote = (InetSocketAddress) socket.getRemoteSocketAddress();
		if (!ctrlEndpoint.handleServiceType(h, data, offset, remote.getAddress(), remote.getPort())) {
			final int svc = h.getServiceType();
			logger.info("received packet from {} with unknown service type 0x{} - ignored", remote, Integer.toHexString(svc));
		}
	}

	private boolean sanitize(final KNXnetIPHeader h, final int length) {
		if (h.getTotalLength() > length)
			logger.warn("received frame length does not match - ignored");
		else if (h.getServiceType() == 0)
			// check service type for 0 (invalid type), so unused service types of us can stay 0 by default
			logger.warn("received frame with service type 0 - ignored");
		else
			return true;
		return false;
	}
}
