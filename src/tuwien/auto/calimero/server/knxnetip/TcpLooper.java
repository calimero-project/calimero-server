/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2018, 2023 B. Malinowsky

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

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.AbstractQueue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KnxRuntimeException;
import tuwien.auto.calimero.internal.Executor;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;

final class TcpLooper implements Runnable, AutoCloseable {

	private static final Duration inactiveConnectionTimeout = Duration.ofSeconds(10);

	static final ConcurrentHashMap<InetSocketAddress, TcpLooper> connections = new ConcurrentHashMap<>();

	private final ControlEndpointService ctrlEndpoint;
	private final Socket socket;
	private final boolean baos;
	private final Logger logger;

	// impl note: we cannot simply return the future of ExecutorService::submit, because Future::cancel is
	// interrupt-based, and the server socket does not honor interrupts; we have to close the socket directly
	public static Closeable start(final ControlEndpointService ctrlEndpoint, final InetSocketAddress endpoint,
			final boolean baos) throws InterruptedException {
		final var serverSocket = new ArrayBlockingQueue<Closeable>(1);
		final Future<?> task = Executor.executor()
				.submit(() -> runTcpServerEndpoint(ctrlEndpoint, endpoint, baos, serverSocket));
		while (!task.isDone()) {
			final var v = serverSocket.poll(1, TimeUnit.SECONDS);
			if (v != null)
				return v;
		}
		throw new KnxRuntimeException("couldn't start tcp service for " + ctrlEndpoint.getServiceContainer().getName());
	}

	private TcpLooper(final ControlEndpointService ces, final Socket conn, final boolean baos) {
		ctrlEndpoint = ces;
		socket = conn;
		this.baos = baos;
		logger = ctrlEndpoint.logger;
	}

	static boolean send(final byte[] buf, final InetSocketAddress address) throws IOException {
		final TcpLooper looper = connections.get(address);
		if (looper == null)
			return false;

		looper.send(buf);
		return true;
	}

	private static void runTcpServerEndpoint(final ControlEndpointService ces, final InetSocketAddress endpoint,
			final boolean baos, final AbstractQueue<Closeable> serverSocket) {

		final String namePrefix = ces.server.getName() + " " + ces.getServiceContainer().getName() + (baos ? " baos" : "")
				+ " tcp ";
		final String name = namePrefix + "service";
		Thread.currentThread().setName(name);

		ServerSocket localRef = null;
		try (ServerSocket s = new ServerSocket(endpoint.getPort(), 50, endpoint.getAddress())) {
			serverSocket.add(s);
			localRef = s;
			final var netif = NetworkInterface.getByInetAddress(s.getInetAddress());
			ces.logger.info("{} ({} {}) is up and running", name, netif.getName(),
					hostPort((InetSocketAddress) s.getLocalSocketAddress()));
			while (true) {
				final Socket conn = s.accept();
				conn.setTcpNoDelay(true);
				final TcpLooper looper = new TcpLooper(ces, conn, baos);
				connections.put((InetSocketAddress) conn.getRemoteSocketAddress(), looper);

				Executor.execute(looper, namePrefix + "connection "
						+ hostPort((InetSocketAddress) conn.getRemoteSocketAddress()));
			}
		}
		catch (final InterruptedIOException e) {
			ces.logger.info("tcp service {}:{} interrupted", endpoint.getAddress().getHostAddress(),
					endpoint.getPort());
			Thread.currentThread().interrupt();
		}
		catch (final IOException e) {
			if (localRef == null || !localRef.isClosed())
				ces.logger.error("socket error in tcp service {}:{}", endpoint.getAddress().getHostAddress(),
						endpoint.getPort(), e);
		}
	}

	private static String hostPort(final InetSocketAddress addr) {
		return ServiceLooper.hostPort(addr);
	}

	static void lastSessionTimedOut(final InetSocketAddress remote) {
		final TcpLooper looper = connections.get(remote);
		if (looper != null && !looper.ctrlEndpoint.anyMatchDataConnection(remote))
			looper.close("last active secure session timed out");
	}

	static void lastConnectionTimedOut(final InetSocketAddress remote) {
		final TcpLooper looper = connections.get(remote);
		if (looper != null && !looper.ctrlEndpoint.sessions.anyMatch(remote))
			looper.close("last active client connection timed out");
	}

	private boolean inactive() {
		final InetSocketAddress remote = (InetSocketAddress) socket.getRemoteSocketAddress();
		return !ctrlEndpoint.sessions.anyMatch(remote) && !ctrlEndpoint.anyMatchDataConnection(remote);
	}

	@Override
	public void run() {
		final String name = Thread.currentThread().getName();

		try (InputStream in = socket.getInputStream()) {
			if (baos) {
				if (!ctrlEndpoint.setupBaosTcpEndpoint((InetSocketAddress) socket.getRemoteSocketAddress()))
					return;
			}

			logger.info("accepted {}", name);

			final int rcvBufferSize = 512;
			final byte[] data = new byte[rcvBufferSize];
			int offset = 0;
			if (!baos)
				socket.setSoTimeout((int) inactiveConnectionTimeout.toMillis());

			while (!socket.isClosed()) {
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
							while (skip-- > 0 && in.read() != -1);
							offset = 0;
						}
					}
					catch (final KNXFormatException e) {
						logger.warn("received invalid frame", e);
						break;
					}
				}

				try {
					final int read = in.read(data, offset, data.length - offset);
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
			logger.warn("{} error", name, e);
		}
		catch (IOException | RuntimeException e) {
			if (!socket.isClosed())
				logger.error("tcp connection error to {}", hostPort((InetSocketAddress) socket.getRemoteSocketAddress()), e);
		}
		finally {
			close();
		}
	}

	public void send(final byte[] data) throws IOException {
		try {
			final OutputStream out = socket.getOutputStream();
			out.write(data);
			out.flush();
		}
		catch (final IOException e) {
			close("I/O error: " + e.getMessage());
			throw e;
		}
	}

	@Override
	public void close() {
		close("");
	}

	private void close(final String reason) {
		final String suffix = reason.isEmpty() ? "" : " (" + reason + ")";
		logger.info("close tcp connection to {}{}", hostPort((InetSocketAddress) socket.getRemoteSocketAddress()), suffix);
		try {
			socket.close();
		}
		catch (final IOException ignore) {}
		connections.remove(socket.getRemoteSocketAddress());
	}

	private void onReceive(final KNXnetIPHeader h, final byte[] data, final int offset)
		throws IOException, KNXFormatException {
		final InetSocketAddress remote = (InetSocketAddress) socket.getRemoteSocketAddress();
		if (!ctrlEndpoint.handleServiceType(h, data, offset, remote)) {
			final int svc = h.getServiceType();
			logger.info("received packet from {} with unknown service type 0x{} - ignored", remote,
					Integer.toHexString(svc));
		}
	}

	private boolean sanitize(final KNXnetIPHeader h, final int length) {
		if (h.getTotalLength() > length)
			logger.warn("received frame with expected length {} does not match actual length {} - ignored",
					h.getTotalLength(), length);
		else if (h.getServiceType() == 0)
			// check service type for 0 (invalid type), so unused service types of us can stay 0 by default
			logger.warn("received frame with service type 0 - ignored");
		else
			return true;
		return false;
	}
}
