/*
    Calimero 3 - A library for KNX network access
    Copyright (c) 2018, 2025 B. Malinowsky

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

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import io.calimero.KnxRuntimeException;
import io.calimero.internal.Executor;
import io.calimero.knxnetip.EndpointAddress;
import io.calimero.knxnetip.TcpEndpointAddress;

sealed abstract class StreamEndpoint implements AutoCloseable
		permits TcpEndpoint, UnixDomainSocketEndpoint {

	final ConcurrentHashMap<EndpointAddress, StreamLooper> connections = new ConcurrentHashMap<>();
	final ControlEndpointService ctrlEndpoint;
	final EndpointAddress endpoint;
	final boolean baos;

	private final String namePrefix;
	private final String name;
	private volatile Thread thread;

	StreamEndpoint(final ControlEndpointService ces, final EndpointAddress endpoint, final String name, final boolean baos) {
		ctrlEndpoint = ces;
		this.endpoint = endpoint;
		this.baos = baos;

		namePrefix = ctrlEndpoint.getServiceContainer().getName() + (baos ? " baos" : "") + " ";
		this.name = namePrefix + name + " service";
	}

	void start() throws InterruptedException {
		final var init = new CompletableFuture<Void>();

		final Runnable loop = () -> {
			try (var server = open()) {
				init.complete(null);

				if (endpoint instanceof TcpEndpointAddress) {
					final var isa = (InetSocketAddress) server.getLocalAddress();
					final var netif = NetworkInterface.getByInetAddress(isa.getAddress());
					ctrlEndpoint.logger.log(INFO, "{0} {1}/{2} is up and running", name, netif.getName(), endpoint);
				}
				else
					ctrlEndpoint.logger.log(INFO, "{0} {1} is up and running", name, endpoint);

				while (true) {
					final var channel = server.accept();
					final var looper = newLooper(channel);
					connections.put(looper.endpoint, looper);
					Executor.execute(looper, namePrefix + "connection " + looper.endpoint);
				}
			}
			catch (final Throwable t) {
				if (init.completeExceptionally(t))
					return;
				if (t instanceof ClosedByInterruptException)
					ctrlEndpoint.logger.log(Level.DEBUG, "{0} {1} closed", name, endpoint);
				else if (t instanceof final IOException e)
					ctrlEndpoint.logger.log(ERROR, "socket error in " + name + " " + endpoint, e);
			}
			finally {
				cleanup();
			}
		};

		try {
			thread = Executor.execute(loop, name);
			init.get(5, TimeUnit.SECONDS);
		}
		catch (final Throwable t) {
			close();
			final String msg = "couldn't start %s %s".formatted(name, endpoint);
			switch (t) {
				case InterruptedException e -> throw e;
				case ExecutionException __  -> throw new KnxRuntimeException(msg, t.getCause());
				default                     -> throw new KnxRuntimeException(msg, t);
			}
		}
	}

	abstract ServerSocketChannel open() throws IOException;

	abstract StreamLooper newLooper(SocketChannel channel) throws IOException;

	void send(final byte[] buf, final EndpointAddress address) throws IOException {
		final var looper = connections.get(address);
		if (looper != null)
			looper.send(buf);
	}

	void cleanup() {}

	@Override
	public void close() {
		connections.values().forEach(StreamLooper::close);
		final Thread t = thread;
		if (t != null)
			t.interrupt();
	}

	void lastSessionTimedOut(final EndpointAddress remote) {
		final StreamLooper looper = connections.get(remote);
		if (looper != null && !looper.ces.anyMatchDataConnection(remote))
			looper.close("last active secure session timed out");
	}

	void lastConnectionTimedOut(final EndpointAddress remote) {
		final StreamLooper looper = connections.get(remote);
		if (looper != null && !looper.ces.sessions.anyMatch(remote))
			looper.close("last active client connection timed out");
	}
}
