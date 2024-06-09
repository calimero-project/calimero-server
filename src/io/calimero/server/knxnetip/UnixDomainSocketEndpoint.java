/*
    Calimero 2 - A library for KNX network access
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

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;

import io.calimero.KnxRuntimeException;
import io.calimero.internal.Executor;

final class UnixDomainSocketEndpoint implements Runnable, AutoCloseable {
	private final ControlEndpointService ces;
	private final Path path;
	private final boolean baos;
	final ConcurrentHashMap<EndpointAddress, Looper> connections = new ConcurrentHashMap<>();

	private boolean running;


	UnixDomainSocketEndpoint(final ControlEndpointService ctrlEndpoint, final Path path, final boolean baos) {
		ces = ctrlEndpoint;
		this.path = path;
		this.baos = baos;
	}

	void start() throws InterruptedException {
		final Future<?> task = Executor.executor().submit(this::run);
		try {
			while (!task.isDone()) {
				synchronized (this) {
					if (running)
						return;
					wait();
				}
			}
		}
		catch (final InterruptedException e) {
			close();
			throw e;
		}
		throw new KnxRuntimeException("couldn't start unix domain socket service for " + ces.getServiceContainer().getName());
	}

	boolean send(final byte[] buf, final EndpointAddress addr) throws IOException {
		final var looper = connections.get(addr);
		if (looper == null)
			return false;

		looper.send(buf);
		return true;
	}

	public void run() {
		final String namePrefix = ces.getServiceContainer().getName() + (baos ? " baos" : "") + " unix domain socket ";
		final String name = namePrefix + "service";
		Thread.currentThread().setName(name);

		ServerSocketChannel localRef = null;
		try (var server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
			if (path.toString().isEmpty())
				server.bind(null);
			else {
				final var addr = UnixDomainSocketAddress.of(path);
				Files.deleteIfExists(path);
				server.bind(addr);
			}

			synchronized (this) {
				running = true;
				notifyAll();
			}
			localRef = server;
			ces.logger.log(INFO, "{0} ({1}) is up and running", name, server.getLocalAddress());

			while (true) {
				final SocketChannel conn = server.accept();
				final var looper = new Looper(ces, conn);
				Executor.execute(looper, namePrefix + "connection " + looper.endpoint);
			}
		}
		catch (final InterruptedIOException e) {
			ces.logger.log(INFO, "unix domain socket service {0} interrupted", path);
			Thread.currentThread().interrupt();
		}
		catch (final IOException e) {
			if (localRef == null || localRef.isOpen())
				ces.logger.log(ERROR, "socket error in unix domain socket service " + path, e);
		}
		finally {
			try {
				if (!path.toString().isEmpty())
					Files.deleteIfExists(path);
			}
			catch (final IOException e) {
				ces.logger.log(INFO, "error deleting unix domain socket path " + path, e);
			}
		}
	}

	@Override
	public void close() {
		connections.values().forEach(Looper::close);
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


	final class Looper extends StreamLooper {
		private final SocketChannel channel;


		private static UnixDomainSocketAddress remote(final SocketChannel channel) throws IOException {
			// remote UDS is usually unnamed, in that case, use local path of server channel
			var remote = (UnixDomainSocketAddress) channel.getRemoteAddress();
			if (remote.getPath().toString().isEmpty())
				remote = (UnixDomainSocketAddress) channel.getLocalAddress();
			return remote;
		}

		Looper(final ControlEndpointService ces, final SocketChannel channel) throws IOException {
			super(ces, new UnixEndpointAddress(remote(channel), channel.hashCode()), baos);
			this.channel = channel;
			connections.put(endpoint, this);
		}

		@Override
		boolean connected() { return channel.isConnected(); }

		@Override
		int read(final byte[] data, final int offset) throws IOException {
			return channel.read(ByteBuffer.wrap(data, offset, data.length - offset));
		}

		@Override
		void write(final byte[] data) throws IOException { channel.write(ByteBuffer.wrap(data)); }

		@Override
		void close(final String reason) {
			super.close(reason);
			try {
				channel.close();
			}
			catch (final IOException ignore) {}
			connections.remove(endpoint);
		}
	}
}
