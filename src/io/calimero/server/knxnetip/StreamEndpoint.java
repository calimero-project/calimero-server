/*
    Calimero 3 - A library for KNX network access
    Copyright (c) 2018, 2024 B. Malinowsky

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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;

import io.calimero.KnxRuntimeException;
import io.calimero.internal.Executor;

sealed abstract class StreamEndpoint implements Runnable, AutoCloseable
		permits TcpEndpoint, UnixDomainSocketEndpoint {

	final ConcurrentHashMap<EndpointAddress, StreamLooper> connections = new ConcurrentHashMap<>();
	final ControlEndpointService ctrlEndpoint;
	final EndpointAddress endpoint;
	final boolean baos;

	private final String name;
	private Thread thread;


	StreamEndpoint(final ControlEndpointService ces, final EndpointAddress endpoint, final String name, final boolean baos) {
		ctrlEndpoint = ces;
		this.endpoint = endpoint;
		this.name = name;
		this.baos = baos;
	}

	void start() throws InterruptedException {
		final Future<?> task = Executor.executor().submit(this);
		try {
			while (!task.isDone()) {
				synchronized (this) {
					if (thread != null)
						return;
					wait();
				}
			}
		}
		catch (final InterruptedException e) {
			close();
			throw e;
		}
		throw new KnxRuntimeException("couldn't start " + name + " service for " + ctrlEndpoint.getServiceContainer().getName());
	}

	public void run() {
		final String namePrefix = ctrlEndpoint.getServiceContainer().getName() + (baos ? " baos" : "") + " ";
		final String name = namePrefix + this.name + " service";
		Thread.currentThread().setName(name);

		try (var server = open()) {
			synchronized (this) {
				thread = Thread.currentThread();
				notifyAll();
			}
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
		catch (final ClosedByInterruptException e) {
			ctrlEndpoint.logger.log(Level.DEBUG, name + " {0} closed", endpoint);
		}
		catch (final IOException e) {
			ctrlEndpoint.logger.log(ERROR, "socket error in " + name + " " + endpoint, e);
		}
	}

	abstract ServerSocketChannel open() throws IOException;

	abstract StreamLooper newLooper(SocketChannel channel) throws IOException;

	void send(final byte[] buf, final EndpointAddress address) throws IOException {
		final var looper = connections.get(address);
		if (looper != null)
			looper.send(buf);
	}

	@Override
	public void close() {
		connections.values().forEach(StreamLooper::close);
		synchronized (this) {
			if (thread != null) thread.interrupt();
		}
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
