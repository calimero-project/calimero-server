/*
    Calimero 3 - A library for KNX network access
    Copyright (c) 2024, 2025 B. Malinowsky

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

import static java.lang.System.Logger.Level.INFO;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;

final class UnixDomainSocketEndpoint extends StreamEndpoint {
	UnixDomainSocketEndpoint(final ControlEndpointService ctrlEndpoint, final Path path, final boolean baos) {
		super(ctrlEndpoint, new UnixEndpointAddress(UnixDomainSocketAddress.of(path), 0), "unix socket", baos);
	}

	@Override
	ServerSocketChannel open() throws IOException {
		final var ssc = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
		final var path = ((UnixDomainSocketAddress) endpoint.address()).getPath();
		if (path.toString().isEmpty())
			ssc.bind(null);
		else {
			Files.deleteIfExists(path);
			path.toFile().deleteOnExit();
			ssc.bind(endpoint.address());
		}
		return ssc;
	}

	@Override
	StreamLooper newLooper(final SocketChannel channel) throws IOException {
		return new Looper(ctrlEndpoint, channel);
	}

	@Override
	void cleanup()  {
		final var path = ((UnixDomainSocketAddress) endpoint.address()).getPath();
		if (!path.toString().isEmpty()) try {
			Files.deleteIfExists(path);
		} catch (final IOException e) {
			ctrlEndpoint.logger.log(INFO, "error deleting unix socket path " + path, e);
		}
	}


	final class Looper extends StreamLooper {
		Looper(final ControlEndpointService ces, final SocketChannel channel) throws IOException {
			super(ces, new UnixEndpointAddress(remote(channel), channel.hashCode()), channel, baos);
		}

		@Override
		void close(final String reason) {
			super.close(reason);
			connections.remove(this.endpoint);
		}

		private static UnixDomainSocketAddress remote(final SocketChannel channel) throws IOException {
			// remote UDS is usually unnamed, in that case, use local path of server channel
			final var remote = (UnixDomainSocketAddress) channel.getRemoteAddress();
			if (remote.getPath().toString().isEmpty())
				return (UnixDomainSocketAddress) channel.getLocalAddress();
			return remote;
		}
	}
}
