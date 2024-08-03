/*
    Calimero 2 - A library for KNX network access
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

import static java.net.StandardSocketOptions.TCP_NODELAY;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.time.Duration;

final class TcpEndpoint extends StreamEndpoint {
	TcpEndpoint(final ControlEndpointService ces, final InetSocketAddress endpoint, final boolean baos) {
		super(ces, new TcpEndpointAddress(endpoint), "tcp", baos);
	}

	@Override
	ServerSocketChannel open() throws IOException {
		final var ssc = ServerSocketChannel.open(StandardProtocolFamily.INET);
		ssc.bind(endpoint.address());
		return ssc;
	}

	@Override
	StreamLooper newLooper(final SocketChannel channel) throws IOException {
		return new Looper(ctrlEndpoint, channel);
	}



	final class Looper extends StreamLooper {
		private static final Duration inactiveConnectionTimeout = Duration.ofSeconds(10);

		Looper(final ControlEndpointService ces, final SocketChannel channel) throws IOException {
			super(ces, new TcpEndpointAddress((InetSocketAddress) channel.getRemoteAddress()), channel, baos);
			channel.setOption(TCP_NODELAY, true);
			if (!baos)
				channel.socket().setSoTimeout((int) inactiveConnectionTimeout.toMillis());
		}

		@Override
		void close(final String reason) {
			super.close(reason);
			connections.remove(this.endpoint);
		}
	}
}
