/*
    Calimero 3 - A library for KNX network access
    Copyright (c) 2026 B. Malinowsky

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

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.net.StandardSocketOptions;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.List;

import io.calimero.IndividualAddress;
import io.calimero.KNXFormatException;
import io.calimero.knxnetip.Discoverer;
import io.calimero.knxnetip.KNXnetIPRouting;
import io.calimero.knxnetip.servicetype.PacketHelper;
import io.calimero.knxnetip.servicetype.SearchRequest;
import io.calimero.knxnetip.util.DeviceDIB;
import io.calimero.link.medium.KNXMediumSettings;
import io.calimero.server.ServerConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class KnxipHeaderTest {
	private KNXnetIPServer server;

	@BeforeEach
	void init() throws InterruptedException {
		final var config = new ServerConfiguration("test", "KNXnetIPHeaderTest", true, List.of(), List.of(), List.of());
		server = new KNXnetIPServer(config);
		final ServiceContainer sc = new DefaultServiceContainer("test container", "any", 5647,
				KNXMediumSettings.create(DeviceDIB.MEDIUM_TP1, new IndividualAddress(1, 1, 1)), false, true, false,
				false);
		server.addServiceContainer(sc);
		server.launch();
		Thread.sleep(1_000);
	}

	@AfterEach
	void tearDown() {
		server.shutdown();
	}

	@Test
	void rejectInvalidKnxipHeaders() throws IOException, KNXFormatException, InterruptedException {
		final var res = new InetSocketAddress(anyLocalIPv4Address, 0);
		final var group = new InetSocketAddress(KNXnetIPRouting.DefaultMulticast, Discoverer.SEARCH_PORT);

		try (final var ch = newChannel(null)) {
			// Byte offsets in KNXnet/IP header layout:
			// +---------+--------+-------------+------------+
			// |   0     |   1    |   2     3   |   4    5   |
			// +---------+--------+-------------+------------+
			// | Hdr Size| Version| Service ID  | Total Size |
			// +---------+--------+-------------+------------+
			for (int offset = 0; offset < 6; offset++) {
				final byte[] req = PacketHelper.toPacket(new SearchRequest(res));
				for (int b = 0; b <= 0xff; b++) {
					req[offset] = (byte) b;
					ch.send(ByteBuffer.wrap(req), group);
				}
				Thread.sleep(500);
			}
		}
		Thread.sleep(2_000);
	}

	private static DatagramChannel newChannel(final InetSocketAddress bind) throws IOException {
		return (DatagramChannel) DatagramChannel.open(StandardProtocolFamily.INET)
				.setOption(StandardSocketOptions.SO_REUSEADDR, true)
				.bind(bind)
				.setOption(StandardSocketOptions.IP_MULTICAST_TTL, 64)
				.configureBlocking(false);
	}

	private static final InetAddress anyLocalIPv4Address;
	static {
		try {
			anyLocalIPv4Address = InetAddress.getByAddress(new byte[4]);
		}
		catch (UnknownHostException e) {
			throw new InternalError(e);
		}
	}
}
