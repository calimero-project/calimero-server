/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2016, 2017 B. Malinowsky

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

import static tuwien.auto.calimero.device.ios.InterfaceObject.KNXNETIP_PARAMETER_OBJECT;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.device.ios.KNXPropertyException;
import tuwien.auto.calimero.knxnetip.Discoverer;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.knxnetip.servicetype.PacketHelper;
import tuwien.auto.calimero.knxnetip.servicetype.SearchRequest;
import tuwien.auto.calimero.knxnetip.servicetype.SearchResponse;
import tuwien.auto.calimero.knxnetip.util.DeviceDIB;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;

final class DiscoveryService extends ServiceLooper
{
	private static final InetAddress systemSetupMulticast = KNXnetIPServer.defRoutingMulticast;

	private final NetworkInterface[] outgoing;

	DiscoveryService(final KNXnetIPServer server, final NetworkInterface[] outgoing, final NetworkInterface[] joinOn)
	{
		super(server, null, 512, 0);
		this.outgoing = outgoing;
		s = createSocket(joinOn);
	}

	private MulticastSocket createSocket(final NetworkInterface[] joinOn)
	{
		final String p = System.getProperties().getProperty("java.net.preferIPv4Stack");
		logger.trace("network stack uses IPv4 addresses: " + (p == null ? "unknown" : p));
		final MulticastSocket s;
		try {
			s = new MulticastSocket(Discoverer.SEARCH_PORT);
		}
		catch (final IOException e) {
			logger.error("failed to create discovery socket for " + server.getName(), e);
			throw wrappedException(e);
		}

		// send out beyond local network
		try {
			s.setTimeToLive(64);
		}
		catch (final IOException ignore) {}

		// on Windows platforms, the IP_MULTICAST_LOOP option applies to the
		// datagram receive path, whereas on Unix platforms, it applies to
		// the send path; therefore, leave loopback enabled (as by default)
//			try {
//				s.setLoopbackMode(false);
//			}
//			catch (final SocketException ignore) {}

//			try {
//				if (outgoing != null)
//					s.setNetworkInterface(outgoing);
//			}
//			catch (final SocketException e) {
//				logger.error("setting outgoing network interface to " + outgoing.getName());
//				s.close();
//				throw e;
//			}
		try {
			joinOnInterfaces(s, joinOn);
		}
		catch (final IOException e) {
			s.close();
			throw wrappedException(e);
		}
		return s;
	}

	// supply null for joinOn to join on all found network interfaces
	private void joinOnInterfaces(final MulticastSocket s, final NetworkInterface[] joinOn) throws IOException
	{
		final SocketAddress group = new InetSocketAddress(systemSetupMulticast, 0);
		if (joinOn == null) {
			// We want to use the system-chosen network interface to send our join request.
			// If joinGroup is called with the interface omitted, the interface as returned by
			// getInterface() is used. If getInterface returns 0.0.0.0, join with interface
			// set to null (on OSX, joinGroup(InetAddress) will fail)
			if (s.getInterface().isAnyLocalAddress())
				s.joinGroup(group, null);
			else
				s.joinGroup(systemSetupMulticast);
			logger.info("KNXnet/IP discovery listens on interface with address " + s.getInterface());
			return;
		}
		final List<NetworkInterface> nifs = joinOn.length > 0 ? Arrays.asList(joinOn)
				: Collections.list(NetworkInterface.getNetworkInterfaces());
		final StringBuffer found = new StringBuffer();
		boolean joinedAny = false;
		// we try to bind to all requested interfaces. Only if that completely fails, we throw
		// the first caught exception
		IOException thrown = null;
		for (final Iterator<NetworkInterface> i = nifs.iterator(); i.hasNext();) {
			final NetworkInterface ni = i.next();
			final Enumeration<InetAddress> addrs = ni.getInetAddresses();
			if (!addrs.hasMoreElements()) {
				logger.warn("KNXnet/IP discovery join fails with no IP address bound to interface " + ni.getName());
				continue;
			}
			found.append(" ").append(ni.getName()).append(" [");
			while (addrs.hasMoreElements()) {
				final InetAddress addr = addrs.nextElement();
				if (addr instanceof Inet4Address) {
					found.append(addr.getHostAddress());
					try {
						s.joinGroup(group, ni);
						joinedAny = true;
						logger.info("KNXnet/IP discovery listens on interface " + ni.getName());
					}
					catch (final IOException e) {
						if (thrown == null)
							thrown = e;
						logger.error("KNXnet/IP discovery could not join on interface " + ni.getName(), e);
					}
					break;
				}
			}
			found.append("],");
		}
		logger.trace("found network interfaces" + found);
		if (!joinedAny)
			throw Objects.requireNonNull(thrown);
	}

	@Override
	boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset, final InetAddress src,
		final int port) throws KNXFormatException, IOException
	{
		final int svc = h.getServiceType();
		if (svc == KNXnetIPHeader.SEARCH_REQ) {
			// A request for TCP communication or a request using an unsupported
			// protocol version should result in a host protocol type error.
			// But since there is no status field in the search response,
			// we log and ignore such requests.

			if (!checkVersion(h))
				return true;
			final SearchRequest sr = new SearchRequest(data, offset);
			if (sr.getEndpoint().getHostProtocol() != HPAI.IPV4_UDP) {
				logger.warn("search requests have protocol support for UDP/IP only");
				return true;
			}

			// for discovery, we do not remember previous NAT decisions
			useNat = false;
			final SocketAddress addr = createResponseAddress(sr.getEndpoint(), src, port, 1);
			for (final Iterator<LooperThread> i = server.controlEndpoints.iterator(); i.hasNext();) {
				final LooperThread t = i.next();
				final ControlEndpointService ces = (ControlEndpointService) t.getLooper();
				final ServiceContainer sc = ces.getServiceContainer();
				if (sc.isActivated()) {
					// we create our own HPAI from the actual socket, since
					// the service container might have opted for ephemeral port use
					final InetSocketAddress local = (InetSocketAddress) ces.getSocket().getLocalSocketAddress();
					final HPAI hpai = new HPAI(sc.getControlEndpoint().getHostProtocol(), local);

					try {
						final NetworkInterface ni = NetworkInterface.getByInetAddress(local.getAddress());
						final byte[] mac = ni != null ? ni.getHardwareAddress() : null;
						server.getInterfaceObjectServer().setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(sc),
								PID.MAC_ADDRESS, 1, 1, mac == null ? new byte[6] : mac);
					}
					catch (final SocketException | KNXPropertyException e) {}

					final DeviceDIB device = server.createDeviceDIB(sc);
					final ServiceFamiliesDIB svcFamilies = server.createServiceFamiliesDIB(sc);
					final byte[] buf = PacketHelper.toPacket(new SearchResponse(hpai, device, svcFamilies));
					final DatagramPacket p = new DatagramPacket(buf, buf.length, addr);
					logger.trace("sending search response with container '" + sc.getName() + "' to " + addr);
					sendOnInterfaces(p);
					logger.info("KNXnet/IP discovery: identify ourself as '{}' to {}", device.getName(), addr);
				}
			}
			return true;
		}
		// we can safely ignore search responses and avoid a warning being logged
		else if (svc == KNXnetIPHeader.SEARCH_RES)
			return true;
		// also ignore routing messages
		else if (svc == KNXnetIPHeader.ROUTING_IND || svc == KNXnetIPHeader.ROUTING_LOST_MSG
				|| svc == KNXnetIPHeader.ROUTING_BUSY)
			return true;
		// other requests are rejected with error
		return false;
	}

	private void sendOnInterfaces(final DatagramPacket p) throws SocketException, IOException
	{
		if (!p.getAddress().isMulticastAddress() || outgoing == null) {
			s.send(p);
			return;
		}
		final List<NetworkInterface> nifs = outgoing.length > 0 ? Arrays.asList(outgoing)
				: Collections.list(NetworkInterface.getNetworkInterfaces());
		for (final NetworkInterface nif : nifs) {
			if (nif.getInetAddresses().hasMoreElements() && nif.isUp()) {
				try {
					((MulticastSocket) s).setNetworkInterface(nif);
					logger.trace("send search response on interface " + nameOf(nif));
					s.send(p);
				}
				catch (final SocketException e) {
					logger.info("failure sending on interface " + nameOf(nif));
				}
			}
		}
	}

	// some OS use a dedicated display name, others use the same as returned by getName, etc.
	private String nameOf(final NetworkInterface nif)
	{
		final String name = nif.getName();
		final String friendly = nif.getDisplayName();
		if (friendly != null & !name.equals(friendly))
			return name + " (" + friendly + ")";
		return name;
	}

	@Override
	public void quit()
	{
		try {
			((MulticastSocket) s).leaveGroup(new InetSocketAddress(systemSetupMulticast, 0), null);
		}
		catch (final IOException ignore) {}
		super.quit();
	}

	private int objectInstance(final ServiceContainer sc)
	{
		return server.objectInstance(sc);
	}
}
