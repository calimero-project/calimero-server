/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2016, 2024 B. Malinowsky

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

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.StringJoiner;

import io.calimero.KNXFormatException;
import io.calimero.device.ios.DeviceObject;
import io.calimero.knxnetip.Discoverer;
import io.calimero.knxnetip.KNXnetIPRouting;
import io.calimero.knxnetip.servicetype.KNXnetIPHeader;
import io.calimero.knxnetip.servicetype.SearchRequest;
import io.calimero.knxnetip.util.DIB;
import io.calimero.knxnetip.util.DeviceDIB;
import io.calimero.knxnetip.util.HPAI;
import io.calimero.knxnetip.util.Srp;
import io.calimero.knxnetip.util.Srp.Type;
import io.calimero.server.knxnetip.KNXnetIPServer.Endpoint;

final class DiscoveryService extends ServiceLooper
{
	private static final InetAddress systemSetupMulticast = KNXnetIPRouting.DefaultMulticast;

	private final NetworkInterface[] outgoing;
	private final ArrayList<String> joined = new ArrayList<>();

	DiscoveryService(final KNXnetIPServer server, final NetworkInterface[] outgoing, final NetworkInterface[] joinOn)
	{
		super(server, null, 512, 0);
		this.outgoing = outgoing;
		s = createSocket(joinOn);
	}

	private MulticastSocket createSocket(final NetworkInterface[] joinOn)
	{
		final String p = System.getProperties().getProperty("java.net.preferIPv4Stack");
		logger.log(TRACE, "network stack uses IPv4 addresses: " + (p == null ? "unknown" : p));
		final MulticastSocket s;
		try {
			s = new MulticastSocket(Discoverer.SEARCH_PORT);
		}
		catch (final IOException e) {
			throw wrappedException(e);
		}

		// send out beyond local network
		try {
			s.setTimeToLive(64);
		}
		catch (final IOException ignore) {}

		try {
			joinOnInterfaces(s, joinOn);
		}
		catch (final IOException e) {
			s.close();
			throw wrappedException(e);
		}
		return s;
	}

	private void joinOnInterfaces(final MulticastSocket s, final NetworkInterface[] joinOn) throws IOException
	{
		final SocketAddress group = new InetSocketAddress(systemSetupMulticast, 0);
		final List<NetworkInterface> nifs = joinOn.length > 0 ? Arrays.asList(joinOn)
				: Collections.list(NetworkInterface.getNetworkInterfaces());
		final var found = new StringJoiner(", ");
		boolean joinedAny = false;
		// we try to bind to all requested interfaces. Only if that completely fails, we throw
		// the first caught exception
		IOException thrown = null;
		for (final var ni : nifs) {
			final Enumeration<InetAddress> addrs = ni.getInetAddresses();
			if (!addrs.hasMoreElements()) {
				logger.log(WARNING, "KNXnet/IP discovery join fails with no IP address bound to interface " + ni.getName());
				continue;
			}
			var nifInfo = ni.getName();
			while (addrs.hasMoreElements()) {
				final InetAddress addr = addrs.nextElement();
				if (addr instanceof Inet4Address) {
					nifInfo += " [" + addr.getHostAddress() + "]";
					try {
						s.joinGroup(group, ni);
						joinedAny = true;
						joined.add(ni.getName());
					}
					catch (final IOException e) {
						if (thrown == null)
							thrown = e;
						logger.log(WARNING, "KNXnet/IP discovery could not join on interface " + ni.getName(), e);
					}
					break;
				}
			}
			found.add(nifInfo);
		}
		logger.log(TRACE, "found network interfaces {0}", found);
		if (!joinedAny)
			throw Objects.requireNonNull(thrown);
	}

	@Override
	boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset, final InetSocketAddress src)
			throws KNXFormatException, IOException {
		final int svc = h.getServiceType();
		if (svc == KNXnetIPHeader.SEARCH_REQ || svc == KNXnetIPHeader.SearchRequest) {
			// A request for TCP communication or a request using an unsupported
			// protocol version should result in a host protocol type error.
			// But since there is no status field in the search response, we log and ignore such requests.
			if (!checkVersion(h))
				return true;
			final SearchRequest sr = SearchRequest.from(h, data, offset);
			if (sr.getEndpoint().hostProtocol() != HPAI.IPV4_UDP) {
				logger.log(WARNING, "search requests to a discovery endpoint are only supported for UDP/IP");
				return true;
			}

			final boolean ext = svc == KNXnetIPHeader.SearchRequest;

			byte[] macFilter = {};
			byte[] requestedServices = {};
			byte[] requestedDibs = { DIB.DEVICE_INFO, ext ? DIB.AdditionalDeviceInfo : (byte) 0, DIB.SUPP_SVC_FAMILIES };
			for (final Srp srp : sr.searchParameters()) {
				final Type type = srp.type();
				if (type == Srp.Type.SelectByProgrammingMode) {
					if (!DeviceObject.lookup(server.getInterfaceObjectServer()).programmingMode())
						return true;
				}
				else if (type == Srp.Type.SelectByMacAddress)
					macFilter = srp.data();
				else if (type == Srp.Type.SelectByService)
					requestedServices = srp.data();
				else if (type == Srp.Type.RequestDibs)
					requestedDibs = srp.data();
				else  if (srp.isMandatory())
					return true;
			}

			// for discovery, we do not remember previous NAT decisions
			useNat = false;
			final var addr = createResponseAddress(sr.getEndpoint(), src, 1);
			final var list = server.endpoints.stream().map(Endpoint::controlEndpoint).flatMap(Optional::stream).toList();
			for (final ControlEndpointService ces : list)
				sendSearchResponse(addr, ces, ext, macFilter, requestedServices, requestedDibs);
			return true;
		}
		else if (ignoreServices.contains(svc))
			return true;
		else if (h.isSecure())
			return true;
		// other requests are rejected
		return false;
	}

	// known knx ip services which we receive but can safely ignore
	private static final Set<Integer> ignoreServices = Set.of(
			KNXnetIPHeader.ROUTING_IND,
			KNXnetIPHeader.ROUTING_LOST_MSG,
			KNXnetIPHeader.ROUTING_BUSY,
			KNXnetIPHeader.RoutingSystemBroadcast,
			KNXnetIPHeader.CONNECT_REQ,
			KNXnetIPHeader.DISCONNECT_REQ,
			KNXnetIPHeader.CONNECTIONSTATE_REQ);

	private void sendSearchResponse(final InetSocketAddress dst, final ControlEndpointService ces, final boolean ext,
			final byte[] macFilter, final byte[] requestedServices, final byte[] requestedDibs) throws IOException {
		final ServiceContainer sc = ces.getServiceContainer();
		if (sc.isActivated()) {
			final var res = ces.createSearchResponse(ext, macFilter, requestedServices, requestedDibs, 0);
			if (res.isPresent()) {
				final var buf = res.get();
				final var sentOn = send(new DatagramPacket(buf, buf.length, dst));
				final DeviceDIB deviceDib = server.createDeviceDIB(sc);
				logger.log(DEBUG, "KNXnet/IP discovery: identify as ''{0}'' for container {1} to {2} on {3}", deviceDib.getName(),
						sc.getName(), hostPort(dst), sentOn);
			}
		}
	}

	private List<String> send(final DatagramPacket p) throws IOException {
		if (!p.getAddress().isMulticastAddress() || outgoing == null) {
			s.send(p);
			return List.of("any");
		}
		final List<NetworkInterface> nifs = outgoing.length > 0 ? Arrays.asList(outgoing)
				: Collections.list(NetworkInterface.getNetworkInterfaces());
		return sendOnInterfaces(p, nifs);
	}

	private List<String> sendOnInterfaces(final DatagramPacket p, final List<NetworkInterface> nifs) throws IOException
	{
		final var sentOn = new ArrayList<String>();
		for (final NetworkInterface nif : nifs) {
			if (nif.getInetAddresses().hasMoreElements() && nif.isUp()) {
				try {
					((MulticastSocket) s).setNetworkInterface(nif);
					s.send(p);
					sentOn.add(nameOf(nif));
				}
				catch (final IOException e) {
					logger.log(INFO, "failure sending on interface {0}: {1}", nameOf(nif), e.getMessage());
				}
			}
		}
		return sentOn;
	}

	// some OS use a dedicated display name, others use the same as returned by getName, etc.
	private static String nameOf(final NetworkInterface nif)
	{
		final String name = nif.getName();
		final String friendly = nif.getDisplayName();
		if (friendly != null && !name.equals(friendly))
			return name + " (" + friendly + ")";
		return name;
	}

	@Override
	public void quit()
	{
		try {
			s.leaveGroup(new InetSocketAddress(systemSetupMulticast, 0), null);
		}
		catch (final IOException ignore) {}
		super.quit();
	}

	@Override
	public String toString() {
		return "discovery endpoint " + joined;
	}
}
