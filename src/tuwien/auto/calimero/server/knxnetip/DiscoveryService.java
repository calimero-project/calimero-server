/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2016, 2021 B. Malinowsky

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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.StringJoiner;
import java.util.TreeSet;
import java.util.stream.Collectors;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.device.ios.DeviceObject;
import tuwien.auto.calimero.knxnetip.Discoverer;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.knxnetip.servicetype.PacketHelper;
import tuwien.auto.calimero.knxnetip.servicetype.SearchRequest;
import tuwien.auto.calimero.knxnetip.servicetype.SearchResponse;
import tuwien.auto.calimero.knxnetip.util.DIB;
import tuwien.auto.calimero.knxnetip.util.DeviceDIB;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB;
import tuwien.auto.calimero.knxnetip.util.Srp;
import tuwien.auto.calimero.knxnetip.util.Srp.Type;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.server.knxnetip.KNXnetIPServer.Endpoint;

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
		final var joined = new ArrayList<String>();
		// we try to bind to all requested interfaces. Only if that completely fails, we throw
		// the first caught exception
		IOException thrown = null;
		for (final var ni : nifs) {
			final Enumeration<InetAddress> addrs = ni.getInetAddresses();
			if (!addrs.hasMoreElements()) {
				logger.warn("KNXnet/IP discovery join fails with no IP address bound to interface " + ni.getName());
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
						logger.warn("KNXnet/IP discovery could not join on interface " + ni.getName(), e);
					}
					break;
				}
			}
			found.add(nifInfo);
		}
		logger.trace("found network interfaces {}", found);
		if (!joinedAny)
			throw Objects.requireNonNull(thrown);
		logger.info("KNXnet/IP discovery listens on interfaces {}", joined);
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
			if (sr.getEndpoint().getHostProtocol() != HPAI.IPV4_UDP) {
				logger.warn("search requests to a discovery endpoint are only supported for UDP/IP");
				return true;
			}

			final boolean ext = svc == KNXnetIPHeader.SearchRequest;

			byte[] macFilter = {};
			byte[] requestedServices = {};
			byte[] requestedDibs = { DIB.DEVICE_INFO, ext ? DIB.AdditionalDeviceInfo : (byte) 0, DIB.SUPP_SVC_FAMILIES };
			for (final Srp srp : sr.searchParameters()) {
				final Type type = srp.getType();
				if (type == Srp.Type.SelectByProgrammingMode) {
					if (!DeviceObject.lookup(server.getInterfaceObjectServer()).programmingMode())
						return true;
				}
				else if (type == Srp.Type.SelectByMacAddress)
					macFilter = srp.getData();
				else if (type == Srp.Type.SelectByService)
					requestedServices = srp.getData();
				else if (type == Srp.Type.RequestDibs)
					requestedDibs = srp.getData();
				else  if (srp.isMandatory())
					return true;
			}

			// for discovery, we do not remember previous NAT decisions
			useNat = false;
			final SocketAddress addr = createResponseAddress(sr.getEndpoint(), src, 1);
			final var list = server.endpoints.stream().map(Endpoint::controlEndpoint).flatMap(Optional::stream)
					.collect(Collectors.toList());
			for (final ControlEndpointService ces : list)
				sendSearchResponse(addr, ces, ext, macFilter, requestedServices, requestedDibs);
			return true;
		}
		// we can safely ignore search responses and avoid a warning being logged
		else if (svc == KNXnetIPHeader.SEARCH_RES || svc == KNXnetIPHeader.SearchResponse)
			return true;
		// also ignore routing messages
		else if (svc == KNXnetIPHeader.ROUTING_IND || svc == KNXnetIPHeader.ROUTING_LOST_MSG || svc == KNXnetIPHeader.ROUTING_BUSY)
			return true;
		else if (svc == KNXnetIPHeader.RoutingSystemBroadcast)
			return true;
		else if (h.isSecure())
			return true;
		// other requests are rejected with error
		return false;
	}

	private void sendSearchResponse(final SocketAddress dst, final ControlEndpointService ces, final boolean ext,
		final byte[] macFilter, final byte[] requestedServices, final byte[] requestedDibs) throws IOException {
		final ServiceContainer sc = ces.getServiceContainer();
		if (sc.isActivated()) {
			// we create our own HPAI from the actual socket, since
			// the service container might have opted for ephemeral port use
			// it can happen that our socket got closed and we get null
			final InetSocketAddress local = (InetSocketAddress) ces.getSocket().getLocalSocketAddress();
			if (local == null) {
				logger.warn("KNXnet/IP discovery unable to announce container '{}', problem with local endpoint: "
						+ "socket bound={}, closed={}", sc.getName(), ces.getSocket().isBound(), ces.getSocket().isClosed());
				return;
			}

			// skip response if we have a mac filter set which does not match our mac
			final byte[] mac = server.getProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(sc), PID.MAC_ADDRESS,
					new byte[6]);
			if (macFilter.length > 0 && !Arrays.equals(macFilter, mac))
				return;

			if (requestedServices.length > 0) {
				final ServiceFamiliesDIB families = server.createServiceFamiliesDIB(sc, ext);
				// skip response if we have a service request which we don't support
				for (int i = 0; i < requestedServices.length; i++) {
					final int familyId = requestedServices[i] & 0xff;
					final int version = requestedServices[i + 1] & 0xff;
					if (families.families().getOrDefault(familyId, 0) < version)
						return;
				}
			}

			final Set<Integer> set = new TreeSet<>();
			for (final byte dibType : requestedDibs)
				set.add(dibType & 0xff);
			final List<DIB> dibs = new ArrayList<>();
			set.forEach(dibType -> ces.createDib(dibType, dibs, ext));

			final HPAI hpai = new HPAI(HPAI.IPV4_UDP, local);
			final byte[] buf = PacketHelper.toPacket(new SearchResponse(ext, hpai, dibs));
			final DatagramPacket p = new DatagramPacket(buf, buf.length, dst);
			logger.trace("sending search response with container '" + sc.getName() + "' to " + dst);
			sendOnInterfaces(p);
			final DeviceDIB deviceDib = server.createDeviceDIB(sc);
			logger.debug("KNXnet/IP discovery: identify as '{}' to {}", deviceDib.getName(), dst);
		}
	}

	private void sendOnInterfaces(final DatagramPacket p) throws IOException
	{
		if (!p.getAddress().isMulticastAddress() || outgoing == null) {
			s.send(p);
			return;
		}
		final List<NetworkInterface> nifs = outgoing.length > 0 ? Arrays.asList(outgoing)
				: Collections.list(NetworkInterface.getNetworkInterfaces());
		final var sentOn = new ArrayList<String>();
		for (final NetworkInterface nif : nifs) {
			if (nif.getInetAddresses().hasMoreElements() && nif.isUp()) {
				try {
					((MulticastSocket) s).setNetworkInterface(nif);
					s.send(p);
					sentOn.add(nameOf(nif));
				}
				catch (final SocketException e) {
					logger.info("failure sending on interface " + nameOf(nif));
				}
			}
		}
		logger.trace("sent search response on interfaces {}", sentOn);
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
