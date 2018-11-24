/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2016, 2018 B. Malinowsky

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
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import tuwien.auto.calimero.DeviceDescriptor.DD0;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.KnxPropertyException;
import tuwien.auto.calimero.knxnetip.Discoverer;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.knxnetip.servicetype.PacketHelper;
import tuwien.auto.calimero.knxnetip.servicetype.SearchRequest;
import tuwien.auto.calimero.knxnetip.servicetype.SearchResponse;
import tuwien.auto.calimero.knxnetip.util.AdditionalDeviceDib;
import tuwien.auto.calimero.knxnetip.util.DIB;
import tuwien.auto.calimero.knxnetip.util.DeviceDIB;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB;
import tuwien.auto.calimero.knxnetip.util.TunnelingDib;
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
		final StringBuilder found = new StringBuilder();
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
		if (svc == KNXnetIPHeader.SEARCH_REQ || svc == KNXnetIPHeader.SearchRequest) {
			// A request for TCP communication or a request using an unsupported
			// protocol version should result in a host protocol type error.
			// But since there is no status field in the search response,
			// we log and ignore such requests.
			if (!checkVersion(h))
				return true;
			final SearchRequest sr = SearchRequest.from(h, data, offset);
			if (sr.getEndpoint().getHostProtocol() != HPAI.IPV4_UDP) {
				logger.warn("search requests have protocol support for UDP/IP only");
				return true;
			}

			// for discovery, we do not remember previous NAT decisions
			useNat = false;
			final SocketAddress addr = createResponseAddress(sr.getEndpoint(), src, port, 1);
			for (final LooperThread t : server.controlEndpoints) {
				final Optional<ControlEndpointService> looper = t.looper().map(ControlEndpointService.class::cast);
				if (looper.isPresent())
					sendSearchResponse(addr, looper.get(), sr.requestedDibs());
			}
			return true;
		}
		// we can safely ignore search responses and avoid a warning being logged
		else if (svc == KNXnetIPHeader.SEARCH_RES || svc == KNXnetIPHeader.SearchResponse)
			return true;
		// also ignore routing messages
		else if (svc == KNXnetIPHeader.ROUTING_IND || svc == KNXnetIPHeader.ROUTING_LOST_MSG || svc == KNXnetIPHeader.ROUTING_BUSY)
			return true;
		else if (h.isSecure())
			return true;
		// other requests are rejected with error
		return false;
	}

	private void sendSearchResponse(final SocketAddress dst, final ControlEndpointService ces, final List<Integer> dibCodes)
		throws IOException {
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

			final HPAI hpai = new HPAI(sc.getControlEndpoint().getHostProtocol(), local);
			try {
				final NetworkInterface ni = NetworkInterface.getByInetAddress(local.getAddress());
				final byte[] mac = ni != null ? ni.getHardwareAddress() : null;
				server.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(sc), PID.MAC_ADDRESS, mac == null ? new byte[6] : mac);
			}
			catch (SocketException | KnxPropertyException e) {}

			final List<DIB> dibs = new ArrayList<>();
			final DeviceDIB deviceDib = server.createDeviceDIB(sc);
			if (dibCodes.isEmpty() || dibCodes.contains(DIB.DEVICE_INFO))
				dibs.add(deviceDib);
			if (dibCodes.isEmpty() || dibCodes.contains(DIB.SUPP_SVC_FAMILIES))
				dibs.add(server.createServiceFamiliesDIB(sc));
			if (dibCodes.contains(DIB.AdditionalDeviceInfo))
				dibs.add(createAdditionalDeviceDib(sc));
			if (dibCodes.contains(DIB.SecureServiceFamilies))
				dibs.add(createSecureServiceFamiliesDib(sc));
			if (dibCodes.contains(DIB.Tunneling))
				dibs.add(createTunnelingDib(ces));

			final byte[] buf = PacketHelper.toPacket(new SearchResponse(dibCodes.size() > 0, hpai, dibs));
			final DatagramPacket p = new DatagramPacket(buf, buf.length, dst);
			logger.trace("sending search response with container '" + sc.getName() + "' to " + dst);
			sendOnInterfaces(p);
			logger.debug("KNXnet/IP discovery: identify as '{}' to {}", deviceDib.getName(), dst);
		}
	}

	private ServiceFamiliesDIB createSecureServiceFamiliesDib(final ServiceContainer sc) {
		final int caps = server.getProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(sc), SecureSession.pidSecuredServices, 1, 0);
		// service family 'core' is skipped here since not used in capabilities bitset
		final int[] services = new int[] { ServiceFamiliesDIB.DEVICE_MANAGEMENT, ServiceFamiliesDIB.TUNNELING,
			ServiceFamiliesDIB.ROUTING, ServiceFamiliesDIB.REMOTE_LOGGING, ServiceFamiliesDIB.REMOTE_CONFIGURATION_DIAGNOSIS,
			ServiceFamiliesDIB.OBJECT_SERVER };

		final int[] tmp = new int[services.length];
		int count = 0;
		for (int i = 0; i < services.length; ++i)
			if ((caps >> i & 0x1) == 1)
				tmp[count++] = services[i];

		final int[] supported = Arrays.copyOfRange(tmp, 0, count);
		final int[] versions = new int[count];
		Arrays.fill(versions, 1);
		return ServiceFamiliesDIB.newSecureServiceFamilies(supported, versions);
	}

	private TunnelingDib createTunnelingDib(final ControlEndpointService ces) {
		final List<IndividualAddress> addresses = additionalAddresses(ces.getServiceContainer());
		final int[] status = new int[addresses.size()];

		for (int i = 0; i < addresses.size(); i++) {
			final IndividualAddress addr = addresses.get(i);
			final boolean inuse = ces.addressInUse(addr);
			status[i] = 4 | (inuse ? 0 : 1);
		}
		final int maxApduLength = ces.getServiceContainer().getMediumSettings().maxApduLength();
		return new TunnelingDib((short) maxApduLength, addresses, status);
	}

	private List<IndividualAddress> additionalAddresses(final ServiceContainer sc) {
		final int oi = objectInstance(sc);
		final int elems = server.getPropertyElems(KNXNETIP_PARAMETER_OBJECT, oi, PID.ADDITIONAL_INDIVIDUAL_ADDRESSES);
		final List<IndividualAddress> list = new ArrayList<>();
		try {
			final byte[] data = server.getInterfaceObjectServer().getProperty(KNXNETIP_PARAMETER_OBJECT, oi,
					PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 1, elems);
			final ByteBuffer buf = ByteBuffer.wrap(data);
			for (int i = 0; i < elems; ++i)
				list.add(new IndividualAddress(buf.getShort() & 0xffff));
		}
		catch (final KnxPropertyException e) {
			logger.warn(e.getMessage());
		}
		return list;
	}

	private AdditionalDeviceDib createAdditionalDeviceDib(final ServiceContainer sc) {
		final int oi = objectInstance(sc);
		final int status = server.getProperty(InterfaceObject.ROUTER_OBJECT,  oi, PID.MEDIUM_STATUS, 1, 0);
		return new AdditionalDeviceDib(status, sc.getMediumSettings().maxApduLength(), DD0.TYPE_091A);
	}

	private void sendOnInterfaces(final DatagramPacket p) throws IOException
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
