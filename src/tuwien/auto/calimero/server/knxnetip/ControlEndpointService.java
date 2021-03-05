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

import static java.util.function.Predicate.not;
import static java.util.stream.Collectors.toList;
import static tuwien.auto.calimero.device.ios.InterfaceObject.KNXNETIP_PARAMETER_OBJECT;
import static tuwien.auto.calimero.knxnetip.KNXnetIPDevMgmt.DEVICE_MGMT_CONNECTION;
import static tuwien.auto.calimero.knxnetip.KNXnetIPTunnel.TUNNEL_CONNECTION;
import static tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB.ServiceFamily.DeviceManagement;
import static tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB.ServiceFamily.Tunneling;

import java.io.Closeable;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DeviceDescriptor.DD0;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.device.ios.DeviceObject;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KnxPropertyException;
import tuwien.auto.calimero.knxnetip.KNXnetIPConnection;
import tuwien.auto.calimero.knxnetip.KNXnetIPTunnel;
import tuwien.auto.calimero.knxnetip.KNXnetIPTunnel.TunnelingLayer;
import tuwien.auto.calimero.knxnetip.servicetype.ConnectRequest;
import tuwien.auto.calimero.knxnetip.servicetype.ConnectResponse;
import tuwien.auto.calimero.knxnetip.servicetype.ConnectionstateRequest;
import tuwien.auto.calimero.knxnetip.servicetype.ConnectionstateResponse;
import tuwien.auto.calimero.knxnetip.servicetype.DescriptionRequest;
import tuwien.auto.calimero.knxnetip.servicetype.DescriptionResponse;
import tuwien.auto.calimero.knxnetip.servicetype.DisconnectRequest;
import tuwien.auto.calimero.knxnetip.servicetype.DisconnectResponse;
import tuwien.auto.calimero.knxnetip.servicetype.ErrorCodes;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.knxnetip.servicetype.PacketHelper;
import tuwien.auto.calimero.knxnetip.servicetype.SearchRequest;
import tuwien.auto.calimero.knxnetip.servicetype.SearchResponse;
import tuwien.auto.calimero.knxnetip.util.AdditionalDeviceDib;
import tuwien.auto.calimero.knxnetip.util.CRD;
import tuwien.auto.calimero.knxnetip.util.DIB;
import tuwien.auto.calimero.knxnetip.util.DeviceDIB;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.knxnetip.util.KnxAddressesDIB;
import tuwien.auto.calimero.knxnetip.util.ManufacturerDIB;
import tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB;
import tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB.ServiceFamily;
import tuwien.auto.calimero.knxnetip.util.Srp;
import tuwien.auto.calimero.knxnetip.util.Srp.Type;
import tuwien.auto.calimero.knxnetip.util.TunnelCRD;
import tuwien.auto.calimero.knxnetip.util.TunnelCRI;
import tuwien.auto.calimero.knxnetip.util.TunnelingDib;
import tuwien.auto.calimero.log.LogService.LogLevel;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.server.knxnetip.SecureSession.Session;

final class ControlEndpointService extends ServiceLooper
{
	// Connect response error codes
	private static final int NoMoreUniqueConnections = 0x25;
	private static final int AuthError = 0x28; // client is not authorized to use the requested individual address
	private static final int NoTunnelingAddress = 0x2d; // address requested in the extended CRI is not a tunneling address
	private static final int ConnectionInUse = 0x2e; // requested individual address for this connection is in use


	private final ServiceContainer svcCont;

	// channel -> data endpoint
	private final Map<Integer, DataEndpoint> connections = new ConcurrentHashMap<>();

	private final List<IndividualAddress> usedKnxAddresses = new ArrayList<>();
	// If the server assigns its own KNX individual address to a connection, no
	// management (using tunneling or from the KNX subnet) shall be allowed.
	// This flag maintains the current state, access is synchronized on
	// the variable usedKnxAddresses.
	private int activeMgmtConnections;

	// overall maximum allowed is 0xff
	private static final int MAX_CHANNEL_ID = 255;
	private int lastChannelId;

	final SecureSession sessions;
	private boolean secureSvcInProgress;

	private final Closeable tcpLooper;

	ControlEndpointService(final KNXnetIPServer server, final ServiceContainer sc)
	{
		super(server, null, 512, 10000);
		svcCont = sc;
		s = createSocket();
		sessions = new SecureSession(this);

		final InetAddress addr = s.getLocalAddress();
		server.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(), PID.CURRENT_IP_ADDRESS, addr.getAddress());
		server.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(), PID.CURRENT_SUBNET_MASK, subnetMaskOf(addr));
		server.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(), PID.MAC_ADDRESS, macAddress(addr));

		final boolean secureMgmt = isSecuredService(DeviceManagement);
		final boolean secureTunneling = isSecuredService(Tunneling);
		final String mgmt = secureMgmt ? "required" : "optional";
		final String tunneling = secureTunneling ? "required" : "optional";
		logger.info("{} secure mgmt/tunneling connections: {}/{}", sc.getName(), mgmt, tunneling);

		try {
			tcpLooper = TcpLooper.start(this, (InetSocketAddress) s.getLocalSocketAddress());
		}
		catch (final Exception e) {
			if (e instanceof InterruptedException)
				Thread.currentThread().interrupt();
			s.close();
			throw wrappedException(e);
		}
	}

	void connectionClosed(final DataEndpoint endpoint, final IndividualAddress device)
	{
		connections.remove(endpoint.getChannelId());
		// free knx address and channel id we assigned to the connection
		freeDeviceAddress(device);

		if (endpoint.isDeviceMgmt())
			synchronized (usedKnxAddresses) {
				--activeMgmtConnections;
			}

		final long now = System.currentTimeMillis();
		final boolean timeout = (now - endpoint.getLastMsgTimestamp()) >= 120_000;
		if (timeout && !anyMatchDataConnection(endpoint.getRemoteAddress())) {
			TcpLooper.lastConnectionTimedOut(endpoint.getRemoteAddress());
		}
	}

	void resetRequest(final DataEndpoint endpoint)
	{
		final InetSocketAddress ctrlEndpoint = null;
		fireResetRequest(endpoint.getName(), ctrlEndpoint);
	}

	@Override
	public void quit() {
		closeDataConnections();
		try {
			tcpLooper.close();
		}
		catch (final IOException ignore) {}
		super.quit();
	}

	public String toString() {
		final var local = (InetSocketAddress) s.getLocalSocketAddress();
		String bound = "";
		if (local == null)
			bound = "closed";
		else {
			try {
				final NetworkInterface netif = NetworkInterface.getByInetAddress(local.getAddress());
				if (netif != null)
					bound = netif.getName() + " ";
			}
			catch (final SocketException ignore) {}
			bound += hostPort(local);
		}
		return svcCont.getName() + " control endpoint (" + bound + ")";
	}

	@Override
	protected void onTimeout()
	{
		try {
			final InetAddress ip = Optional.ofNullable(((InetSocketAddress) s.getLocalSocketAddress()))
					.map(InetSocketAddress::getAddress).orElse(InetAddress.getByAddress(new byte[4]));
			final List<InetAddress> addresses = usableIpAddresses().collect(toList());
			if (!addresses.contains(ip)) {
				logger.warn("{} control endpoint: interface {} updated its IP address from {} to {}",
						svcCont.getName(), svcCont.networkInterface(), ip.getHostAddress(), addresses);
				quit();
			}
		}
		catch (final IOException e) {}
		sessions.closeDormantSessions();
	}

	ServiceContainer getServiceContainer()
	{
		return svcCont;
	}

	Map<Integer, DataEndpoint> connections() {
		return connections;
	}

	@Override
	boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset, final InetSocketAddress src)
			throws KNXFormatException, IOException {
		if (h.isSecure()) {
			try {
				secureSvcInProgress = true;
				return sessions.acceptService(h, data, offset, src, this);
			}
			finally {
				secureSvcInProgress = false;
			}
		}
		else if (h.getServiceType() == KNXnetIPHeader.CONNECT_REQ) {
			final ConnectRequest req = new ConnectRequest(data, offset);
			final var connType = req.getCRI().getConnectionType();

			final boolean tunneling = connType == TUNNEL_CONNECTION;
			final boolean devmgmt = connType == DEVICE_MGMT_CONNECTION;
			final var typeString = tunneling ? "tunneling" : devmgmt ? "device management" : "0x" + connType;

			if (tunneling && isSecuredService(Tunneling) || devmgmt && isSecuredService(DeviceManagement)) {
				logger.warn("reject {}, secure services required for {}", h, typeString);
				final InetSocketAddress ctrlEndpt = createResponseAddress(req.getControlEndpoint(), src, 1);
				final byte[] buf = PacketHelper
						.toPacket(errorResponse(ErrorCodes.CONNECTION_TYPE, ctrlEndpt.toString()));
				s.send(new DatagramPacket(buf, buf.length, ctrlEndpt));
			}
			else
				return acceptControlService(0, h, data, offset, src);
		}
		else
			return acceptControlService(0, h, data, offset, src);
		return true;
	}

	boolean acceptControlService(final int sessionId, final KNXnetIPHeader h, final byte[] data, final int offset,
			final InetSocketAddress src) throws KNXFormatException, IOException {
		final int svc = h.getServiceType();
		if (svc == KNXnetIPHeader.SearchRequest) {
			// extended unicast search request to this control endpoint
			if (!checkVersion(h))
				return true;

			final SearchRequest sr = SearchRequest.from(h, data, offset);
			byte[] macFilter = {};
			byte[] requestedServices = {};
			byte[] requestedDibs = { DIB.DEVICE_INFO, DIB.AdditionalDeviceInfo, DIB.SUPP_SVC_FAMILIES };
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

			final InetSocketAddress addr = createResponseAddress(sr.getEndpoint(), src, 1);
			sendSearchResponse(sessionId, addr, macFilter, requestedServices, requestedDibs);
		}
		else if (svc == KNXnetIPHeader.DESCRIPTION_REQ) {
			if (!checkVersion(h))
				return true;
			final DescriptionRequest dr = new DescriptionRequest(data, offset);
			final DeviceDIB device = server.createDeviceDIB(svcCont);
			final ServiceFamiliesDIB svcFamilies = server.createServiceFamiliesDIB(svcCont, false);
			final ManufacturerDIB mfr = createManufacturerDIB();
			final List<IndividualAddress> addresses = additionalAddresses();
			final DescriptionResponse description = addresses.isEmpty()
					? new DescriptionResponse(device, svcFamilies, mfr)
					: new DescriptionResponse(device, svcFamilies, new KnxAddressesDIB(addresses), mfr);

			final InetSocketAddress responseAddress = createResponseAddress(dr.getEndpoint(), src, 1);
			final byte[] buf = PacketHelper.toPacket(description);
			logger.info("send KNXnet/IP description to {}: {}", responseAddress, description);
			send(sessionId, 0, buf, responseAddress);
		}
		else if (svc == KNXnetIPHeader.CONNECT_REQ) {
			useNat = false;
			final ConnectRequest req = new ConnectRequest(data, offset);
			int status = ErrorCodes.NO_ERROR;

			if (!checkVersion(h))
				status = ErrorCodes.VERSION_NOT_SUPPORTED;

			final HPAI controlEndpoint = req.getControlEndpoint();
			final boolean tcp = controlEndpoint.getHostProtocol() == HPAI.IPV4_TCP;
			if (tcp) {
				final var ctrlRouteBack = controlEndpoint.isRouteBack();
				final HPAI dataEndpoint = req.getDataEndpoint();
				final var dataRouteBack = dataEndpoint.isRouteBack();
				if (!ctrlRouteBack || !dataRouteBack) {
					logger.info("connect request from {} does not contain route-back {} endpoint, ignore", hostPort(src),
							ctrlRouteBack ? "data" : "control");
					return true;
				}
			}
			final InetSocketAddress ctrlEndpt = createResponseAddress(controlEndpoint, src, 1);
			byte[] buf = null;
			boolean established = false;

			final int channelId = assignChannelId();
			if (status == ErrorCodes.NO_ERROR) {
				if (channelId == 0)
					status = ErrorCodes.NO_MORE_CONNECTIONS;
				else {
					logger.info("{}: setup data endpoint (channel {}) for connection request from {} ({})",
							svcCont.getName(), channelId, ctrlEndpt, tcp ? "tcp" : "udp");
					final InetSocketAddress dataEndpt = createResponseAddress(req.getDataEndpoint(), src, 2);
					final ConnectResponse res = initNewConnection(req, ctrlEndpt, dataEndpt, channelId);
					buf = PacketHelper.toPacket(res);
					established = res.getStatus() == ErrorCodes.NO_ERROR;
				}
			}
			if (buf == null)
				buf = PacketHelper.toPacket(errorResponse(status, ctrlEndpt.toString()));

			send(sessionId, channelId, buf, ctrlEndpt);
			if (established)
				connectionEstablished(svcCont, connections.get(channelId));
		}
		else if (svc == KNXnetIPHeader.CONNECT_RES)
			logger.warn("received connect response - ignored");
		else if (svc == KNXnetIPHeader.DISCONNECT_REQ) {
			final DisconnectRequest dr = new DisconnectRequest(data, offset);
			// find connection based on channel id
			final int channelId = dr.getChannelID();
			final DataEndpoint conn = connections.get(channelId);

			// requests with wrong channel ID are ignored (conforming to spec)
			if (conn == null) {
				logger.warn("received disconnect request with unknown channel id " + dr.getChannelID() + " - ignored");
				return true;
			}

			// According to specification, a control endpoint is allowed to change
			// during an established connection, but it's not recommended; if the
			// sender control endpoint differs from our connection control endpoint,
			// issue a warning
			final InetSocketAddress ctrlEndpt = conn.getRemoteAddress();
			if (!ctrlEndpt.equals(src)) {
				logger.warn("disconnect request: sender control endpoint changed from " + ctrlEndpt + " to " + src
						+ ", not recommended");
			}

			conn.updateLastMsgTimestamp();

			final byte[] buf = PacketHelper.toPacket(new DisconnectResponse(channelId, ErrorCodes.NO_ERROR));
			try {
				send(sessionId, channelId, buf, ctrlEndpt);
			}
			catch (final IOException e) {
				logger.error("communication failure", e);
			}
			finally {
				conn.cleanup(CloseEvent.CLIENT_REQUEST, "client request", LogLevel.DEBUG, null);
			}
		}
		else if (svc == KNXnetIPHeader.DISCONNECT_RES) {
			final DisconnectResponse res = new DisconnectResponse(data, offset);
			if (res.getStatus() != ErrorCodes.NO_ERROR)
				logger.warn("received disconnect response status 0x" + Integer.toHexString(res.getStatus()) + " ("
						+ ErrorCodes.getErrorMessage(res.getStatus()) + ")");
			// finalize closing
		}
		else if (svc == KNXnetIPHeader.CONNECTIONSTATE_REQ) {
			final ConnectionstateRequest csr = new ConnectionstateRequest(data, offset);
			int status = checkVersion(h) ? ErrorCodes.NO_ERROR : ErrorCodes.VERSION_NOT_SUPPORTED;

			if (status == ErrorCodes.NO_ERROR) {
				final var endpoint = connections.get(csr.getChannelID());
				if (endpoint == null)
					status = ErrorCodes.CONNECTION_ID;
				else {
					logger.trace("received connection state request from {} for channel {}", endpoint.getRemoteAddress(),
							csr.getChannelID());
					endpoint.updateLastMsgTimestamp();
				}
			}

			if (status == ErrorCodes.NO_ERROR)
				status = subnetStatus();
			else
				logger.warn("received invalid connection state request for channel {}: {}", csr.getChannelID(),
						ErrorCodes.getErrorMessage(status));

			final byte[] buf = PacketHelper.toPacket(new ConnectionstateResponse(csr.getChannelID(), status));
			send(sessionId, csr.getChannelID(), buf, createResponseAddress(csr.getControlEndpoint(), src, 0));
		}
		else if (svc == KNXnetIPHeader.CONNECTIONSTATE_RES)
			logger.warn("received connection state response - ignored");
		else {
			DataEndpoint endpoint = null;
			try {
				// to get the channel id, we are just interested in connection header
				// which has the same layout for request and ack
				final int channelId = PacketHelper.getEmptyServiceRequest(h, data, offset).getChannelID();
				endpoint = connections.get(channelId);
			}
			catch (final KNXFormatException e) {}
			if (endpoint != null)
				return endpoint.handleDataServiceType(h, data, offset);
			return false;
		}
		return true;
	}

	int subnetStatus() {
		final int status = server.getProperty(InterfaceObject.ROUTER_OBJECT, objectInstance(), PID.MEDIUM_STATUS, 1, 0);
		return status == 0 ? ErrorCodes.NO_ERROR : ErrorCodes.KNX_CONNECTION;
	}

	void mediumConnectionStatusChanged(final boolean active) {
		connections.values().forEach(c -> c.mediumConnectionStatusChanged(active));
	}

	private void closeDataConnections() {
		for (final DataEndpoint endpoint : connections.values())
			endpoint.close(CloseEvent.SERVER_REQUEST, "quit service container " + svcCont.getName(), LogLevel.INFO, null);
	}

	private void sendSearchResponse(final int sessionId, final InetSocketAddress dst, final byte[] macFilter,
			final byte[] requestedServices, final byte[] requestedDibs) throws IOException {
		final var res = createSearchResponse(true, macFilter, requestedServices, requestedDibs);
		if (res.isPresent()) {
			send(sessionId, 0, res.get(), dst);
			final DeviceDIB deviceDib = server.createDeviceDIB(svcCont);
			logger.debug("KNXnet/IP discovery: identify as '{}' for container {} to {} on {}", deviceDib.getName(),
					svcCont.getName(), dst, svcCont.networkInterface());
		}
	}

	Optional<byte[]> createSearchResponse(final boolean ext, final byte[] macFilter,
			final byte[] requestedServices, final byte[] requestedDibs) throws IOException {

		// we create our own HPAI from the actual socket, since
		// the service container might have opted for ephemeral port use
		// it can happen that our socket got closed and we get null
		final InetSocketAddress local = (InetSocketAddress) getSocket().getLocalSocketAddress();
		if (local == null) {
			logger.warn("KNXnet/IP discovery unable to announce container '{}', problem with local endpoint: "
					+ "socket bound={}, closed={}", svcCont.getName(), getSocket().isBound(), getSocket().isClosed());
			return Optional.empty();
		}

		try {
			final NetworkInterface ni = NetworkInterface.getByInetAddress(local.getAddress());
			final byte[] mac = ni != null ? ni.getHardwareAddress() : null;
			server.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(), PID.MAC_ADDRESS,
					mac == null ? new byte[6] : mac);

			// skip response if we have a mac filter set which does not match our mac
			if (macFilter.length > 0 && !Arrays.equals(macFilter, mac))
				return Optional.empty();
		}
		catch (SocketException | KnxPropertyException e) {}

		if (requestedServices.length > 0) {
			final ServiceFamiliesDIB families = server.createServiceFamiliesDIB(svcCont, ext);
			// skip response if we have a service request which we don't support
			for (int i = 0; i < requestedServices.length; i += 2) {
				final var familyId = ServiceFamily.of(requestedServices[i] & 0xff);
				final int version = requestedServices[i + 1] & 0xff;
				if (families.families().getOrDefault(familyId, 0) < version)
					return Optional.empty();
			}
		}

		final Set<Integer> set = new TreeSet<>();
		for (final byte dibType : requestedDibs)
			set.add(dibType & 0xff);
		final List<DIB> dibs = new ArrayList<>();
		set.forEach(dibType -> createDib(dibType, dibs, ext));

		final HPAI hpai = new HPAI(HPAI.IPV4_UDP, local);
		final byte[] buf = PacketHelper.toPacket(new SearchResponse(ext, hpai, dibs));
		return Optional.of(buf);
	}

	private boolean createDib(final int dibType, final List<DIB> dibs, final boolean extended) {
		switch (dibType) {
		case DIB.DEVICE_INFO:
			return dibs.add(server.createDeviceDIB(svcCont));
		case DIB.SUPP_SVC_FAMILIES:
			return dibs.add(server.createServiceFamiliesDIB(svcCont, extended));
		case DIB.AdditionalDeviceInfo:
			return dibs.add(createAdditionalDeviceDib());
		case DIB.SecureServiceFamilies:
			createSecureServiceFamiliesDib().ifPresent(dibs::add);
			return true;
		case DIB.TunnelingInfo:
			createTunnelingDib().ifPresent(dibs::add);
			return true;
		}
		return false;
	}

	private AdditionalDeviceDib createAdditionalDeviceDib() {
		final int status = server.getProperty(InterfaceObject.ROUTER_OBJECT, objectInstance(), PID.MEDIUM_STATUS, 1, 0);
		final int pidMaxLocalApduLength = 69;
		final int maxLocalApduLength = server.getProperty(InterfaceObject.CEMI_SERVER_OBJECT, objectInstance(),
				pidMaxLocalApduLength, 1, 15);
		return new AdditionalDeviceDib(status, maxLocalApduLength, DD0.TYPE_091A);
	}

	private Optional<ServiceFamiliesDIB> createSecureServiceFamiliesDib() {
		final var supported = Stream.of(DeviceManagement, Tunneling, ServiceFamily.Routing)
				.filter(this::isSecuredService)
				.collect(Collectors.toMap(svc -> svc, __ -> 1));

		if (supported.isEmpty())
			return Optional.empty();
		return Optional.of(ServiceFamiliesDIB.newSecureServiceFamilies(supported));
	}

	private Optional<TunnelingDib> createTunnelingDib() {
		final List<IndividualAddress> addresses = additionalAddresses();
		if (addresses.isEmpty() && svcCont.reuseControlEndpoint())
			addresses.add(svcCont.getMediumSettings().getDeviceAddress());
		if (addresses.isEmpty())
			return Optional.empty();

		final int[] status = new int[addresses.size()];

		for (int i = 0; i < addresses.size(); i++) {
			final IndividualAddress addr = addresses.get(i);
			final boolean inuse = addressInUse(addr);
			status[i] = 4 | 2 | (inuse ? 0 : 1);
		}
		final int pidMaxInterfaceApduLength = 68;
		final int maxApduLength = server.getProperty(InterfaceObject.CEMI_SERVER_OBJECT, objectInstance(),
				pidMaxInterfaceApduLength, 1, 15);
		return Optional.of(new TunnelingDib((short) maxApduLength, addresses, status));
	}

	private void send(final int sessionId, final int channelId, final byte[] packet, final InetSocketAddress dst) throws IOException {
		byte[] buf = packet;
		if (sessionId > 0) {
			final Session session = sessions.sessions.get(sessionId);
			if (session == null) {
				logger.info("session {} got deallocated, channel {} no longer valid", sessionId, channelId);
				return;
			}
			final long seq = session.sendSeq.getAndIncrement();
			final int msgTag = 0;
			buf = sessions.newSecurePacket(sessionId, seq, msgTag, packet);
			logger.debug("send session {} seq {} tag {} to {}", sessionId, seq, msgTag, dst);
		}

		if (!TcpLooper.send(buf, dst))
			s.send(new DatagramPacket(buf, buf.length, dst));
	}

	private DatagramSocket createSocket()
	{
		final HPAI ep = svcCont.getControlEndpoint();
		InetAddress ip = null;
		try {
			final DatagramSocket s = new DatagramSocket(null);
			// if we use the KNXnet/IP default port, we have to enable address reuse for a successful bind
			if (ep.getPort() == KNXnetIPConnection.DEFAULT_PORT)
				s.setReuseAddress(true);
			ip = usableIpAddresses().findFirst().orElse(null);
			s.bind(new InetSocketAddress(ip, ep.getPort()));
			final InetSocketAddress boundTo = (InetSocketAddress) s.getLocalSocketAddress();
			logger.trace("{} control endpoint bound to {}", svcCont.getName(), hostPort(boundTo));
			return s;
		}
		catch (final SocketException e) {
			throw wrappedException(e);
		}
	}

	private static byte[] subnetMaskOf(final InetAddress addr)
	{
		int length = 0;
		try {
			final List<InterfaceAddress> addresses = Optional.ofNullable(NetworkInterface.getByInetAddress(addr))
					.map(NetworkInterface::getInterfaceAddresses).orElse(Collections.emptyList());
			length = addresses.stream().filter(ia -> ia.getAddress().equals(addr))
					.map(ia -> (int) ia.getNetworkPrefixLength()).findFirst().orElse(0);

		}
		catch (final SocketException ignore) {}
		return ByteBuffer.allocate(4).putInt((int) ((0xffffffffL >> length) ^ 0xffffffffL)).array();
	}

	private static byte[] macAddress(final InetAddress addr) {
		byte[] mac = null;
		try {
			final NetworkInterface ni = NetworkInterface.getByInetAddress(addr);
			mac = ni != null ? ni.getHardwareAddress() : null;
		}
		catch (final SocketException ignore) {}
		return mac == null ? new byte[6] : mac;
	}

	private Stream<InetAddress> usableIpAddresses() throws SocketException {
		final NetworkInterface netif = NetworkInterface.getByName(svcCont.networkInterface());
		if (netif != null)
			return netif.inetAddresses().filter(Inet4Address.class::isInstance);
		if (!"any".equals(svcCont.networkInterface()))
			return Stream.empty();

		final var localHost = localHost().filter(Inet4Address.class::isInstance)
				.filter(not(InetAddress::isLoopbackAddress));
		if (localHost.isPresent())
			return localHost.stream();

		return NetworkInterface.networkInterfaces().filter(ControlEndpointService::interfaceIsUp)
				.flatMap(NetworkInterface::inetAddresses).filter(Inet4Address.class::isInstance)
				.filter(not(InetAddress::isLoopbackAddress));
	}

	private static boolean interfaceIsUp(final NetworkInterface netif) {
		try {
			return netif.isUp();
		}
		catch (final SocketException e) {
			return false;
		}
	}

	private Optional<InetAddress> localHost() {
		final long start = System.nanoTime();
		try {
			return Optional.of(InetAddress.getLocalHost());
		}
		catch (final UnknownHostException e) {}
		finally {
			final long elapsed = System.nanoTime() - start;
			if (elapsed > 3_000_000_000L)
				logger.warn("slow local host resolution, took {} ms", elapsed / 1000 / 1000);
		}
		return Optional.empty();
	}

	private int objectInstance()
	{
		return server.objectInstance(svcCont);
	}

	private IndividualAddress serverAddress()
	{
		try {
			return new IndividualAddress(server.getInterfaceObjectServer().getProperty(KNXNETIP_PARAMETER_OBJECT,
					objectInstance(), PID.KNX_INDIVIDUAL_ADDRESS, 1, 1));
		}
		catch (final KnxPropertyException e) {
			logger.error("no server device address set in KNXnet/IP parameter object!");
			return null;
		}
	}

	private IndividualAddress device;

	private ConnectResponse initNewConnection(final ConnectRequest req, final InetSocketAddress ctrlEndpt,
		final InetSocketAddress dataEndpt, final int channelId)
	{
		// information about remote endpoint in case of error response
		final String endpoint = ctrlEndpt.toString();

		boolean tunnel = true;
		boolean busmonitor = false;
		IndividualAddress device = null;
		CRD crd = null;

		int sessionId = 0;
		final int connType = req.getCRI().getConnectionType();
		if (secureSvcInProgress) {
			sessionId = sessions.registerConnection(connType, ctrlEndpt, channelId);
			if (sessionId == 0) {
				logger.error("no valid secure session for connection request from {}", ctrlEndpt);
				return errorResponse(ErrorCodes.CONNECTION_TYPE, endpoint);
			}
		}

		if (connType == KNXnetIPTunnel.TUNNEL_CONNECTION) {
			final TunnelingLayer knxLayer;
			final TunnelCRI cri = (TunnelCRI) req.getCRI();
			try {
				knxLayer = cri.tunnelingLayer();
			}
			catch (final KNXIllegalArgumentException e) {
				return errorResponse(ErrorCodes.TUNNELING_LAYER, endpoint);
			}
			if (knxLayer != TunnelingLayer.LinkLayer && knxLayer != TunnelingLayer.BusMonitorLayer)
				return errorResponse(ErrorCodes.TUNNELING_LAYER, endpoint);

			busmonitor = knxLayer == TunnelingLayer.BusMonitorLayer;
			if (busmonitor) {
				// check if service container has busmonitor allowed
				if (!svcCont.isNetworkMonitoringAllowed())
					return errorResponse(ErrorCodes.TUNNELING_LAYER, endpoint);

				// KNX specification says that if tunneling on busmonitor is
				// supported, only one tunneling connection is allowed per subnetwork,
				// i.e., if there are any active link-layer connections, we don't
				// allow tunneling on busmonitor.
				final List<DataEndpoint> active = connections.values().stream()
						.filter(h -> !h.isMonitor()).collect(toList());
				if (active.size() > 0) {
					logger.warn("{}: tunneling on busmonitor-layer currently not allowed (active connections "
							+ "for tunneling on link-layer)\n\tcurrently connected: {}", svcCont.getName(), active);
					return errorResponse(ErrorCodes.NO_MORE_CONNECTIONS, endpoint);
				}

				// but we can allow several monitor connections at the same time (not spec-conform)
				final boolean allowMultiMonitorConnections = true;
				if (allowMultiMonitorConnections) {
					final long monitoring = activeMonitorConnections().size();
					logger.info("{}: active monitor connections: {}, 1 connect request", svcCont.getName(), monitoring);
				}
			}
			else {
				// KNX specification says that if tunneling on busmonitor is supported, only one tunneling connection
				// is allowed per subnetwork, i.e., if there is an active bus monitor connection, we don't
				// allow any other tunneling connections.
				final List<DataEndpoint> active = activeMonitorConnections();
				if (active.size() > 0) {
					logger.warn("{}: connect request denied for tunneling on link-layer (active tunneling on "
							+ "busmonitor-layer connections)\n\tcurrently connected: {}", svcCont.getName(), active);
					return errorResponse(ErrorCodes.NO_MORE_CONNECTIONS, endpoint);
				}
			}

			final int userId;
			if (sessionId > 0) {
				userId = sessions.sessions.get(sessionId).userId;
				if (isSecuredService(Tunneling) && !userAuthorizedForTunneling(userId))
					return errorResponse(ErrorCodes.CONNECTION_TYPE, endpoint);
			}
			else
				userId = 0;

			final int ret = cri.tunnelingAddress().map(addr -> extendedConnectRequest(userId, addr))
					.orElseGet(() -> basicConnectRequest(userId));
			if (ret != ErrorCodes.NO_ERROR)
				return errorResponse(ret, endpoint);

			device = this.device;
			final boolean isServerAddress = device.equals(serverAddress());
			logger.info("assign {} address {} to channel {}",
					isServerAddress ? "server device" : "additional individual", device, channelId);
			crd = new TunnelCRD(device);
		}
		else if (connType == DEVICE_MGMT_CONNECTION) {
			logger.info("setup device management connection with channel ID {}", channelId);
			// At first, check if we are allowed to open mgmt connection at all; if
			// server assigned its own device address, we have to reject the request
			synchronized (usedKnxAddresses) {
				if (usedKnxAddresses.contains(serverAddress())) {
					logger.warn("server device address is currently assigned to connection, "
							+ "no management connections allowed");
					return errorResponse(ErrorCodes.CONNECTION_TYPE, endpoint);
				}
				++activeMgmtConnections;
			}

			tunnel = false;
			crd = CRD.createResponse(DEVICE_MGMT_CONNECTION, null);
		}
		else
			return errorResponse(ErrorCodes.CONNECTION_TYPE, endpoint);

		final ServiceLooper svcLoop;
		final DataEndpoint newDataEndpoint;
		LooperTask looperTask = null;

		if (svcCont.reuseControlEndpoint()) {
			svcLoop = this;
			newDataEndpoint = new DataEndpoint(s, getSocket(), ctrlEndpt, dataEndpt, channelId, device, tunnel,
					busmonitor, useNat, sessions, sessionId, this::connectionClosed, this::resetRequest);
		}
		else {
			try {
				svcLoop = new DataEndpointService(server, s, svcCont.getName());

				final BiConsumer<DataEndpoint, IndividualAddress> bc = (h, a) -> svcLoop.quit();
				newDataEndpoint = new DataEndpoint(s, svcLoop.getSocket(), ctrlEndpt, dataEndpt, channelId, device,
						tunnel, busmonitor, useNat, sessions, sessionId, bc.andThen(this::connectionClosed),
						((DataEndpointService) svcLoop)::resetRequest);
				((DataEndpointService) svcLoop).svcHandler = newDataEndpoint;

				looperTask = new LooperTask(server,
						svcCont.getName() + " data endpoint " + hostPort(newDataEndpoint.getRemoteAddress()), 0,
						() -> svcLoop);
			}
			catch (final RuntimeException e) {
				// we don't have any better error than NO_MORE_CONNECTIONS for this
				return errorResponse(ErrorCodes.NO_MORE_CONNECTIONS, endpoint);
			}
		}

		if (!acceptConnection(svcCont, newDataEndpoint, device, busmonitor)) {
			// don't use sh.close() here, we would initiate tunneling disconnect sequence
			// but we have to call svcLoop.quit() to close local data socket
			svcLoop.quit();
			freeDeviceAddress(device);
			return errorResponse(ErrorCodes.KNX_CONNECTION, endpoint);
		}
		connections.put(channelId, newDataEndpoint);
		if (looperTask != null)
			LooperTask.execute(looperTask);
		if (!svcCont.reuseControlEndpoint())
			looperTasks.add(looperTask);

		// for udp, always create our own HPAI from the socket, since the service container
		// might have opted for ephemeral port use
		final boolean tcp = req.getControlEndpoint().getHostProtocol() == HPAI.IPV4_TCP;
		final HPAI hpai = tcp ? new HPAI(HPAI.IPV4_TCP, null)
				: new HPAI(HPAI.IPV4_UDP, (InetSocketAddress) svcLoop.getSocket().getLocalSocketAddress());
		return new ConnectResponse(channelId, ErrorCodes.NO_ERROR, hpai, crd);
	}

	private List<DataEndpoint> activeMonitorConnections() {
		return connections.values().stream().filter(DataEndpoint::isMonitor).collect(toList());
	}

	private ConnectResponse errorResponse(final int status, final String endpoint)
	{
		final ConnectResponse res = new ConnectResponse(status);
		logger.warn("no data endpoint for remote endpoint {}, {}", endpoint, res.getStatusString());
		return res;
	}

	List<IndividualAddress> additionalAddresses() {
		final List<IndividualAddress> list = new ArrayList<>();
		try {
			final byte[] data = server.getInterfaceObjectServer().getProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(),
					PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 1, Integer.MAX_VALUE);
			final ByteBuffer buf = ByteBuffer.wrap(data);
			while (buf.hasRemaining())
				list.add(new IndividualAddress(buf.getShort() & 0xffff));
		}
		catch (final KnxPropertyException e) {
			logger.warn(e.getMessage());
		}
		return list;
	}

	private static final int pidTunnelingAddresses = 79;
	private static final int pidTunnelingUsers = 97;

	private int extendedConnectRequest(final int userId, final IndividualAddress addr) {
		final byte[] indices = allPropertyValues(pidTunnelingAddresses);
		final var additionalAddresses = additionalAddresses();
		boolean tunnelingAddress = false;

		for (int i = 0; i < indices.length; i++) {
			final var idx = indices[i] & 0xff;
			if (idx == 0) {
				if (addr.equals(serverAddress())) {
					tunnelingAddress = true;
					break;
				}
			}
			else if (addr.equals(additionalAddresses.get(idx - 1))) {
				tunnelingAddress = true;
				break;
			}
		}
		if (!tunnelingAddress)
			return NoTunnelingAddress;

		if (userId == 1) {
			final boolean ret = checkAndSetDeviceAddress(addr, addr.equals(serverAddress()));
			return ret ? ErrorCodes.NO_ERROR : ConnectionInUse;
		}

		boolean addrAuthorized = false;
		if (userId > 0) {
			// n:m mapping user -> tunneling address index
			final byte[] userToAddrIdx = allPropertyValues(pidTunnelingUsers);
			// users satisfy <= order, indices per user satisfy <= order
			for (int i = 0; i < userToAddrIdx.length; i += 2) {
				final var user = userToAddrIdx[i] & 0xff;
				if (userId > user)
					break;
				if (userId == user) {
					// tunneling address index: { addrIdx | 0 < addrIdx <= 255 }
					final var addrIdx = (userToAddrIdx[i + 1] & 0xff) - 1;
					final var idx = indices[addrIdx] & 0xff;
					final var ia = idx == 0 ? serverAddress() : additionalAddresses.get(idx - 1);
					if (addr.equals(ia)) {
						addrAuthorized = true;
						break;
					}
				}
			}
		}

		if (!addrAuthorized && isSecuredService(Tunneling))
			return AuthError;

		final boolean ret = checkAndSetDeviceAddress(addr, addr.equals(serverAddress()));
		device = addr;
		return ret ? ErrorCodes.NO_ERROR : ConnectionInUse;
	}

	private int basicConnectRequest(final int userId) {
		final byte[] addressIndices = allPropertyValues(pidTunnelingAddresses);
		final var additionalAddresses = additionalAddresses();

		IndividualAddress assigned = null;
		// exclude mgmt user, it always has access and is not stored in tunneling users
		if (userId > 1 && isSecuredService(Tunneling)) {
			// n:m mapping user -> tunneling address index
			// user is stored in natural order, idx per user is stored in natural order
			final byte[] userToAddrIdx = allPropertyValues(pidTunnelingUsers);

			for (int i = 0; i < userToAddrIdx.length; i += 2) {
				final var user = userToAddrIdx[i];
				if (user > userId)
					break;

				if (userId == user) {
					// tunneling address index is 1-based
					final var addrIdx = userToAddrIdx[i + 1] - 1;
					// addresses indices are 1-based
					final var idx = addressIndices[addrIdx];
					final var addr = idx == 0 ? serverAddress() : additionalAddresses.get(idx - 1);
					if (checkAndSetDeviceAddress(addr, addr.equals(serverAddress()))) {
						assigned = addr;
						break;
					}
				}
			}
		}
		else {
			for (int i = 0; i < addressIndices.length; i++) {
				// indices are 1-based
				final var idx = addressIndices[i];
				final var addr = idx == 0 ? serverAddress() : additionalAddresses.get(idx - 1);
				if (checkAndSetDeviceAddress(addr, addr.equals(serverAddress()))) {
					assigned = addr;
					break;
				}
			}
		}

		if (assigned == null) {
			final List<IndividualAddress> list = additionalAddresses;
			if (new HashSet<>(list).size() != list.size())
				return NoMoreUniqueConnections;
			return ErrorCodes.NO_MORE_CONNECTIONS;
		}
		device = assigned;
		return ErrorCodes.NO_ERROR;
	}

	private boolean userAuthorizedForTunneling(final int userId) {
		if (userId == 1)
			return true;
		final byte[] userToAddrIdx = allPropertyValues(pidTunnelingUsers);
		for (int i = 0; i < userToAddrIdx.length; i += 2) {
			final var user = userToAddrIdx[i];
			if (user > userId)
				return false;

			if (userId == user)
				return true;
		}
		return false;
	}

	private boolean isSecuredService(final ServiceFamily serviceFamily) {
		final int securedServices = server.getProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(),
				SecureSession.pidSecuredServices, 1, (byte) 0);
		final boolean secured = ((securedServices >> serviceFamily.id()) & 0x01) == 0x01;
		return secured;
	}

	private byte[] allPropertyValues(final int propertyId) {
		final var ios = server.getInterfaceObjectServer();
		try {
			return ios.getProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(), propertyId, 1, Integer.MAX_VALUE);
		}
		catch (final KnxPropertyException ignore) {}
		return new byte[0];
	}

	private boolean matchesSubnet(final IndividualAddress addr, final IndividualAddress subnetMask)
	{
		if (subnetMask.getArea() == addr.getArea()) {
			// if we represent an area coupler, line is 0
			if (subnetMask.getLine() == 0 || subnetMask.getLine() == addr.getLine()) {
				// address does match the mask
				return true;
			}
		}
		logger.warn("additional individual address {} does not match KNX subnet {}", addr, subnetMask);
		return false;
	}

	private boolean checkAndSetDeviceAddress(final IndividualAddress device, final boolean isServerAddress)
	{
		if (!matchesSubnet(device, serverAddress()))
			return false;
		synchronized (usedKnxAddresses) {
			if (isServerAddress && activeMgmtConnections > 0) {
				logger.warn("active management connection, cannot assign server device address");
				return false;
			}
			if (usedKnxAddresses.contains(device)) {
				logger.debug("address {} already assigned", device);
				return false;
			}
			usedKnxAddresses.add(device);
			return true;
		}
	}

	private void freeDeviceAddress(final IndividualAddress device)
	{
		synchronized (usedKnxAddresses) {
			usedKnxAddresses.remove(device);
		}
	}

	boolean addressInUse(final IndividualAddress addr) {
		synchronized (usedKnxAddresses) {
			return usedKnxAddresses.contains(addr);
		}
	}

	private boolean acceptConnection(final ServiceContainer sc, final KNXnetIPConnection conn,
		final IndividualAddress addr, final boolean busmonitor)
	{
		final List<ServerListener> l = server.listeners().listeners();
		return l.stream().allMatch(e -> e.acceptDataConnection(sc, conn, addr, busmonitor));
	}

	private void connectionEstablished(final ServiceContainer sc, final KNXnetIPConnection conn)
	{
		final List<ServerListener> l = server.listeners().listeners();
		l.stream().forEach(e -> e.connectionEstablished(sc, conn));
	}

	// workaround to find the correct looper/connection when ETS sends to the wrong UDP port
	// TODO make thread-safe
	private static final Set<LooperTask> looperTasks = Collections.newSetFromMap(new WeakHashMap<>());

	static Optional<DataEndpointService> findDataEndpoint(final int channelId) {
		for (final LooperTask t : looperTasks) {
			final Optional<DataEndpointService> looper = t.looper().map(DataEndpointService.class::cast);
			if (looper.isPresent() && looper.get().svcHandler.getChannelId() == channelId)
				return looper;
		}
		return Optional.empty();
	}

	boolean anyMatchDataConnection(final InetSocketAddress remoteEndpoint) {
		return connections.values().stream().anyMatch(c -> c.getRemoteAddress().equals(remoteEndpoint));
	}

	// we do not assign channel id 0
	private int assignChannelId() {
		if (connections.size() == MAX_CHANNEL_ID)
			return 0;
		// Try to assign the new channel id by counting up from the last assigned channel
		// id. We do this to eventually assign the overall usable range of ids, and to
		// avoid excessive assignment of the low channel ids only.
		int id = lastChannelId % MAX_CHANNEL_ID + 1;
		while (connections.containsKey(id))
			id = id % MAX_CHANNEL_ID + 1;
		lastChannelId = id;
		return lastChannelId;
	}

	private ManufacturerDIB createManufacturerDIB()
	{
		final int mfrId = server.getProperty(InterfaceObject.DEVICE_OBJECT, 1, PID.MANUFACTURER_ID, 1,
				KNXnetIPServer.defMfrId);
		byte[] data = KNXnetIPServer.defMfrData;
		final int elems = server.getPropertyElems(InterfaceObject.DEVICE_OBJECT, 1, PID.MANUFACTURER_DATA);
		if (elems > 0) {
			try {
				final InterfaceObjectServer ios = server.getInterfaceObjectServer();
				data = ios.getProperty(InterfaceObject.DEVICE_OBJECT, 1, PID.MANUFACTURER_DATA, 1, elems);
			}
			catch (final KnxPropertyException e) {}
		}
		return new ManufacturerDIB(mfrId, data);
	}
}
