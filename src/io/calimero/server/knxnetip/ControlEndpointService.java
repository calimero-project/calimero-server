/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2016, 2025 B. Malinowsky

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

import static io.calimero.device.ios.InterfaceObject.KNXNETIP_PARAMETER_OBJECT;
import static io.calimero.knxnetip.KNXnetIPDevMgmt.DEVICE_MGMT_CONNECTION;
import static io.calimero.knxnetip.KNXnetIPTunnel.TUNNEL_CONNECTION;
import static io.calimero.knxnetip.util.ServiceFamiliesDIB.ServiceFamily.DeviceManagement;
import static io.calimero.knxnetip.util.ServiceFamiliesDIB.ServiceFamily.Tunneling;
import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;
import static java.util.function.Predicate.not;
import static java.util.stream.Collectors.toList;

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
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import io.calimero.CloseEvent;
import io.calimero.DeviceDescriptor.DD0;
import io.calimero.IndividualAddress;
import io.calimero.KNXFormatException;
import io.calimero.KNXIllegalArgumentException;
import io.calimero.device.ios.DeviceObject;
import io.calimero.device.ios.InterfaceObject;
import io.calimero.device.ios.KnxPropertyException;
import io.calimero.device.ios.KnxipParameterObject;
import io.calimero.knxnetip.KNXnetIPConnection;
import io.calimero.knxnetip.KNXnetIPTunnel;
import io.calimero.knxnetip.KNXnetIPTunnel.TunnelingLayer;
import io.calimero.knxnetip.servicetype.ConnectRequest;
import io.calimero.knxnetip.servicetype.ConnectResponse;
import io.calimero.knxnetip.servicetype.ConnectionstateRequest;
import io.calimero.knxnetip.servicetype.ConnectionstateResponse;
import io.calimero.knxnetip.servicetype.DescriptionRequest;
import io.calimero.knxnetip.servicetype.DescriptionResponse;
import io.calimero.knxnetip.servicetype.DisconnectRequest;
import io.calimero.knxnetip.servicetype.DisconnectResponse;
import io.calimero.knxnetip.servicetype.ErrorCodes;
import io.calimero.knxnetip.servicetype.KNXnetIPHeader;
import io.calimero.knxnetip.servicetype.PacketHelper;
import io.calimero.knxnetip.servicetype.SearchRequest;
import io.calimero.knxnetip.servicetype.SearchResponse;
import io.calimero.knxnetip.servicetype.ServiceRequest;
import io.calimero.knxnetip.util.AdditionalDeviceDib;
import io.calimero.knxnetip.util.CRD;
import io.calimero.knxnetip.util.DIB;
import io.calimero.knxnetip.util.DeviceDIB;
import io.calimero.knxnetip.util.HPAI;
import io.calimero.knxnetip.util.KnxAddressesDIB;
import io.calimero.knxnetip.util.ManufacturerDIB;
import io.calimero.knxnetip.util.ServiceFamiliesDIB;
import io.calimero.knxnetip.util.ServiceFamiliesDIB.ServiceFamily;
import io.calimero.knxnetip.util.Srp;
import io.calimero.knxnetip.util.Srp.Type;
import io.calimero.knxnetip.util.TunnelCRD;
import io.calimero.knxnetip.util.TunnelCRI;
import io.calimero.knxnetip.util.TunnelingDib;
import io.calimero.knxnetip.util.TunnelingDib.SlotStatus;
import io.calimero.mgmt.PropertyAccess.PID;
import io.calimero.server.knxnetip.DataEndpoint.ConnectionType;
import io.calimero.server.knxnetip.SecureSessions.Session;

final class ControlEndpointService extends ServiceLooper
{
	// Connect response error codes
	private static final int NoMoreUniqueConnections = 0x25;
	private static final int AuthError = 0x28; // client is not authorized to use the requested individual address
	private static final int NoTunnelingAddress = 0x2d; // address requested in the extended CRI is not a tunneling address
	private static final int ConnectionInUse = 0x2e; // requested individual address for this connection is in use


	private final ServiceContainer svcCont;
	private final KnxipParameterObject knxipObject;

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

	final SecureSessions sessions;
	private boolean secureSvcInProgress;

	final TcpEndpoint tcpEndpoint;
	private final TcpEndpoint baosEndpoint;

	final UnixDomainSocketEndpoint udsEndpoint;
	private final UnixDomainSocketEndpoint udsBaosEndpoint;


	private volatile boolean inShutdown;


	ControlEndpointService(final KNXnetIPServer server, final ServiceContainer sc)
	{
		super(server, null, 512, 10000);
		svcCont = sc;
		knxipObject = KnxipParameterObject.lookup(server.getInterfaceObjectServer(), objectInstance());
		s = createSocket();
		sessions = new SecureSessions(this);

		final InetAddress addr = s.getLocalAddress();

		final byte[] empty = new byte[4];
		byte[] data = knxipObject.getOrDefault(PID.IP_ADDRESS, empty);
		if (Arrays.equals(data, empty))
			knxipObject.setInetAddress(PID.IP_ADDRESS, addr);
		knxipObject.setInetAddress(PID.CURRENT_IP_ADDRESS, addr);

		data = knxipObject.getOrDefault(PID.SUBNET_MASK, empty);
		if (Arrays.equals(data, empty))
			server.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(), PID.SUBNET_MASK, subnetMaskOf(addr));
		server.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(), PID.CURRENT_SUBNET_MASK, subnetMaskOf(addr));

		server.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(), PID.MAC_ADDRESS, macAddress(addr));

		final boolean secureMgmt = isSecuredService(DeviceManagement);
		final boolean secureTunneling = isSecuredService(Tunneling);
		final String mgmt = secureMgmt ? "required" : "optional";
		final String tunneling = secureTunneling ? "required" : "optional";
		logger.log(INFO, "{0} secure mgmt/tunneling connections: {1}/{2}", sc.getName(), mgmt, tunneling);

		final var ctrlEndpointAddress = (InetSocketAddress) s.getLocalSocketAddress();
		tcpEndpoint = new TcpEndpoint(this, ctrlEndpointAddress, false);
		final var baosEndpointAddress = new InetSocketAddress(ctrlEndpointAddress.getAddress(), 12004);
		baosEndpoint = new TcpEndpoint(this, baosEndpointAddress, true);

		final Optional<Path> unixSocketPath = ((DefaultServiceContainer) sc).unixSocketPath();
		final Path p = unixSocketPath.orElse(Path.of(""));
		udsEndpoint = new UnixDomainSocketEndpoint(this, p, false);
		udsBaosEndpoint = new UnixDomainSocketEndpoint(this, Path.of(p + ".baos"), true);

		try {
			tcpEndpoint.start();
			final boolean baosConnections = ((DefaultServiceContainer) sc).baosSupport();
			if (baosConnections)
				baosEndpoint.start();

			if (unixSocketPath.isPresent()) {
				udsEndpoint.start();
				if (baosConnections)
					udsBaosEndpoint.start();
			}
		}
		catch (final Exception e) {
			closeEndpoints();

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
		final var remote = endpoint.remoteAddress();
		if (timeout && !anyMatchDataConnection(remote)) {
			tcpEndpoint.lastConnectionTimedOut(remote);
			udsEndpoint.lastConnectionTimedOut(remote);
		}
	}

	void resetRequest(final DataEndpoint endpoint)
	{
		final InetSocketAddress ctrlEndpoint = null;
		fireResetRequest(endpoint.name(), ctrlEndpoint);
	}

	@Override
	public void quit() {
		inShutdown = true;
		closeDataConnections();
		closeEndpoints();
		super.quit();
	}

	private void closeEndpoints() {
		tcpEndpoint.close();
		baosEndpoint.close();
		udsEndpoint.close();
		udsBaosEndpoint.close();
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
					bound = netif.getName() + "/";
			}
			catch (final SocketException ignore) {}
			bound += hostPort(local);
		}
		return svcCont.getName() + " control endpoint " + bound;
	}

	@Override
	protected void onTimeout()
	{
		try {
			final InetAddress ip = Optional.ofNullable(((InetSocketAddress) s.getLocalSocketAddress()))
					.map(InetSocketAddress::getAddress).orElse(InetAddress.getByAddress(new byte[4]));
			final List<InetAddress> addresses = usableIpAddresses().collect(toList());
			if (!addresses.contains(ip)) {
				logger.log(WARNING, "{0} control endpoint: interface {1} updated its IP address from {2} to {3}",
						svcCont.getName(), svcCont.networkInterface(), ip.getHostAddress(), addresses);
				quit();
			}
		}
		catch (final IOException ignore) {}
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
	boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset, final EndpointAddress src)
			throws KNXFormatException, IOException {
		logger.log(TRACE, "{0} received {1} {2}", svcCont.getName(), src,
				HexFormat.ofDelimiter(" ").formatHex(data,offset - h.getStructLength(), offset - h.getStructLength() + h.getTotalLength()));
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
			// Some clients immediately send a new connect.req when the old connection got closed.
			// If we're shutting down, we're not here anymore. This avoids our connections list being repopulated
			// with newly established connections which won't last and just get closed again.
			if (inShutdown) {
				logger.log(TRACE, "{0} is being shut down, ignore connect request from {1}", svcCont.getName(), src);
				return true;
			}

			final ConnectRequest req = new ConnectRequest(data, offset);
			final var connType = req.getCRI().getConnectionType();
			final boolean tunneling = connType == TUNNEL_CONNECTION;
			final boolean devmgmt = connType == DEVICE_MGMT_CONNECTION;
			final var typeString = tunneling ? "tunneling" : devmgmt ? "device management" : "0x" + connType;

			if (tunneling && isSecuredService(Tunneling) || devmgmt && isSecuredService(DeviceManagement)) {
				logger.log(WARNING, "reject {0}, secure services required for {1}", h, typeString);
				final var ctrlEndpt = createResponseAddress(req.getControlEndpoint(), src, 1);
				final byte[] buf = PacketHelper
						.toPacket(errorResponse(ErrorCodes.CONNECTION_TYPE, ctrlEndpt.toString()));
				send(0, 0, buf, ctrlEndpt);
			}
			else
				return acceptControlService(0, h, data, offset, src);
		}
		else
			return acceptControlService(0, h, data, offset, src);
		return true;
	}

	boolean acceptControlService(final int sessionId, final KNXnetIPHeader h, final byte[] data, final int offset,
			final EndpointAddress src) throws KNXFormatException, IOException {
		final int svc = h.getServiceType();
		if (svc == KNXnetIPHeader.SearchRequest) {
			// extended unicast search request to this control endpoint
			if (!checkVersion(h))
				return true;

			final SearchRequest sr = SearchRequest.from(h, data, offset);
			byte[] macFilter = {};
			byte[] requestedServices = {};
			byte[] requestedDibs = {};
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

			final var addr = createResponseAddress(sr.getEndpoint(), src, 1);
			sendSearchResponse(sessionId, addr, macFilter, requestedServices, requestedDibs);
		}
		else if (svc == KNXnetIPHeader.DESCRIPTION_REQ) {
			if (!checkVersion(h))
				return true;
			final DescriptionRequest dr = new DescriptionRequest(data, offset);
			final DeviceDIB device = server.createDeviceDIB(svcCont);
			final ServiceFamiliesDIB svcFamilies = server.createServiceFamiliesDIB(svcCont, false);
			final ManufacturerDIB mfr = createManufacturerDIB();
			final List<IndividualAddress> addresses = knxipObject.additionalAddresses();
			final DescriptionResponse description = addresses.isEmpty()
					? new DescriptionResponse(device, svcFamilies, mfr)
					: new DescriptionResponse(device, svcFamilies, new KnxAddressesDIB(addresses), mfr);

			final var responseAddress = createResponseAddress(dr.getEndpoint(), src, 1);
			final byte[] buf = PacketHelper.toPacket(description);
			logger.log(INFO, "send KNXnet/IP description to {0}: {1}", responseAddress, description);
			send(sessionId, 0, buf, responseAddress);
		}
		else if (svc == KNXnetIPHeader.CONNECT_REQ) {
			useNat = false;
			// req throws if HPAI contains invalid address part
			final ConnectRequest req = new ConnectRequest(data, offset);

			final int connType = req.getCRI().getConnectionType();
			final int expectedVersion = connType == ObjectServerProtocol
					? ObjectServerVersion : KNXnetIPConnection.KNXNETIP_VERSION_10;
			int status = checkVersion(h, expectedVersion);

			final HPAI controlEndpoint = req.getControlEndpoint();
			final var ctrlEndpt = createResponseAddress(controlEndpoint, src, 1);
			byte[] buf = null;
			boolean established = false;

			final int channelId = assignChannelId();
			if (status == ErrorCodes.NO_ERROR) {
				if (channelId == 0)
					status = ErrorCodes.NO_MORE_CONNECTIONS;
				else {
					logger.log(INFO, "{0}: setup data endpoint (channel {1}) for connection request from {2}",
							svcCont.getName(), channelId, ctrlEndpt);
					final var dataEndpt = createResponseAddress(req.getDataEndpoint(), src, 2);
					final ConnectResponse res = initNewConnection(req, ctrlEndpt, dataEndpt, channelId);
					buf = PacketHelper.toPacket(expectedVersion, res);
					established = res.getStatus() == ErrorCodes.NO_ERROR;
				}
			}
			if (buf == null)
				buf = PacketHelper.toPacket(expectedVersion, errorResponse(status, ctrlEndpt.toString()));

			send(sessionId, channelId, buf, ctrlEndpt);
			if (established)
				connectionEstablished(svcCont, connections.get(channelId));
		}
		else if (svc == KNXnetIPHeader.CONNECT_RES)
			logger.log(DEBUG, "received connect response - ignored");
		else if (svc == KNXnetIPHeader.DISCONNECT_REQ) {
			final DisconnectRequest dr = new DisconnectRequest(data, offset);
			// find connection based on channel id
			final int channelId = dr.getChannelID();
			final DataEndpoint conn = connections.get(channelId);

			// requests with wrong channel ID are ignored (conforming to spec)
			if (conn == null) {
				logger.log(DEBUG, "received disconnect request with unknown channel id " + dr.getChannelID() + " - ignored");
				return true;
			}

			// According to specification, a control endpoint is allowed to change
			// during an established connection, but it's not recommended; if the
			// sender control endpoint differs from our connection control endpoint,
			// issue a warning
			final var ctrlEndpt = conn.remoteAddress();
			if (!ctrlEndpt.equals(src)) {
				logger.log(WARNING, "disconnect request: sender control endpoint changed from {0} to {1}, not recommended",
						ctrlEndpt, src);
			}

			conn.updateLastMsgTimestamp();

			final byte[] buf = PacketHelper.toPacket(new DisconnectResponse(channelId, ErrorCodes.NO_ERROR));
			try {
				send(sessionId, channelId, buf, ctrlEndpt);
			}
			catch (final IOException e) {
				logger.log(ERROR, "communication failure", e);
			}
			finally {
				conn.cleanup(CloseEvent.CLIENT_REQUEST, "client request", DEBUG, null);
			}
		}
		else if (svc == KNXnetIPHeader.DISCONNECT_RES) {
			final var res = new DisconnectResponse(data, offset);
			final var endpoint = connections.get(res.getChannelID());
			if (endpoint != null)
				endpoint.disconnectResponse(res);
		}
		else if (svc == KNXnetIPHeader.CONNECTIONSTATE_REQ) {
			final ConnectionstateRequest csr = new ConnectionstateRequest(data, offset);
			int status;

			final var endpoint = connections.get(csr.getChannelID());
			int protocolVersion = KNXnetIPConnection.KNXNETIP_VERSION_10;
			if (endpoint == null)
				status = ErrorCodes.CONNECTION_ID;
			else {
				protocolVersion = endpoint.protocolVersion();
				status = checkVersion(h, protocolVersion);
				if (status == ErrorCodes.NO_ERROR) {
					logger.log(TRACE, "received connection-state request (channel {0}) from {1}",
							csr.getChannelID(), endpoint.remoteAddress());
					endpoint.updateLastMsgTimestamp();
				}
			}

			if (status == ErrorCodes.NO_ERROR)
				status = subnetStatus();
			else {
				final var ctrlEp = csr.getControlEndpoint().endpoint();
				final var addr = endpoint != null ? endpoint.getRemoteAddress()
						: ctrlEp.getAddress().isAnyLocalAddress() || ctrlEp.getPort() == 0 ? src : ctrlEp;
				logger.log(WARNING, "received invalid connection-state request (channel {0}) from {1}: {2}",
						csr.getChannelID(), addr, ErrorCodes.getErrorMessage(status));
			}

			final byte[] buf = PacketHelper.toPacket(protocolVersion,
					new ConnectionstateResponse(csr.getChannelID(), status));
			send(sessionId, csr.getChannelID(), buf, createResponseAddress(csr.getControlEndpoint(), src, 0));
		}
		else if (svc == KNXnetIPHeader.CONNECTIONSTATE_RES)
			logger.log(DEBUG, "received connection-state response - ignored");
		else {
			DataEndpoint endpoint = null;
			try {
				// to get the channel id, we are just interested in connection header
				// which has the same layout for request and ack
				final int channelId = ServiceRequest.from(h, data, offset, buf -> null).getChannelID();

				// baos tcp connections don't have channel id
				if (channelId == 0 && tcpEndpoint.connections.containsKey(src)
						&& (h.getServiceType() == KNXnetIPHeader.ObjectServerRequest
								|| h.getServiceType() == KNXnetIPHeader.ObjectServerAck)) {
					endpoint = connections.values().stream()
							.filter(c -> c.type() == ConnectionType.Baos && src.equals(c.remoteAddress()))
							.findFirst().orElse(null);
				}
				else
					endpoint = connections.get(channelId);
			}
			catch (final KNXFormatException ignore) {}
			if (endpoint != null)
				return endpoint.handleDataServiceType(src, h, data, offset);
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
		try (final var scope = new TaskScope("data connection closer", Duration.ofSeconds(12))) {
			for (final DataEndpoint endpoint : connections.values())
				scope.execute(() -> endpoint.close(CloseEvent.SERVER_REQUEST,
						"quit service container " + svcCont.getName(), INFO, null));
		}
	}

	private void sendSearchResponse(final int sessionId, final EndpointAddress dst, final byte[] macFilter,
			final byte[] requestedServices, final byte[] requestedDibs) throws IOException {
		final var res = createSearchResponse(true, macFilter, requestedServices, requestedDibs, sessionId);
		if (res.isPresent()) {
			send(sessionId, 0, res.get(), dst);
			final DeviceDIB deviceDib = server.createDeviceDIB(svcCont);
			logger.log(DEBUG, "KNXnet/IP discovery: identify as ''{0}'' for container {1} to {2} on {3}", deviceDib.getName(),
					svcCont.getName(), dst, svcCont.networkInterface());
		}
	}

	Optional<byte[]> createSearchResponse(final boolean ext, final byte[] macFilter,
			final byte[] requestedServices, final byte[] requestedDibs, final int sessionId) {

		// we create our own HPAI from the actual socket, since
		// the service container might have opted for ephemeral port use
		// it can happen that our socket got closed and we get null
		final InetSocketAddress local = (InetSocketAddress) getSocket().getLocalSocketAddress();
		if (local == null) {
			logger.log(WARNING, "KNXnet/IP discovery unable to announce container ''{0}'', problem with local endpoint: "
					+ "socket bound={1}, closed={2}", svcCont.getName(), getSocket().isBound(), getSocket().isClosed());
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
		catch (SocketException | KnxPropertyException ignore) {}

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

		// always include device info and service families in response
		final Set<Integer> set = new TreeSet<>(List.of(DIB.DEVICE_INFO, DIB.SUPP_SVC_FAMILIES));
		for (final byte dibType : requestedDibs)
			set.add(dibType & 0xff);
		if (((DefaultServiceContainer) svcCont).baosSupport())
			set.add(DIB.MFR_DATA);
		final List<DIB> dibs = new ArrayList<>();
		set.forEach(dibType -> createDib(dibType, dibs, ext, sessionId));

		final HPAI hpai = new HPAI(HPAI.IPV4_UDP, local);
		final byte[] buf = PacketHelper.toPacket(new SearchResponse(ext, hpai, dibs));
		return Optional.of(buf);
	}

	private void createDib(final int dibType, final List<DIB> dibs, final boolean extended, final int sessionId) {
		switch (dibType) {
			case DIB.DEVICE_INFO -> dibs.add(server.createDeviceDIB(svcCont));
			case DIB.SUPP_SVC_FAMILIES -> dibs.add(server.createServiceFamiliesDIB(svcCont, extended));
			case DIB.AdditionalDeviceInfo -> dibs.add(createAdditionalDeviceDib());
			case DIB.SecureServiceFamilies -> createSecureServiceFamiliesDib().ifPresent(dibs::add);
			case DIB.TunnelingInfo -> createTunnelingDib(sessionId).ifPresent(dibs::add);
			case DIB.MFR_DATA -> dibs.add(new ManufacturerDIB(0x00c5, new byte[]{1, 4, (byte) ObjectServerProtocol, ObjectServerVersion}));
		}
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

	private Optional<TunnelingDib> createTunnelingDib(final int sessionId) {
		final List<IndividualAddress> addresses = knxipObject.additionalAddresses();
		if (addresses.isEmpty() && svcCont.reuseControlEndpoint())
			addresses.add(svcCont.getMediumSettings().getDeviceAddress());
		if (addresses.isEmpty())
			return Optional.empty();

		final boolean subnetOk = subnetStatus() == ErrorCodes.NO_ERROR;

		final var slots = new HashMap<IndividualAddress, EnumSet<SlotStatus>>();
		for (final var addr : addresses) {
			final var status = EnumSet.noneOf(SlotStatus.class);
			if (!addressInUse(addr))
				status.add(SlotStatus.Free);
			if (secureSvcInProgress && sessionId > 0) {
				final var session = sessions.sessions.get(sessionId);
				if (session != null && addressAuthorizedForUser(session.userId, addr))
					status.add(SlotStatus.Authorized);
			}
			else if (!isSecuredService(ServiceFamily.Tunneling))
				status.add(SlotStatus.Authorized);

			if (subnetOk)
				status.add(SlotStatus.Usable);
			slots.put(addr, status);
		}
		final int pidMaxInterfaceApduLength = 68;
		final int maxApduLength = server.getProperty(InterfaceObject.CEMI_SERVER_OBJECT, objectInstance(),
				pidMaxInterfaceApduLength, 1, 15);
		return Optional.of(new TunnelingDib(maxApduLength, slots));
	}

	private void send(final int sessionId, final int channelId, final byte[] packet, final EndpointAddress dst) throws IOException {
		byte[] buf = packet;
		if (sessionId > 0) {
			final Session session = sessions.sessions.get(sessionId);
			if (session == null) {
				logger.log(INFO, "session {0} got deallocated, channel {1} no longer valid", sessionId, channelId);
				return;
			}
			final long seq = session.sendSeq.getAndIncrement();
			final int msgTag = 0;
			buf = sessions.newSecurePacket(sessionId, seq, msgTag, packet);
			logger.log(DEBUG, "send session {0} seq {1} tag {2} to {3}", sessionId, seq, msgTag, dst);
		}

		if (dst instanceof TcpEndpointAddress)
			tcpEndpoint.send(buf, dst);
		else if (dst instanceof UnixEndpointAddress)
			udsEndpoint.send(buf, dst);
		else if (dst instanceof final UdpEndpointAddress udp)
			s.send(new DatagramPacket(buf, buf.length, udp.address()));
	}

	private DatagramSocket createSocket()
	{
		final HPAI ep = svcCont.getControlEndpoint();
		InetAddress ip;
		try {
			final DatagramSocket s = new DatagramSocket(null);
			// if we use the KNXnet/IP default port, we have to enable address reuse for a successful bind
			final int port = ep.endpoint().getPort();
			if (port == KNXnetIPConnection.DEFAULT_PORT)
				s.setReuseAddress(true);
			ip = usableIpAddresses().findFirst().orElse(null);
			s.bind(new InetSocketAddress(ip, port));
			final InetSocketAddress boundTo = (InetSocketAddress) s.getLocalSocketAddress();
			logger.log(TRACE, "{0} control endpoint bound to {1}", svcCont.getName(), hostPort(boundTo));
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
				logger.log(WARNING, "slow local host resolution, took {0} ms", elapsed / 1000 / 1000);
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
			return new IndividualAddress(knxipObject.get(PID.KNX_INDIVIDUAL_ADDRESS));
		}
		catch (final KnxPropertyException e) {
			logger.log(ERROR, "no server device address set in KNXnet/IP parameter object!");
			return null;
		}
	}

	private static final int ObjectServerProtocol = 0xf0;
	private static final int ObjectServerVersion = 0x20;

	private IndividualAddress device;

	private ConnectResponse initNewConnection(final ConnectRequest req, final EndpointAddress ctrlEndpt,
			final EndpointAddress dataEndpt, final int channelId) {
		// information about remote endpoint in case of error response
		final String endpoint = ctrlEndpt.toString();

		ConnectionType cType = ConnectionType.LinkLayer;
		IndividualAddress device = null;
		CRD crd;

		int sessionId = 0;
		final int connType = req.getCRI().getConnectionType();
		if (secureSvcInProgress) {
			sessionId = sessions.registerConnection(connType, ctrlEndpt, channelId);
			if (sessionId == 0) {
				logger.log(ERROR, "no valid secure session for connection request from {0}", ctrlEndpt);
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

			if (knxLayer == TunnelingLayer.BusMonitorLayer) {
				// check if service container has busmonitor allowed
				if (!svcCont.isNetworkMonitoringAllowed())
					return errorResponse(ErrorCodes.TUNNELING_LAYER, endpoint);

				// KNX specification says that if tunneling on busmonitor is
				// supported, only one tunneling connection is allowed per subnetwork,
				// i.e., if there are any active link-layer connections, we don't
				// allow tunneling on busmonitor.
				final List<DataEndpoint> active = activeConnectionsOfType(ConnectionType.LinkLayer);
				if (active.size() > 0) {
					logger.log(WARNING, "{0}: tunneling on busmonitor-layer currently not allowed (active connections "
							+ "for tunneling on link-layer)\n\tcurrently connected: {1}", svcCont.getName(), active);
					return errorResponse(ErrorCodes.NO_MORE_CONNECTIONS, endpoint);
				}

				// but we can allow several monitor connections at the same time (not spec-conform)
				final boolean allowMultiMonitorConnections = true;
				if (allowMultiMonitorConnections) {
					final long monitoring = activeConnectionsOfType(ConnectionType.Monitor).size();
					logger.log(INFO, "{0}: active monitor connections: {1}, 1 connect request", svcCont.getName(), monitoring);
				}

				cType = ConnectionType.Monitor;
			}
			else {
				// KNX specification says that if tunneling on busmonitor is supported, only one tunneling connection
				// is allowed per subnetwork, i.e., if there is an active bus monitor connection, we don't
				// allow any other tunneling connections.
				final List<DataEndpoint> active = activeConnectionsOfType(ConnectionType.Monitor);
				if (active.size() > 0) {
					logger.log(WARNING, "{0}: connect request denied for tunneling on link-layer (active tunneling on "
							+ "busmonitor-layer connections)\n\tcurrently connected: {1}", svcCont.getName(), active);
					return errorResponse(ErrorCodes.NO_MORE_CONNECTIONS, endpoint);
				}
			}

			final List<DataEndpoint> baos = activeConnectionsOfType(ConnectionType.Baos);
			if (baos.size() > 0) {
				logger.log(WARNING, "{0}: connect request denied for tunneling (active baos "
						+ "connections)\n\tcurrently connected: {1}", svcCont.getName(), baos);
				return errorResponse(ErrorCodes.NO_MORE_CONNECTIONS, endpoint);
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
			logger.log(INFO, "assign {0} address {1} to channel {2}",
					isServerAddress ? "server device" : "additional individual", device, channelId);
			crd = new TunnelCRD(device);
		}
		else if (connType == DEVICE_MGMT_CONNECTION) {
			logger.log(INFO, "setup device management connection with channel ID {0}", channelId);
			// At first, check if we are allowed to open mgmt connection at all; if
			// server assigned its own device address, we have to reject the request
			synchronized (usedKnxAddresses) {
				if (usedKnxAddresses.contains(serverAddress())) {
					logger.log(WARNING, "server device address is currently assigned to connection, "
							+ "no management connections allowed");
					return errorResponse(ErrorCodes.CONNECTION_TYPE, endpoint);
				}
				++activeMgmtConnections;
			}

			cType = ConnectionType.DevMgmt;
			crd = CRD.createResponse(DEVICE_MGMT_CONNECTION);
		}
		else if (connType == ObjectServerProtocol && ((DefaultServiceContainer) svcCont).baosSupport()) {
			final List<DataEndpoint> active = activeConnectionsOfType(ConnectionType.Monitor);
			if (active.size() > 0) {
				logger.log(WARNING, "{0}: connect request denied for baos connection (active tunneling on "
						+ "busmonitor-layer connections)\n\tcurrently connected: {1}", svcCont.getName(), active);
				return errorResponse(ErrorCodes.NO_MORE_CONNECTIONS, endpoint);
			}
			final List<DataEndpoint> linkLayer = activeConnectionsOfType(ConnectionType.LinkLayer);
			if (linkLayer.size() > 0) {
				logger.log(WARNING, "{0}: baos connection currently not allowed (active connections "
						+ "for tunneling on link-layer)\n\tcurrently connected: {1}", svcCont.getName(), linkLayer);
				return errorResponse(ErrorCodes.NO_MORE_CONNECTIONS, endpoint);
			}

			logger.log(INFO, "setup baos connection with channel ID {0}", channelId);
			cType = ConnectionType.Baos;
			crd = CRD.createResponse(ObjectServerProtocol);
		}
		else
			return errorResponse(ErrorCodes.CONNECTION_TYPE, endpoint);

		final ServiceLooper svcLoop;
		final DataEndpoint newDataEndpoint;
		LooperTask looperTask = null;

		if (svcCont.reuseControlEndpoint()) { // reusing the control endpoint only makes sense for UDP
			svcLoop = this;
			newDataEndpoint = new DataEndpoint(this, s, getSocket(), ctrlEndpt, dataEndpt, channelId, device, cType,
					useNat, sessions, sessionId, this::connectionClosed, this::resetRequest);
		}
		else {
			try {
				final boolean stream = tcpEndpoint.connections.containsKey(dataEndpt)
						|| udsEndpoint.connections.containsKey(dataEndpt)
						|| baosEndpoint.connections.containsKey(dataEndpt)
						|| udsBaosEndpoint.connections.containsKey(dataEndpt);

				BiConsumer<DataEndpoint, IndividualAddress> bc;
				final DatagramSocket socket;
				Consumer<DataEndpoint> resetRequest;
				if (stream) {
					svcLoop = null;
					socket = null;
					bc = (__, ___) -> {};
					resetRequest = (__) -> {};
				}
				else {
					svcLoop = new DataEndpointService(server, s, svcCont.getName());
					socket = svcLoop.getSocket();
					bc = (h, a) -> svcLoop.quit();
					resetRequest = ((DataEndpointService) svcLoop)::resetRequest;
				}

				newDataEndpoint = new DataEndpoint(this, s, socket, ctrlEndpt, dataEndpt, channelId, device,
						cType, useNat, sessions, sessionId, bc.andThen(this::connectionClosed), resetRequest);
				if (svcLoop != null)
					((DataEndpointService) svcLoop).svcHandler = newDataEndpoint;

				if (!stream)
					looperTask = new LooperTask(server,
							svcCont.getName() + " data endpoint " + newDataEndpoint.remoteAddress(), 0, () -> svcLoop);
			}
			catch (final RuntimeException e) {
				// we don't have any better error than NO_MORE_CONNECTIONS for this
				return errorResponse(ErrorCodes.NO_MORE_CONNECTIONS, endpoint);
			}
		}

		if (!acceptConnection(svcCont, newDataEndpoint, device, cType)) {
			// don't use sh.close() here, we would initiate tunneling disconnect sequence
			// but we have to call svcLoop.quit() to close local data socket
			if (svcLoop != null)
				svcLoop.quit();
			freeDeviceAddress(device);
			return errorResponse(ErrorCodes.KNX_CONNECTION, endpoint);
		}
		connections.put(channelId, newDataEndpoint);
		if (looperTask != null) {
			LooperTask.execute(looperTask);
			if (!svcCont.reuseControlEndpoint())
				looperTasks.add(looperTask);
		}

		// for udp, always create our own HPAI from the socket, since the service container
		// might have opted for ephemeral port use
		final boolean tcp = req.getControlEndpoint().hostProtocol() == HPAI.IPV4_TCP;
		final HPAI hpai = tcp ? HPAI.Tcp : useNat ? HPAI.Nat
				: new HPAI(HPAI.IPV4_UDP, (InetSocketAddress) svcLoop.getSocket().getLocalSocketAddress());
		return new ConnectResponse(channelId, ErrorCodes.NO_ERROR, hpai, crd);
	}

	private List<DataEndpoint> activeConnectionsOfType(final ConnectionType type) {
		return connections.values().stream().filter(c -> c.type() == type).collect(toList());
	}

	private ConnectResponse errorResponse(final int status, final String endpoint)
	{
		final ConnectResponse res = new ConnectResponse(status);
		logger.log(WARNING, "no data endpoint for remote endpoint {0}, {1}", endpoint, res.getStatusString());
		return res;
	}

	List<IndividualAddress> additionalAddresses() {
		return knxipObject.additionalAddresses();
	}

	private int extendedConnectRequest(final int userId, final IndividualAddress addr) {
		final byte[] indices = knxipObject.getOrDefault(KnxipParameterObject.Pid.TunnelingAddresses, new byte[0]);
		final var additionalAddresses = knxipObject.additionalAddresses();
		boolean tunnelingAddress = false;

		for (final byte index : indices) {
			final var idx = index & 0xff;
			if (idx == 0) {
				if (addr.equals(serverAddress())) {
					tunnelingAddress = true;
					break;
				}
			} else if (addr.equals(additionalAddresses.get(idx - 1))) {
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
			final byte[] userToAddrIdx = knxipObject.getOrDefault(KnxipParameterObject.Pid.TunnelingUsers, new byte[0]);
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
		final byte[] addressIndices = knxipObject.getOrDefault(KnxipParameterObject.Pid.TunnelingAddresses, new byte[0]);
		final var additionalAddresses = knxipObject.additionalAddresses();

		IndividualAddress assigned = null;
		// exclude mgmt user, it always has access and is not stored in tunneling users
		if (userId > 1 && isSecuredService(Tunneling)) {
			// n:m mapping user -> tunneling address index
			// user is stored in natural order, idx per user is stored in natural order
			final byte[] userToAddrIdx = knxipObject.getOrDefault(KnxipParameterObject.Pid.TunnelingUsers, new byte[0]);

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
			for (final byte idx : addressIndices) {
				// indices are 1-based
				final var addr = idx == 0 ? serverAddress() : additionalAddresses.get(idx - 1);
				if (checkAndSetDeviceAddress(addr, addr.equals(serverAddress()))) {
					assigned = addr;
					break;
				}
			}
		}

		if (assigned == null) {
			if (new HashSet<>(additionalAddresses).size() != additionalAddresses.size())
				return NoMoreUniqueConnections;
			return ErrorCodes.NO_MORE_CONNECTIONS;
		}
		device = assigned;
		return ErrorCodes.NO_ERROR;
	}

	private boolean userAuthorizedForTunneling(final int userId) {
		if (userId == 1)
			return true;
		final byte[] userToAddrIdx = knxipObject.getOrDefault(KnxipParameterObject.Pid.TunnelingUsers, new byte[0]);
		for (int i = 0; i < userToAddrIdx.length; i += 2) {
			final var user = userToAddrIdx[i] & 0xff;
			if (user > userId)
				return false;

			if (userId == user)
				return true;
		}
		return false;
	}

	private boolean addressAuthorizedForUser(final int userId, final IndividualAddress addr) {
		if (userId == 1)
			return true;
		final var additionalAddresses = knxipObject.additionalAddresses();
		final byte[] userToAddrIdx = knxipObject.getOrDefault(KnxipParameterObject.Pid.TunnelingUsers, new byte[0]);
		for (int i = 0; i < userToAddrIdx.length; i += 2) {
			final var user = userToAddrIdx[i] & 0xff;
			if (user > userId)
				return false;

			if (userId == user) {
				final int tunAddrIdx = userToAddrIdx[i + 1] & 0xff;
				if (tunAddrIdx == 0) {
					if (addr.equals(serverAddress()))
						return true;
				}
				else if (addr.equals(additionalAddresses.get(tunAddrIdx - 1)))
					return true;
			}
		}
		return false;
	}

	private boolean isSecuredService(final ServiceFamily serviceFamily) {
		return knxipObject.securedService(serviceFamily);
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
		logger.log(WARNING, "additional individual address {0} does not match KNX subnet {1}", addr, subnetMask);
		return false;
	}

	private boolean checkAndSetDeviceAddress(final IndividualAddress device, final boolean isServerAddress)
	{
		if (!matchesSubnet(device, serverAddress()))
			return false;
		synchronized (usedKnxAddresses) {
			if (isServerAddress && activeMgmtConnections > 0) {
				logger.log(WARNING, "active management connection, cannot assign server device address");
				return false;
			}
			if (usedKnxAddresses.contains(device)) {
				logger.log(TRACE, "address {0} already assigned", device);
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
		final IndividualAddress addr, final ConnectionType ctype)
	{
		final List<ServerListener> l = server.listeners().listeners();
		return l.stream().allMatch(e -> e.acceptDataConnection(sc, conn, addr, ctype));
	}

	private void connectionEstablished(final ServiceContainer sc, final KNXnetIPConnection conn)
	{
		final List<ServerListener> l = server.listeners().listeners();
		l.forEach(e -> e.connectionEstablished(sc, conn));
	}

	// workaround to find the correct looper/connection when ETS sends to the wrong UDP port
	private static final Set<LooperTask> looperTasks = Collections
			.synchronizedSet(Collections.newSetFromMap(new WeakHashMap<>()));

	static Optional<DataEndpointService> findDataEndpoint(final int channelId) {
		synchronized (looperTasks) {
			for (final LooperTask t : looperTasks) {
				final Optional<DataEndpointService> looper = t.looper().map(DataEndpointService.class::cast);
				if (looper.isPresent() && looper.get().svcHandler.getChannelId() == channelId)
					return looper;
			}
		}
		return Optional.empty();
	}

	boolean anyMatchDataConnection(final EndpointAddress remoteEndpoint) {
		return connections.values().stream().anyMatch(c -> c.remoteAddress().equals(remoteEndpoint));
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
		final int mfrId = server.getProperty(InterfaceObject.DEVICE_OBJECT, 1, PID.MANUFACTURER_ID, 1, 0);
		final var ios = server.getInterfaceObjectServer();
		final byte[] data = ios.getProperty(InterfaceObject.DEVICE_OBJECT, 1, PID.MANUFACTURER_DATA, 1, Integer.MAX_VALUE);
		return new ManufacturerDIB(mfrId, data);
	}

	private int checkVersion(final KNXnetIPHeader h, final int version) {
		final int status = h.getVersion() == version ? ErrorCodes.NO_ERROR : ErrorCodes.VERSION_NOT_SUPPORTED;
		if (status == ErrorCodes.VERSION_NOT_SUPPORTED)
			logger.log(WARNING, "KNXnet/IP " + (h.getVersion() >> 4) + "." + (h.getVersion() & 0xf) + " "
					+ ErrorCodes.getErrorMessage(ErrorCodes.VERSION_NOT_SUPPORTED));
		return status;
	}

	boolean setupBaosStreamEndpoint(final EndpointAddress remote) {
		try {
			final var newDataEndpoint = new DataEndpoint(this, s, null, remote, remote, 0, device,
					ConnectionType.Baos, false, sessions, 0, this::connectionClosed, __ -> {});

			if (!acceptConnection(svcCont, newDataEndpoint, device, ConnectionType.Baos))
				return false;

			connections.put(0, newDataEndpoint);
			connectionEstablished(svcCont, newDataEndpoint);
			return true;
		}
		catch (final RuntimeException e) {
			logger.log(WARNING, "error setting up baos endpoint for {0}", remote, e);
			return false;
		}
	}
}
