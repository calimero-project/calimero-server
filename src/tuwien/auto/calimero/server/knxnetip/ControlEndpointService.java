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
import java.util.BitSet;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KnxPropertyException;
import tuwien.auto.calimero.knxnetip.KNXnetIPConnection;
import tuwien.auto.calimero.knxnetip.KNXnetIPDevMgmt;
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
import tuwien.auto.calimero.knxnetip.util.CRD;
import tuwien.auto.calimero.knxnetip.util.DeviceDIB;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.knxnetip.util.KnxAddressesDIB;
import tuwien.auto.calimero.knxnetip.util.ManufacturerDIB;
import tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB;
import tuwien.auto.calimero.knxnetip.util.TunnelCRD;
import tuwien.auto.calimero.knxnetip.util.TunnelCRI;
import tuwien.auto.calimero.log.LogService.LogLevel;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;

final class ControlEndpointService extends ServiceLooper
{
	private final ServiceContainer svcCont;

	private final List<IndividualAddress> usedKnxAddresses = new ArrayList<>();
	// If the server assigns its own KNX individual address to a connection, no
	// management (using tunneling or from the KNX subnet) shall be allowed.
	// This flag maintains the current state, access is synchronized on
	// the variable usedKnxAddresses.
	private int activeMgmtConnections;

	// overall maximum allowed is 0xff
	private static final int MAX_CHANNEL_ID = 255;
	private final BitSet channelIds = new BitSet(MAX_CHANNEL_ID);
	private int lastChannelId;

	private final SecureSession secure;

	ControlEndpointService(final KNXnetIPServer server, final ServiceContainer sc)
	{
		super(server, null, 512, 10000);
		svcCont = sc;
		s = createSocket();

		final InetAddress addr = s.getLocalAddress();
		server.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(), PID.CURRENT_IP_ADDRESS, addr.getAddress());
		server.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(), PID.CURRENT_SUBNET_MASK, subnetMaskOf(addr));

		secure = new SecureSession(this);
	}

	void connectionClosed(final DataEndpointServiceHandler h, final IndividualAddress device)
	{
		server.dataConnections.remove(h);
		// free knx address and channel id we assigned to the connection
		freeDeviceAddress(device);
		freeChannelId(h.getChannelId());

		if (h.isDeviceMgmt())
			synchronized (usedKnxAddresses) {
				--activeMgmtConnections;
			}
	}

	void resetRequest(final DataEndpointServiceHandler h)
	{
		final InetSocketAddress ctrlEndpoint = null;
		fireResetRequest(h.getName(), ctrlEndpoint);
	}

	@Override
	public void quit()
	{
		// check if we have open data connections before forwarding the call
		if (channelsAssigned())
			server.closeDataConnections(this);
		super.quit();
	}

	@Override
	protected void onTimeout()
	{
		final InetAddress ip = ((InetSocketAddress) s.getLocalSocketAddress()).getAddress();
		try {
			final List<InetAddress> addresses = assignedIpAddresses();
			if (!addresses.contains(ip)) {
				logger.warn("{} control endpoint: interface {} updated its IP address from {} to {}",
						svcCont.getName(), svcCont.networkInterface(), ip.getHostAddress(), addresses);
				quit();
			}
		}
		catch (final IOException e) {}
	}

	ServiceContainer getServiceContainer()
	{
		return svcCont;
	}

	@Override
	boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset, final InetAddress src,
		final int port) throws KNXFormatException, IOException
	{
		final int svc = h.getServiceType();
		if (svc == KNXnetIPHeader.DESCRIPTION_REQ) {
			if (!checkVersion(h))
				return true;
			final DescriptionRequest dr = new DescriptionRequest(data, offset);
			if (dr.getEndpoint().getHostProtocol() != HPAI.IPV4_UDP) {
				logger.warn("description request: protocol support for UDP/IP only");
				return true;
			}
			final DeviceDIB device = server.createDeviceDIB(svcCont);
			final ServiceFamiliesDIB svcFamilies = server.createServiceFamiliesDIB(svcCont);
			final ManufacturerDIB mfr = createManufacturerDIB();
			final List<IndividualAddress> addresses = knxAddresses();
			final DescriptionResponse description = addresses.isEmpty()
					? new DescriptionResponse(device, svcFamilies, mfr)
					: new DescriptionResponse(device, svcFamilies, new KnxAddressesDIB(addresses), mfr);

			final InetSocketAddress responseAddress = createResponseAddress(dr.getEndpoint(), src, port, 1);
			final byte[] buf = PacketHelper.toPacket(description);
			s.send(new DatagramPacket(buf, buf.length, responseAddress));
			logger.info("send KNXnet/IP description to {}: {}", responseAddress, description);
		}
		else if (svc == KNXnetIPHeader.CONNECT_REQ) {
			useNat = false;
			final ConnectRequest req = new ConnectRequest(data, offset);
			int status = ErrorCodes.NO_ERROR;

			if (req.getDataEndpoint().getHostProtocol() != HPAI.IPV4_UDP) {
				logger.warn("connect request: only connection support for UDP/IP");
				status = ErrorCodes.HOST_PROTOCOL_TYPE;
			}
			else if (!checkVersion(h))
				status = ErrorCodes.VERSION_NOT_SUPPORTED;

			final InetSocketAddress ctrlEndpt = createResponseAddress(req.getControlEndpoint(), src, port, 1);
			byte[] buf = null;
			boolean established = false;

			if (status == ErrorCodes.NO_ERROR) {
				final int channelId = assignChannelId();
				if (channelId == 0)
					status = ErrorCodes.NO_MORE_CONNECTIONS;
				else {
					logger.info("{}: setup data endpoint (channel {}) for connection request from {}",
							svcCont.getName(), channelId, ctrlEndpt);
					final InetSocketAddress dataEndpt = createResponseAddress(req.getDataEndpoint(), src, port, 2);
					final ConnectResponse res = initNewConnection(req, ctrlEndpt, dataEndpt, channelId);
					buf = PacketHelper.toPacket(res);
					established = res.getStatus() == ErrorCodes.NO_ERROR;
					if (!established)
						freeChannelId(channelId);
				}
			}
			if (buf == null)
				buf = PacketHelper.toPacket(errorResponse(status, ctrlEndpt.toString()));

			final DatagramPacket p = new DatagramPacket(buf, buf.length, ctrlEndpt);
			s.send(p);
			if (established)
				connectionEstablished(svcCont, server.dataConnections.get(server.dataConnections.size() - 1));
		}
		else if (svc == KNXnetIPHeader.CONNECT_RES)
			logger.warn("received connect response - ignored");
		else if (svc == KNXnetIPHeader.DISCONNECT_REQ) {
			final DisconnectRequest dr = new DisconnectRequest(data, offset);
			// find connection based on channel id
			final int channelId = dr.getChannelID();
			final KNXnetIPConnection conn = findConnection(channelId);

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
			if (!ctrlEndpt.getAddress().equals(src) || ctrlEndpt.getPort() != port) {
				logger.warn("disconnect request: sender control endpoint changed from " + ctrlEndpt + " to " + src
						+ ", not recommended");
			}
			final byte[] buf = PacketHelper.toPacket(new DisconnectResponse(channelId, ErrorCodes.NO_ERROR));
			final DatagramPacket p = new DatagramPacket(buf, buf.length, ctrlEndpt.getAddress(), ctrlEndpt.getPort());
			try {
				s.send(p);
			}
			catch (final IOException e) {
				logger.error("communication failure", e);
			}
			finally {
				((DataEndpointServiceHandler) conn).cleanup(CloseEvent.CLIENT_REQUEST, "client request", LogLevel.INFO,
						null);
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
			if (status == ErrorCodes.NO_ERROR && csr.getControlEndpoint().getHostProtocol() != HPAI.IPV4_UDP)
				status = ErrorCodes.HOST_PROTOCOL_TYPE;

			if (status == ErrorCodes.NO_ERROR) {
				final KNXnetIPConnection c = findConnection(csr.getChannelID());
				if (c == null)
					status = ErrorCodes.CONNECTION_ID;
				else {
					logger.trace("received connection state request from {} for channel {}", c.getRemoteAddress(),
							csr.getChannelID());
					((DataEndpointServiceHandler) c).updateLastMsgTimestamp();
				}
			}

			if (status != ErrorCodes.NO_ERROR)
				logger.warn("received invalid connection state request for channel {}: {}", csr.getChannelID(),
						ErrorCodes.getErrorMessage(status));

			// At this point, if we know about an error with the data connection,
			// set status to ErrorCodes.DATA_CONNECTION; if we know about problems
			// with the KNX subnet, set status to ErrorCodes.KNX_CONNECTION.
			// if (some connection error)
			// status = ErrorCodes.DATA_CONNECTION;
			// if (some subnet problem)
			// status = ErrorCodes.KNX_CONNECTION;

			final byte[] buf = PacketHelper.toPacket(new ConnectionstateResponse(csr.getChannelID(), status));
			final DatagramPacket p = new DatagramPacket(buf, buf.length,
					createResponseAddress(csr.getControlEndpoint(), src, port, 0));
			s.send(p);
		}
		else if (svc == KNXnetIPHeader.CONNECTIONSTATE_RES)
			logger.warn("received connection state response - ignored");
		else if (PacketHelper.isKnxSecure(h)) {
			secure.acceptService(h, data, offset, src, port);
		}
		else {
			DataEndpointServiceHandler sh = null;
			try {
				// to get the channel id, we are just interested in connection header
				// which has the same layout for request and ack
				final int channelId = PacketHelper.getEmptyServiceRequest(h, data, offset).getChannelID();
				sh = findConnection(channelId);
			}
			catch (final KNXFormatException e) {}
			if (sh != null)
				return sh.handleDataServiceType(h, data, offset);
			return false;
		}
		return true;
	}

	private List<IndividualAddress> knxAddresses()
	{
		final List<IndividualAddress> addresses = new ArrayList<>();
		final int elems = server.getPropertyElems(KNXNETIP_PARAMETER_OBJECT, objectInstance(),
				PID.ADDITIONAL_INDIVIDUAL_ADDRESSES);
		try {
			final ByteBuffer buffer = ByteBuffer.wrap(server.getInterfaceObjectServer().getProperty(
					KNXNETIP_PARAMETER_OBJECT, objectInstance(), PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 1, elems));
			while (buffer.hasRemaining())
				addresses.add(new IndividualAddress(buffer.getShort() & 0xffff));
		}
		catch (final KnxPropertyException e) {}
		return addresses;
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
			ip = assignedIpAddresses().stream().filter(a -> a instanceof Inet4Address).findFirst().orElse(null);
			s.bind(new InetSocketAddress(ip, ep.getPort()));
			final InetSocketAddress boundTo = (InetSocketAddress) s.getLocalSocketAddress();
			logger.debug("{} control endpoint: socket bound to {}:{}", svcCont.getName(),
					boundTo.getAddress().getHostAddress(), boundTo.getPort());
			return s;
		}
		catch (SocketException | UnknownHostException e) {
			logger.error("socket creation failed for {}:{}", ip, ep.getPort(), e);
			throw wrappedException(e);
		}
	}

	private byte[] subnetMaskOf(final InetAddress addr)
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

	private List<InetAddress> assignedIpAddresses() throws SocketException, UnknownHostException
	{
		final NetworkInterface netif = NetworkInterface.getByName(svcCont.networkInterface());
		final List<InetAddress> list = netif != null ? Collections.list(netif.getInetAddresses())
				: Collections.singletonList(localHost());
		return list;
	}

	private InetAddress localHost() throws UnknownHostException
	{
		final long start = System.nanoTime();
		final InetAddress addr = InetAddress.getLocalHost();
		final long elapsed = System.nanoTime() - start;
		if (elapsed > 3_000_000_000L)
			logger.warn("slow local host resolution, took {} ms", elapsed / 1000 / 1000);
		return addr;
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

	private ConnectResponse initNewConnection(final ConnectRequest req, final InetSocketAddress ctrlEndpt,
		final InetSocketAddress dataEndpt, final int channelId)
	{
		// information about remote endpoint in case of error response
		final String endpoint = ctrlEndpt.toString();

		boolean tunnel = true;
		boolean busmonitor = false;
		IndividualAddress device = null;
		CRD crd = null;

		final int connType = req.getCRI().getConnectionType();
		if (connType == KNXnetIPTunnel.TUNNEL_CONNECTION) {

			final TunnelingLayer knxLayer;
			try {
				knxLayer = TunnelingLayer.from(((TunnelCRI) req.getCRI()).getKNXLayer());
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
				final List<DataEndpointServiceHandler> active = server.dataConnections.stream()
						.filter(h -> h.getCtrlSocketAddress().equals(s.getLocalSocketAddress()))
						.filter(h -> !h.isMonitor()).collect(Collectors.toList());
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
				final List<DataEndpointServiceHandler> active = activeMonitorConnections();
				if (active.size() > 0) {
					logger.warn("{}: connect request denied for tunneling on link-layer (active tunneling on "
							+ "busmonitor-layer connections)\n\tcurrently connected: {}", svcCont.getName(), active);
					return errorResponse(ErrorCodes.NO_MORE_CONNECTIONS, endpoint);
				}
			}

			device = assignDeviceAddress(svcCont.getMediumSettings().getDeviceAddress());
			if (device == null)
				return errorResponse(ErrorCodes.NO_MORE_CONNECTIONS, endpoint);
			final boolean isServerAddress = device.equals(serverAddress());
			logger.info("assign {} address {} to channel {}",
					isServerAddress ? "server device" : "additional individual", device, channelId);
			crd = new TunnelCRD(device);
		}
		else if (connType == KNXnetIPDevMgmt.DEVICE_MGMT_CONNECTION) {
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
			crd = CRD.createResponse(KNXnetIPDevMgmt.DEVICE_MGMT_CONNECTION, null);
		}
		else
			return errorResponse(ErrorCodes.CONNECTION_TYPE, endpoint);

		final ServiceLooper svcLoop;
		final DataEndpointServiceHandler sh;
		LooperThread looperThread = null;

		if (svcCont.reuseControlEndpoint()) {
			svcLoop = this;
			sh = new DataEndpointServiceHandler(s, getSocket(), ctrlEndpt, dataEndpt, channelId, device, tunnel,
					busmonitor, useNat, this::connectionClosed, this::resetRequest);
		}
		else {
			try {
				svcLoop = new DataEndpointService(server, s);

				final BiConsumer<DataEndpointServiceHandler, IndividualAddress> bc = (h, a) -> svcLoop.quit();
				sh = new DataEndpointServiceHandler(s, svcLoop.getSocket(), ctrlEndpt, dataEndpt, channelId, device,
						tunnel, busmonitor, useNat, bc.andThen(this::connectionClosed),
						((DataEndpointService) svcLoop)::resetRequest);
				((DataEndpointService) svcLoop).svcHandler = sh;

				looperThread = new LooperThread(server, svcCont.getName() + " data endpoint " + sh.getRemoteAddress(),
						0, () -> svcLoop);
			}
			catch (final RuntimeException e) {
				// we don't have any better error than NO_MORE_CONNECTIONS for this
				return errorResponse(ErrorCodes.NO_MORE_CONNECTIONS, endpoint);
			}
		}

		if (!acceptConnection(svcCont, sh, device, busmonitor)) {
			// don't use sh.close() here, we would initiate tunneling disconnect sequence
			// but we have to call svcLoop.quit() to close local data socket
			svcLoop.quit();
			freeDeviceAddress(device);
			return errorResponse(ErrorCodes.NO_MORE_CONNECTIONS, endpoint);
		}
		server.dataConnections.add(sh);
		if (looperThread != null)
			looperThread.start();
		if (!svcCont.reuseControlEndpoint())
			looperThreads.add(looperThread);

		// we always create our own HPAI from the socket, since the service container
		// might have opted for ephemeral port use
		final HPAI hpai = new HPAI(svcCont.getControlEndpoint().getHostProtocol(),
				(InetSocketAddress) svcLoop.getSocket().getLocalSocketAddress());
		return new ConnectResponse(channelId, ErrorCodes.NO_ERROR, hpai, crd);
	}

	private List<DataEndpointServiceHandler> activeMonitorConnections()
	{
		return server.dataConnections.stream().filter(h -> h.getCtrlSocketAddress().equals(s.getLocalSocketAddress()))
				.filter(DataEndpointServiceHandler::isMonitor).collect(Collectors.toList());
	}

	private ConnectResponse errorResponse(final int status, final String endpoint)
	{
		logger.warn("no data endpoint for remote endpoint " + endpoint + ", " + ErrorCodes.getErrorMessage(status));
		return new ConnectResponse(status);
	}

	// null return means no address available
	private IndividualAddress assignDeviceAddress(final IndividualAddress forSubnet)
	{
		final InterfaceObjectServer ios = server.getInterfaceObjectServer();
		// we assign our own KNX server device address iff:
		// - no unused additional addresses are available
		// - we don't run KNXnet/IP routing
		try {
			final int elems = server.getPropertyElems(KNXNETIP_PARAMETER_OBJECT, objectInstance(),
					PID.ADDITIONAL_INDIVIDUAL_ADDRESSES);
			for (int i = 0; i < elems; ++i) {
				final byte[] data = ios.getProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance(),
						PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, i + 1, 1);
				final IndividualAddress addr = new IndividualAddress(data);
				if (matchesSubnet(addr, forSubnet))
					if (checkAndSetDeviceAddress(addr, false))
						return addr;
			}
		}
		catch (final KnxPropertyException e) {
			logger.warn(e.getMessage());
		}
		// there are no free addresses, or no additional address at all
		logger.warn("no additional individual addresses available that matches subnet " + forSubnet);

		if (svcCont instanceof RoutingServiceContainer) {
			logger.warn("KNXnet/IP routing active, cannot assign server device address {}", serverAddress());
			return null;
		}

		final IndividualAddress addr = serverAddress();
		if (addr != null) {
			if (matchesSubnet(addr, forSubnet) && checkAndSetDeviceAddress(addr, true))
				return addr;
			logger.warn("server device address {} already assigned to data connection", addr);
		}
		return null;
	}

	private boolean matchesSubnet(final IndividualAddress addr, final IndividualAddress subnetMask)
	{
		boolean match = false;
		if (subnetMask == null)
			match = true;
		else if (subnetMask.getArea() == addr.getArea()) {
			// if we represent an area coupler, line is 0
			if (subnetMask.getLine() == 0 || subnetMask.getLine() == addr.getLine()) {
				// address does match the mask
				match = true;
			}
		}
		logger.trace("match additional address {} for KNX subnet {}: {}", addr, subnetMask, match ? "ok" : "no match");
		return match;
	}

	private boolean checkAndSetDeviceAddress(final IndividualAddress device, final boolean isServerAddress)
	{
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
	private static final Set<LooperThread> looperThreads = Collections.newSetFromMap(new WeakHashMap<>());

	static LooperThread findConnectionLooper(final int channelId) {
		for (final LooperThread t : looperThreads) {
			if (((DataEndpointService) t.getLooper()).svcHandler.getChannelId() == channelId)
				return t;
		}
		return null;
	}

	private DataEndpointServiceHandler findConnection(final int channelId)
	{
		for (final Iterator<DataEndpointServiceHandler> i = server.dataConnections.iterator(); i.hasNext();) {
			final DataEndpointServiceHandler c = i.next();
			if (c.getChannelId() == channelId)
				return c;
		}
		return null;
	}

	private int assignChannelId()
	{
		// Try to assign the new channel id by counting up from the last assigned channel
		// id. We do this to eventually assign the overall usable range of ids, and to
		// avoid excessive assignment of the low channel ids only.
		// We do not assign channel id 0.
		synchronized (channelIds) {
			int id = channelIds.nextClearBit(lastChannelId + 1);
			if (id == MAX_CHANNEL_ID + 1)
				id = channelIds.nextClearBit(1);
			// if all 255 ids are in use, no more connections are possible
			if (id == MAX_CHANNEL_ID + 1)
				return 0;
			channelIds.set(id);
			lastChannelId = id;
		}
		return lastChannelId;
	}

	private void freeChannelId(final int channelId)
	{
		synchronized (channelIds) {
			channelIds.clear(channelId);
		}
	}

	private boolean channelsAssigned()
	{
		synchronized (channelIds) {
			return channelIds.cardinality() > 0;
		}
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
