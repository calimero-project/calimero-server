/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2024 B. Malinowsky

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

import static tuwien.auto.calimero.server.knxnetip.ServiceLooper.hostPort;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.DeviceDescriptor.DD0;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.KnxRuntimeException;
import tuwien.auto.calimero.ReturnCode;
import tuwien.auto.calimero.ServiceType;
import tuwien.auto.calimero.baos.BaosService;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.cemi.CEMIBusMon;
import tuwien.auto.calimero.cemi.CEMIDevMgmt;
import tuwien.auto.calimero.cemi.CEMIFactory;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.device.ios.DeviceObject;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.KnxPropertyException;
import tuwien.auto.calimero.knxnetip.ConnectionBase;
import tuwien.auto.calimero.knxnetip.KNXConnectionClosedException;
import tuwien.auto.calimero.knxnetip.KNXnetIPConnection;
import tuwien.auto.calimero.knxnetip.servicetype.ConnectionstateRequest;
import tuwien.auto.calimero.knxnetip.servicetype.ConnectionstateResponse;
import tuwien.auto.calimero.knxnetip.servicetype.DisconnectResponse;
import tuwien.auto.calimero.knxnetip.servicetype.ErrorCodes;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.knxnetip.servicetype.PacketHelper;
import tuwien.auto.calimero.knxnetip.servicetype.ServiceAck;
import tuwien.auto.calimero.knxnetip.servicetype.ServiceRequest;
import tuwien.auto.calimero.knxnetip.servicetype.TunnelingFeature;
import tuwien.auto.calimero.knxnetip.servicetype.TunnelingFeature.InterfaceFeature;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.log.LogService.LogLevel;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.secure.SecurityControl;
import tuwien.auto.calimero.secure.SecurityControl.DataSecurity;
import tuwien.auto.calimero.server.knxnetip.SecureSessions.Session;

/**
 * Server-side implementation of KNX IP (secure) tunneling and device management protocol.
 *
 * @author B. Malinowsky
 */
public final class DataEndpoint extends ConnectionBase
{
	// sender SHALL wait 1 second for the acknowledgment response
	// to a tunneling request
	private static final int TUNNELING_REQ_TIMEOUT = 1;
	// sender SHALL wait 10 seconds for the acknowledgment response
	// to a device configuration request
	private static final int CONFIGURATION_REQ_TIMEOUT = 10;

	private final BiConsumer<DataEndpoint, IndividualAddress> connectionClosed;
	private final Consumer<DataEndpoint> resetRequest;

	private final IndividualAddress device;
	private final ConnectionType ctype;

	private volatile boolean shutdown;

	// updated on every correctly received message
	private long lastMsgTimestamp;

	private final SecureSessions sessions;
	private final int sessionId;

	private final boolean tcp;

	private final Instant connectedSince;

	// if enabled by client, notify client about changes of connection status and tunneling address
	private boolean featureInfoServiceEnabled;
	private boolean tunnelingAddressChanged;

	// ETS bug: ETS 6 wants the response sent to its src port the request got sent from,
	// even if indicated otherwise in the HPAI or required by the spec
	private volatile InetSocketAddress useDifferingEtsSrcPortForResponse;

	public enum ConnectionType {
		LinkLayer(KNXnetIPHeader.TUNNELING_REQ, KNXnetIPHeader.TUNNELING_ACK, 2, TUNNELING_REQ_TIMEOUT),
		Monitor(KNXnetIPHeader.TUNNELING_REQ, KNXnetIPHeader.TUNNELING_ACK, 2, TUNNELING_REQ_TIMEOUT),
		DevMgmt(KNXnetIPHeader.DEVICE_CONFIGURATION_REQ, KNXnetIPHeader.DEVICE_CONFIGURATION_ACK, 4, CONFIGURATION_REQ_TIMEOUT),
		Baos(KNXnetIPHeader.ObjectServerRequest, KNXnetIPHeader.ObjectServerAck, 2, TUNNELING_REQ_TIMEOUT);

		private final int req;
		private final int ack;
		private final int maxSendAttempts;
		private final int timeout;

		ConnectionType(final int req, final int ack, final int maxSendAttempts, final int timeout) {
			this.req = req;
			this.ack = ack;
			this.maxSendAttempts = maxSendAttempts;
			this.timeout = timeout;
		}
	}

	DataEndpoint(final DatagramSocket localCtrlEndpt, final DatagramSocket localDataEndpt,
		final InetSocketAddress remoteCtrlEndpt, final InetSocketAddress remoteDataEndpt, final int channelId,
		final IndividualAddress assigned, final ConnectionType type, final boolean useNAT,
		final SecureSessions sessions, final int sessionId,
		final BiConsumer<DataEndpoint, IndividualAddress> connectionClosed,
		final Consumer<DataEndpoint> resetRequest)
	{
		super(type.req, type.ack, type.maxSendAttempts, type.timeout);
		device = assigned;
		this.ctype = type;
		this.channelId = channelId;

		ctrlSocket = localCtrlEndpt;
		socket = localDataEndpt;

		ctrlEndpt = remoteCtrlEndpt;
		dataEndpt = remoteDataEndpt;

		useNat = useNAT;
		this.sessions = sessions;
		this.sessionId = sessionId;
		this.connectionClosed = connectionClosed;
		this.resetRequest = resetRequest;

		logger = LogService.getLogger("calimero.server.knxnetip." + name());

		tcp = TcpLooper.connections.containsKey(remoteDataEndpt);

		connectedSince = Instant.now().truncatedTo(ChronoUnit.SECONDS);

		if (sessionId > 0)
			sessions.addConnection(sessionId, remoteCtrlEndpt);

		updateLastMsgTimestamp();
		setState(OK);
	}

	@Override
	public void send(final CEMI frame, final BlockingMode mode)
		throws KNXTimeoutException, KNXConnectionClosedException, InterruptedException
	{
		checkFrameType(frame);
		if (TcpLooper.connections.containsKey(dataEndpt)) {
			super.send(frame, BlockingMode.NonBlocking);
			setStateNotify(OK);
		}
		else
			super.send(frame, mode);
	}

	@Override
	protected void send(final byte[] packet, final InetSocketAddress dst) throws IOException {
		byte[] buf = packet;
		if (sessionId > 0) {
			final Session session = sessions.sessions.get(sessionId);
			if (session == null) {
				close(CloseEvent.INTERNAL, "session " + sessionId + " got deallocated", LogLevel.INFO, null);
				return;
			}
			final long seq = session.sendSeq.get(); // don't increment send seq, this is just for logging
			buf = sessions.newSecurePacket(sessionId, packet);
			final int msgTag = 0;
			logger.trace("send session {} seq {} tag {} to {} {}", sessionId, seq, msgTag, ServiceLooper.hostPort(dst),
					DataUnitBuilder.toHex(buf, " "));
		}

		if (TcpLooper.send(buf, dst))
			return;

		final var actualDst = useDifferingEtsSrcPortForResponse != null ? useDifferingEtsSrcPortForResponse : dst;
		final DatagramPacket p = new DatagramPacket(buf, buf.length, actualDst);
		final var src = useNat || actualDst.equals(ctrlEndpt) ? ctrlSocket.getLocalSocketAddress() : socket.getLocalSocketAddress();
		logger.trace("send {}->{} {}", hostPort((InetSocketAddress) src),
				hostPort(actualDst), HexFormat.ofDelimiter(" ").formatHex(buf));

		if (useNat || actualDst.equals(ctrlEndpt))
			ctrlSocket.send(p);
		else
			socket.send(p);
	}

	public void send(final BaosService svc) throws KNXConnectionClosedException {
		try {
			final int chid = tcp ? 0 : channelId;
			final int seq = tcp ? 0 : getSeqSend();
			final var buf = PacketHelper.toPacket(new ServiceRequest<>(serviceRequest, chid, seq, svc));

			// NYI udp: we need a send method like for cEMI
			send(buf, dataEndpt);
		}
		catch (final IOException e) {
			close(CloseEvent.INTERNAL, "communication failure", LogLevel.ERROR, e);
			throw new KNXConnectionClosedException("connection closed", e);
		}
	}

	@Override
	public String name()
	{
		final String lock = new String(Character.toChars(0x1F512));
		final String prefix = "KNX IP " + (sessionId > 0 ? lock + " " : "");
		return prefix + ctype + " " + super.name();
	}

	@Override
	public String toString()
	{
		final String type = tcp ? "TCP" : useNat ? "UDP NAT" : "UDP";
		final var deviceAddress = device != null ? ", " + device : "";
		return "%s (%s, channel %d%s)".formatted(name(), type, getChannelId(), deviceAddress);
	}

	public IndividualAddress deviceAddress() { return device; }

	public Instant connectedSince() { return connectedSince; }

	@Override
	protected void close(final int initiator, final String reason, final LogLevel level, final Throwable t)
	{
		super.close(initiator, reason, level, t);
	}

	@Override
	protected void cleanup(final int initiator, final String reason, final LogLevel level, final Throwable t) {
		// we want close/shutdown be called only once
		synchronized (this) {
			if (shutdown)
				return;
			shutdown = true;
		}

		LogService.log(logger, level, "close connection for channel " + channelId + " - " + reason, t);
		connectionClosed.accept(this, device);
		super.cleanup(initiator, reason, level, t);

		if (sessionId > 0)
			sessions.removeConnection(sessionId);
	}

	void setSocket(final DatagramSocket socket) {
		this.socket = socket;
	}

	boolean handleDataServiceType(final InetSocketAddress src, final KNXnetIPHeader h, final byte[] data, final int offset) throws KNXFormatException, IOException
	{
		if (sessionId == 0)
			return acceptDataService(src, h, data, offset);

		if (TcpLooper.connections.containsKey(dataEndpt))
			return acceptDataService(src, h, data, offset);

		if (!h.isSecure()) {
			logger.warn("received non-secure packet {} - discard {}", h, DataUnitBuilder.toHex(data, " "));
			return true;
		}
		return sessions.acceptService(h, data, offset, dataEndpt, this);
	}

	private static final Function<ByteBuffer, BaosService> baosServiceParser = buf -> {
		try {
			return BaosService.from(buf);
		}
		catch (final KNXFormatException e) {
			throw new KnxRuntimeException("parsing baos service", e);
		}
	};

	boolean acceptDataService(final InetSocketAddress src, final KNXnetIPHeader h, final byte[] data, final int offset)
			throws KNXFormatException, IOException {
		final int svc = h.getServiceType();

		final boolean tunnel = ctype == ConnectionType.LinkLayer || ctype == ConnectionType.Monitor;
		final boolean configReq = svc == KNXnetIPHeader.DEVICE_CONFIGURATION_REQ;
		final boolean configAck = svc == KNXnetIPHeader.DEVICE_CONFIGURATION_ACK;

		if (tunnel && (configReq || configAck)) {
			final int recvChannelId = configReq ? ServiceRequest.from(h, data, offset).getChannelID()
					: new ServiceAck(svc, data, offset).getChannelID();
			if (recvChannelId == channelId)
				return false;
			final int localPort = socket.getLocalPort();
			logger.error("ETS 5 sends configuration requests for channel {} to wrong UDP port {} (channel {}), "
					+ "try to find correct connection", recvChannelId, localPort, channelId);
			final Optional<DataEndpointService> dataEndpointService = ControlEndpointService.findDataEndpoint(recvChannelId);
			if (dataEndpointService.isPresent()) {
				dataEndpointService.get().rebindSocket(localPort);
				dataEndpointService.get().svcHandler.acceptDataService(src, h, data, offset);
			}
			return true;
		}

		final String type = tunnel ? "tunneling" : "device configuration";
		if (svc == serviceRequest || svc == KNXnetIPHeader.TunnelingFeatureGet || svc == KNXnetIPHeader.TunnelingFeatureSet) {

			final var req = svc == KNXnetIPHeader.ObjectServerRequest
					? ServiceRequest.from(h, data, offset, baosServiceParser)
					: ServiceRequest.from(h, data, offset);

			if (!checkChannelId(req.getChannelID(), "request"))
				return true;

			final int seq = req.getSequenceNumber();
			final int status = checkVersion(h) ? ErrorCodes.NO_ERROR : ErrorCodes.VERSION_NOT_SUPPORTED;
			if (tcp)
				; // no-op
			else if (seq == getSeqRcv() || (tunnel && ((seq + 1) & 0xFF) == getSeqRcv())) {
				final byte[] buf = PacketHelper.toPacket(new ServiceAck(serviceAck, channelId, seq, status));
				send(buf, etsDstHack(dataEndpt, src));
			}
			else {
				logger.warn(type + " request with invalid receive sequence " + seq + ", expected " + getSeqRcv() + " - ignored");
				return true;
			}

			if (status == ErrorCodes.VERSION_NOT_SUPPORTED) {
				close(CloseEvent.INTERNAL, "protocol version changed", LogLevel.ERROR, null);
				return true;
			}

			if (tcp || seq == getSeqRcv()) {
				incSeqRcv();
				updateLastMsgTimestamp();

				if (svc == KNXnetIPHeader.TunnelingFeatureGet || svc == KNXnetIPHeader.TunnelingFeatureSet) {
					respondToFeature(src, h, data, offset);
					if (tunnelingAddressChanged) {
						tunnelingAddressChanged = false;
						sendFeatureInfo(InterfaceFeature.IndividualAddress, device.toByteArray());
					}
					return true;
				}
				if (svc == KNXnetIPHeader.ObjectServerRequest) {
					final var baosService = (BaosService) req.service();
					checkNotifyBaosService(baosService);
					return true;
				}

				final CEMI cemi = req.service();
				if (tunnel)
					checkNotifyTunnelingCEMI(cemi);
				else
					checkNotifyConfigurationCEMI(cemi);
			}
		}
		else if (svc == serviceAck) {
			final ServiceAck res = new ServiceAck(svc, data, offset);
			if (!checkChannelId(res.getChannelID(), "acknowledgment"))
				return true;

			if (res.getSequenceNumber() != getSeqSend())
				logger.warn("received " + type + " acknowledgment with wrong send-sequence " + res.getSequenceNumber() + ", expected "
						+ getSeqSend() + " - ignored");
			else {
				if (!checkVersion(h)) {
					close(CloseEvent.INTERNAL, "protocol version changed", LogLevel.ERROR, null);
					return true;
				}
				incSeqSend();
				updateLastMsgTimestamp();

				// update state and notify our lock
				setStateNotify(res.getStatus() == ErrorCodes.NO_ERROR ? OK : ACK_ERROR);
				if (logger.isTraceEnabled())
					logger.trace("received service ack {} from " + ServiceLooper.hostPort(ctrlEndpt) + " (channel "
							+ channelId + ")", res.getSequenceNumber());
				if (internalState == ACK_ERROR)
					logger.warn("received service acknowledgment status " + res.getStatusString());
			}
		}
		else if (svc == KNXnetIPHeader.CONNECTIONSTATE_REQ) {
			// For some weird reason (or no reason, because it's not in the spec), ETS sends a
			// connection-state.req from its data endpoint to our data endpoint immediately after
			// a new connection was established.
			// It expects it to be answered by the control endpoint (!), so do that here.
			// If we ignore that connection-state.req, the ETS connection establishment
			// gets delayed by the connection-state.res timeout.
			final ConnectionstateRequest csr = new ConnectionstateRequest(data, offset);
			int status = checkVersion(h) ? ErrorCodes.NO_ERROR : ErrorCodes.VERSION_NOT_SUPPORTED;
			if (status == ErrorCodes.NO_ERROR && csr.getControlEndpoint().hostProtocol() != HPAI.IPV4_UDP) status = ErrorCodes.HOST_PROTOCOL_TYPE;

			if (status == ErrorCodes.NO_ERROR) {
				logger.trace("data endpoint received connection-state request (channel {}) from {}",
						csr.getChannelID(), hostPort(dataEndpt));
				updateLastMsgTimestamp();
				status = subnetStatus();
			}
			else
				logger.warn("received invalid connection-state request (channel {}) from {}: {}",
						csr.getChannelID(), hostPort(dataEndpt), ErrorCodes.getErrorMessage(status));

			final byte[] buf = PacketHelper.toPacket(new ConnectionstateResponse(csr.getChannelID(), status));
			final var dst = etsDstHack(csr.getControlEndpoint().endpoint(), src);
			send(buf, dst);
		}
		else
			return false;
		return true;
	}

	void disconnectResponse(final DisconnectResponse res) {
		if (res.getStatus() != ErrorCodes.NO_ERROR)
			logger.warn("received disconnect response status 0x{} ({})",
					Integer.toHexString(res.getStatus()), ErrorCodes.getErrorMessage(res.getStatus()));
		finishClosingNotify();
	}

	private void respondToFeature(final InetSocketAddress src, final KNXnetIPHeader h, final byte[] data, final int offset)
			throws KNXFormatException, IOException {
		final ByteBuffer buffer = ByteBuffer.wrap(data, offset, h.getTotalLength() - h.getStructLength());
		final TunnelingFeature res = responseForFeature(h, buffer);
		logger.debug("respond with {}", res);

		final var dst = etsDstHack(dataEndpt, src);
		send(PacketHelper.toPacket(new ServiceRequest<>(res.type(), channelId, getSeqSend(), res)), dst);
	}

	private TunnelingFeature responseForFeature(final KNXnetIPHeader h, final ByteBuffer buffer) throws KNXFormatException {
		// NYI detect data type conflict (wrong sized value) and respond with ReturnCode.DataTypeConflict
		final var req = ServiceRequest.from(h, buffer.array(), buffer.position());
		final TunnelingFeature feat = req.service();
		logger.debug("received {}", feat);

		final int svc = h.getServiceType();
		if (svc == KNXnetIPHeader.TunnelingFeatureGet) {
			return switch (feat.featureId()) {
				case SupportedEmiTypes -> responseForFeature(feat, (byte) 0, (byte) 0x04); // only cEMI (see EmiType.CEmi)
				case IndividualAddress -> responseForFeature(feat, device.toByteArray());
				case MaxApduLength -> responseForFeature(feat, (byte) 0, (byte) maxApduLength());
				case DeviceDescriptorType0 -> responseForFeature(feat, DD0.TYPE_091A.toByteArray());
				case ConnectionStatus -> responseForFeature(feat, (byte) (subnetStatus() == ErrorCodes.NO_ERROR ? 1 : 0));
				case Manufacturer -> responseForFeature(feat, (byte) 0, (byte) 0);
				case ActiveEmiType -> responseForFeature(feat, (byte) 0x03); // always cEMI (see KnxTunnelEmi.CEmi)
				case EnableFeatureInfoService -> responseForFeature(feat, (byte) (featureInfoServiceEnabled ? 1 : 0));
			};
		}
		else if (svc == KNXnetIPHeader.TunnelingFeatureSet) {
			final byte[] value = feat.featureValue().get();
			// write access to IA is only permitted if connection is not secured
			if (feat.featureId() == InterfaceFeature.IndividualAddress && sessionId == 0) {
				final ReturnCode result = updateTunnelingAddress(value) ? ReturnCode.Success : ReturnCode.DataVoid;
				return responseForFeature(feat, result, value);
			}
			else if (feat.featureId() == InterfaceFeature.EnableFeatureInfoService) {
				if (value[0] != 0 && value[0] != 1)
					return responseForFeature(feat, ReturnCode.OutOfMaxRange, value);
				featureInfoServiceEnabled = value[0] == 1;
				return responseForFeature(feat, value);
			}

			return responseForFeature(feat, ReturnCode.AccessReadOnly, value);
		}

		logger.warn("unknown or unsupported: {} {}", Integer.toHexString(svc), feat);
		return responseForFeature(feat, ReturnCode.AddressVoid);
	}

	private static TunnelingFeature responseForFeature(final TunnelingFeature req, final byte... featureValue) {
		return responseForFeature(req, ReturnCode.Success, featureValue);
	}

	private static TunnelingFeature responseForFeature(final TunnelingFeature req, final ReturnCode rc,
			final byte... featureValue) {
		return TunnelingFeature.newResponse(req.featureId(), rc, featureValue);
	}

	private boolean updateTunnelingAddress(final byte[] value) {
		final IndividualAddress ia = new IndividualAddress(value);
		if (!device.equals(ia)) {
			if (serverAddress().equals(ia) || additionalAddresses().contains(ia))
				return false;
			// NYI update tunneling address
		}
		tunnelingAddressChanged = true;
		return true;
	}

	private int subnetStatus() {
		final var endpoints = ControlEndpointService.findDataEndpoint(channelId).map(ep -> ep.server.endpoints)
				.orElse(List.of());
		for (final var endpoint : endpoints) {
			final Optional<ControlEndpointService> looper = endpoint.controlEndpoint();
			if (looper.isPresent()) {
				final ControlEndpointService ces = looper.get();
				if (ces.addressInUse(device))
					return ces.subnetStatus();
			}
		}
		return ErrorCodes.KNX_CONNECTION;
	}

	private int maxApduLength() {
		final Optional<DataEndpointService> dataEndpoint = ControlEndpointService.findDataEndpoint(channelId);
		if (dataEndpoint.isPresent()) {
			try {
				return DeviceObject.lookup(dataEndpoint.get().server.getInterfaceObjectServer()).maxApduLength();
			}
			catch (final KnxPropertyException ignore) {}
		}
		return 15;
	}

	private IndividualAddress serverAddress() {
		final Optional<DataEndpointService> dataEndpoint = ControlEndpointService.findDataEndpoint(channelId);
		int addr = 0;
		if (dataEndpoint.isPresent())
			addr = dataEndpoint.get().server.getProperty(InterfaceObject.DEVICE_OBJECT, 1, PID.KNX_INDIVIDUAL_ADDRESS, 1, 0);
		return new IndividualAddress(addr);
	}

	private List<IndividualAddress> additionalAddresses() {
		final var endpoints = ControlEndpointService.findDataEndpoint(channelId)
				.map(ep -> ep.server.endpoints).orElse(List.of());
		for (final var endpoint : endpoints) {
			final Optional<ControlEndpointService> looper = endpoint.controlEndpoint();
			if (looper.isPresent()) {
				return looper.get().additionalAddresses();
			}
		}
		return List.of();
	}

	void mediumConnectionStatusChanged(final boolean active) {
		sendFeatureInfo(InterfaceFeature.ConnectionStatus, (byte) (active ? 1 : 0));
	}

	private void sendFeatureInfo(final InterfaceFeature id, final byte... value) {
		if (featureInfoServiceEnabled) {
			final TunnelingFeature info = TunnelingFeature.newInfo(id, value);
			logger.debug("send {}", info);
			try {
				send(PacketHelper.toPacket(new ServiceRequest<>(info.type(), channelId, getSeqSend(), info)), dataEndpt);
			}
			catch (final IOException e) {
				logger.error("sending {}", info, e);
			}
		}
	}

	void updateLastMsgTimestamp()
	{
		lastMsgTimestamp = System.currentTimeMillis();
	}

	long getLastMsgTimestamp()
	{
		return lastMsgTimestamp;
	}

	int getChannelId()
	{
		return channelId;
	}

	boolean isDeviceMgmt()
	{
		return ctype == ConnectionType.DevMgmt;
	}

	public ConnectionType type() { return ctype; }

	private boolean checkVersion(final KNXnetIPHeader h)
	{
		if (h.getVersion() != protocolVersion())
			logger.warn("KNXnet/IP " + (h.getVersion() >> 4) + "." + (h.getVersion() & 0xf) + " "
					+ ErrorCodes.getErrorMessage(ErrorCodes.VERSION_NOT_SUPPORTED));
		return h.getVersion() == protocolVersion();
	}

	int protocolVersion() {
		return ctype == ConnectionType.Baos ? 0x20 : KNXnetIPConnection.KNXNETIP_VERSION_10;
	}

	private void checkNotifyTunnelingCEMI(final CEMI cemi)
	{
		final int mc = cemi.getMessageCode();
		if (ctype == ConnectionType.Monitor)
			logger.warn("client is not allowed to send cEMI messages in busmonitor mode - ignored");
		else if (mc == CEMILData.MC_LDATA_REQ) {
			CEMILData ldata = (CEMILData) cemi;
			if (ldata.getSource().equals(new IndividualAddress(0)))
				ldata = CEMIFactory.create(device, ldata.getDestination(), ldata, false);
			fireFrameReceived(ldata);
		}
		else if (mc == CEMIDevMgmt.MC_RESET_REQ) {
			fireFrameReceived(cemi);
			resetRequest.accept(this);
		}
		else {
			logger.warn(switch (mc) {
				case CEMILData.MC_LDATA_CON -> "received L-Data confirmation - ignored";
				case CEMILData.MC_LDATA_IND -> "received L-Data indication - ignored";
				case CEMIBusMon.MC_BUSMON_IND -> "received L-Busmon indication - ignored";
				default -> "unsupported cEMI message code " + mc + " - ignored";
			});
		}
	}

	private void checkNotifyConfigurationCEMI(final CEMI cemi)
	{
		if (cemi.getMessageCode() == CEMIDevMgmt.MC_PROPREAD_REQ
				|| cemi.getMessageCode() == CEMIDevMgmt.MC_PROPWRITE_REQ
				|| cemi.getMessageCode() == CEMIDevMgmt.MC_FUNCPROP_CMD_REQ
				|| cemi.getMessageCode() == CEMIDevMgmt.MC_FUNCPROP_READ_REQ
				|| cemi.getMessageCode() == CEMIDevMgmt.MC_RESET_REQ) {
			fireDeviceMgmtFrameReceived(cemi);
			if (cemi.getMessageCode() == CEMIDevMgmt.MC_RESET_REQ)
				resetRequest.accept(this);
		}
		else {
			switch (cemi.getMessageCode()) {
				case CEMIDevMgmt.MC_PROPREAD_CON -> logger.warn("received property read confirmation - ignored");
				case CEMIDevMgmt.MC_PROPWRITE_CON -> logger.warn("received property write confirmation - ignored");
				case CEMIDevMgmt.MC_PROPINFO_IND -> logger.warn("received property info indication - ignored");
				case CEMIDevMgmt.MC_RESET_IND -> logger.warn("received reset indication - ignored");
				default -> logger.warn("unsupported cEMI message code 0x" + Integer.toHexString(cemi.getMessageCode()) + " - ignored");
			}
		}
	}

	// with cEMI device mgmt we have to adjust security control for frame event
	private void fireDeviceMgmtFrameReceived(final CEMI frame) {
		final var securityControl = sessionId == 0 ? SecurityControl.Plain
				: SecurityControl.of(DataSecurity.AuthConf, true);
		final FrameEvent fe = new FrameEvent(this, frame, false, securityControl);
		listeners.fire(l -> l.frameReceived(fe));
	}

	private void checkNotifyBaosService(final BaosService svc) {
		if (svc.subService() == BaosService.DatapointValueIndication
				|| svc.subService() == BaosService.ServerItemIndication || svc.isResponse()) {
			logger.warn("unsupported baos service {}", svc);
			return;
		}
		final FrameEvent fe = new FrameEvent(this, svc.toByteArray());
		listeners.fire(l -> l.frameReceived(fe));
	}

	private void checkFrameType(final CEMI frame)
	{
		if (ctype == ConnectionType.LinkLayer && !(frame instanceof CEMILData))
			throw new KNXIllegalArgumentException("link layer requires cEMI L-Data frame type");

		if (ctype == ConnectionType.Monitor && !(frame instanceof CEMIBusMon))
			throw new KNXIllegalArgumentException("bus monitor requires cEMI bus monitor frame type");

		if (ctype == ConnectionType.DevMgmt && !(frame instanceof CEMIDevMgmt))
			throw new KNXIllegalArgumentException("expect cEMI device management frame type");
	}

	// ETS bug: ETS 6 wants the response sent to its src port the request got sent from,
	// even if indicated otherwise in the HPAI or required by the spec
	private InetSocketAddress etsDstHack(final InetSocketAddress correct, final InetSocketAddress actual) {
		// we ignore any attempt to respond to a different IP address
		if (!actual.getAddress().equals(correct.getAddress()))
			return correct;
		if (actual.getPort() == correct.getPort())
			return correct;
		logger.debug("[ETS] respond to different port {} (data endpoint was setup for {})", actual.getPort(), correct.getPort());
		useDifferingEtsSrcPortForResponse = actual;
		return actual;
	}
}
