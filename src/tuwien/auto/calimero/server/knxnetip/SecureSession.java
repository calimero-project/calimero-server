/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2018, 2019 B. Malinowsky

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

import static tuwien.auto.calimero.DataUnitBuilder.toHex;

import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.XECPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KnxPropertyException;
import tuwien.auto.calimero.knxnetip.KNXnetIPDevMgmt;
import tuwien.auto.calimero.knxnetip.KnxSecureException;
import tuwien.auto.calimero.knxnetip.SecureConnection;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;

/** Secure sessions container for KNX IP secure unicast connections. */
class SecureSession {

	private static final int SecureSvc = 0x0950;
	private static final int SessionReq = 0x0951; // 1. client -> server
	private static final int SessionRes = 0x0952; // 2. server -> client
	private static final int SessionAuth = 0x0953; // 3. client -> server
	private static final int SessionStatus = 0x0954; // 4. server -> client


	private static final int macSize = 16; // [bytes]
	private static final int keyLength = 32; // [bytes]

	private final DatagramSocket socket;
	private final Logger logger;

	static final int pidDeviceAuth = 92; // PDT generic 16
	static final int pidUserPwdHashes = 93; // PDT generic 16
	static final int pidSecuredServices = 94;
	static final int pidLatencyTolerance = 95;
	static final int pidSyncLatencyTolerance = 96;

	static final byte[] emptyPwdHash = { (byte) 0xe9, (byte) 0xc3, 0x04, (byte) 0xb9, 0x14, (byte) 0xa3, 0x51, 0x75, (byte) 0xfd,
		0x7d, 0x1c, 0x67, 0x3a, (byte) 0xb5, 0x2f, (byte) 0xe1 };

	private final InterfaceObjectServer ios;
	private final int objectInstance;

	private final byte[] sno;
	private final Key deviceAuthKey;

	private static AtomicLong sessionCounter = new AtomicLong();

	static final class Session {
		final AtomicLong sendSeq = new AtomicLong();

		private final AtomicLong connectionCount = new AtomicLong();
		private final InetSocketAddress client;
		private final Key secretKey;

		volatile long lastUpdate = System.nanoTime() / 1_000_000;
		byte[] serverKey;
		byte[] clientKey;
		int userId;

		private Session(final int sessionId, final InetSocketAddress client, final Key secretKey) {
			this.client = client;
			this.secretKey = secretKey;
		}
	}
	final Map<Integer, Session> sessions = new ConcurrentHashMap<>();


	SecureSession(final ControlEndpointService ctrlEndpoint) {
		socket = ctrlEndpoint.getSocket();
		final String lock = new String(Character.toChars(0x1F512));
		final String name = ctrlEndpoint.getServiceContainer().getName();
		logger = LoggerFactory.getLogger("calimero.server.knxnetip." + name + ".KNX IP " + lock + " Session");
		ios = ctrlEndpoint.server.getInterfaceObjectServer();
		objectInstance = ctrlEndpoint.server.objectInstance(ctrlEndpoint.getServiceContainer());
		sno = deriveSerialNumber(ctrlEndpoint.getSocket().getLocalAddress());
		deviceAuthKey = deviceAuthKey();
	}

	boolean acceptService(final KNXnetIPHeader h, final byte[] data, final int offset, final InetSocketAddress remote,
		final Object svcHandler) throws KNXFormatException, IOException {

		int sessionId = 0;
		try {
			if (h.getServiceType() == SessionReq) {
				final ByteBuffer res = establishSession(remote, h, data, offset);
				send(res.array(), remote);
				final int size = sessions.size();
				logger.trace("{} session{} currently open {}", size, size == 1 ? "" : "s", sessions.keySet());
				return true;
			}
			if (h.getServiceType() == SecureSvc) {
				sessionId = ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
				final Session session = sessions.get(sessionId);
				if (session == null) {
					logger.warn("reject secure service with invalid session ID {}", sessionId);
					return true;
				}
				final Key secretKey = session.secretKey;
				final Object[] fields = SecureConnection.unwrap(h, data, offset, secretKey);
				final int sid = (int) fields[0];
				final long seq = (long) fields[1];
				final long sno = (long) fields[2];
				final int tag = (int) fields[3];
				final byte[] knxipPacket = (byte[]) fields[4];

				final KNXnetIPHeader svcHeader = new KNXnetIPHeader(knxipPacket, 0);
				logger.debug("received session {} seq {} (S/N {} tag {}) {}: {}", sid, seq, sno, tag, svcHeader,
						toHex(knxipPacket, " "));
				session.lastUpdate = System.nanoTime() / 1_000_000L;

				if (svcHeader.getServiceType() == SessionAuth) {
					int status = AuthFailed;
					// we only authenticate if that didn't happen before, otherwise we fail and remove session
					if (session.userId == 0) {
						try {
							sessionAuth(session, knxipPacket, 6);
							status = AuthSuccess;
							logger.debug("client {} authorized for session {} with user ID {}", session.client,
									sessionId, session.userId);
						}
						catch (final KnxSecureException e) {
							logger.info("secure session {}: {}", sessionId, e.getMessage());
						}
					}
					sendStatusInfo(sessionId, session.sendSeq.getAndIncrement(), status, remote);
					if (status == AuthFailed)
						sessions.remove(sessionId);
				}
				else if (svcHeader.getServiceType() == SessionStatus) {
					final int status = sessionStatus(svcHeader, knxipPacket, svcHeader.getStructLength());
					logger.info("secure session {}: {}", sid, statusMsg(status));
					if (status == Close)
						closeSession(sessionId, session);
					else if (status == KeepAlive) {
						// check unauthenticated case
						if (session.userId == 0) {
							sendStatusInfo(sessionId, session.sendSeq.getAndIncrement(), Unauthorized, remote);
							sessions.remove(sessionId);
							return true;
						}
						// a valid keep-alive is a no-op, because session timestamp got already updated
					}
				}
				else {
					if (session.userId == 0) {
						sendStatusInfo(sessionId, session.sendSeq.getAndIncrement(), Unauthorized, remote);
						// TODO close all secure connections of this session
						sessions.remove(sessionId);
						return true;
					}
					// forward to service handler
					final int start = svcHeader.getStructLength();
					if (svcHandler instanceof ControlEndpointService) {
						if (svcHeader.getServiceType() == KNXnetIPHeader.CONNECT_REQ) {
							connections.put(remote, sessionId);
						}
						final ControlEndpointService ces = (ControlEndpointService) svcHandler;
						return ces.acceptControlService(sessionId, svcHeader, knxipPacket, start, remote.getAddress(), remote.getPort());
					}
					else
						return ((DataEndpointServiceHandler) svcHandler).acceptDataService(svcHeader, knxipPacket, start);
				}
				return true;
			}
		}
		catch (KnxSecureException | KnxPropertyException e) {
			logger.error("error processing {}, {}", h, e.getMessage());
			if (sessionId > 0)
				sendStatusInfo(sessionId, 0, Unauthorized, remote);
			return true;
		}
		return false;
	}

	// temporary
	private final Map<InetSocketAddress, Integer> connections = new ConcurrentHashMap<>();

	int registerConnection(final int connType, final InetSocketAddress ctrlEndpt, final int channelId) {
		final int sid = connections.getOrDefault(ctrlEndpt, 0);
		// only session with user id 1 has proper access level for management access
		if (connType == KNXnetIPDevMgmt.DEVICE_MGMT_CONNECTION && sid > 0 && sessions.get(sid).userId > 1) {
			logger.warn("refuse management connection to user {}", sessions.get(sid).userId);
			return 0;
		}
		return sid;
	}

	void addConnection(final int sessionId, final InetSocketAddress remoteCtrlEp) {
		final Session session = sessions.get(sessionId);
		if (session != null) {
			connections.remove(remoteCtrlEp);
			session.connectionCount.incrementAndGet();
		}
	}

	void removeConnection(final int sessionId) {
		final Session session = sessions.get(sessionId);
		if (session != null && session.connectionCount.decrementAndGet() <= 0) {
			logger.debug("remove secure session {}", sessionId);
			sessions.remove(sessionId);
		}
	}

	boolean anyMatch(final InetSocketAddress remoteEndpoint) {
		for (final Entry<Integer, Session> entry : sessions.entrySet()) {
			if (entry.getValue().client.equals(remoteEndpoint))
				return true;
		}
		return false;
	}

	private void send(final byte[] data, final InetSocketAddress address) throws IOException {
		if (!TcpLooper.send(data, address))
			socket.send(new DatagramPacket(data, data.length, address));
	}

	private ByteBuffer establishSession(final InetSocketAddress remote, final KNXnetIPHeader h, final byte[] data, final int offset) {

		final byte[] clientKey = Arrays.copyOfRange(data, offset + 8, h.getTotalLength());
		final byte[] publicKey;
		final byte[] sharedSecret;

		try {
			final KeyPair keyPair = generateKeyPair();
			final BigInteger u = ((XECPublicKey) keyPair.getPublic()).getU();
			publicKey = u.toByteArray();
			reverse(publicKey);
			sharedSecret = keyAgreement(keyPair.getPrivate(), clientKey);
		}
		catch (final Throwable e) {
			throw new KnxSecureException("error creating secure session keys for " + remote, e);
		}

		final Key secretKey = createSecretKey(sessionKey(sharedSecret));

		final int sessionId = newSessionId();
		final Session session = new Session(sessionId, remote, secretKey);
		session.serverKey = publicKey;
		session.clientKey = clientKey;
		sessions.put(sessionId, session);
		logger.debug("establish secure session {} for {}", sessionId, remote);

		return sessionResponse(sessionId, publicKey, clientKey);
	}

	private ByteBuffer sessionResponse(final int sessionId, final byte[] publicKey, final byte[] clientPublicKey) {
		final int len = sessionId == 0 ? 8 : 0x38;
		final ByteBuffer buf = ByteBuffer.allocate(len);
		buf.put(new KNXnetIPHeader(SessionRes, len - 6).toByteArray());
		buf.putShort((short) sessionId);
		if (sessionId == 0)
			return buf;

		final int msgLen = buf.position() + keyLength;
		final ByteBuffer macInput = ByteBuffer.allocate(16 + 2 + msgLen);
		macInput.put(new byte[16]);
		macInput.put((byte) 0);
		macInput.put((byte) msgLen);
		macInput.put(buf.array(), 0, buf.position());
		macInput.put(xor(publicKey, 0, clientPublicKey, 0, keyLength));
		final byte[] mac = cbcMacSimple(deviceAuthKey, macInput.array(), 0, macInput.capacity());
		encrypt(mac, deviceAuthKey);

		buf.put(publicKey);
		buf.put(mac);
		return buf;
	}

	// TODO user-Level access should not allow mgmt connections (user id > 1)
	// TODO check if user 1 is already in use
	private void sessionAuth(final Session session, final byte[] data, final int offset) {
		final ByteBuffer buffer = ByteBuffer.wrap(data, offset, data.length - offset);
		final int userId = buffer.getShort() & 0xffff;
		if (userId < 1 || userId > 0x7F)
			throw new KnxSecureException("user " + userId + " out of range [1..127]");

		final byte[] mac = new byte[macSize];
		buffer.get(mac);

		final int msgLen = 6 + 2 + keyLength;
		final ByteBuffer macInput = ByteBuffer.allocate(16 + 2 + msgLen);
		macInput.put(new byte[16]);
		macInput.put((byte) 0);
		macInput.put((byte) msgLen);
		macInput.put(data, 0, 6 + 2);
		macInput.put(xor(session.serverKey, 0, session.clientKey, 0, keyLength));
		final Key userPwdHash = userPwdHash(userId);
		final byte[] verifyAgainst = cbcMacSimple(userPwdHash, macInput.array(), 0, macInput.capacity());
		encrypt(verifyAgainst, userPwdHash);

		final boolean authenticated = Arrays.equals(mac, verifyAgainst);
		if (!authenticated) {
			final String packet = toHex(Arrays.copyOfRange(data, offset - 6, offset - 6 + 0x18), " ");
			throw new KnxSecureException("authentication failed for user " + userId + ", auth " + packet);
		}

		session.userId = userId;
	}

	private void sendStatusInfo(final int sessionId, final long seq, final int status, final InetSocketAddress address) {
		try {
			final byte[] packet = statusInfo(sessionId, seq, status);
			send(packet, address);
		}
		catch (IOException | RuntimeException e) {
			logger.error("sending session {} status {} to {}", sessionId, statusMsg(status), address, e);
		}
	}

	private byte[] statusInfo(final int sessionId, final long seq, final int status) {
		final ByteBuffer packet = ByteBuffer.allocate(6 + 2);
		packet.put(new KNXnetIPHeader(SessionStatus, 2).toByteArray());
		packet.put((byte) status);
		final int msgTag = 0;
		return newSecurePacket(sessionId, seq, msgTag, packet.array());
	}

	private int sessionStatus(final KNXnetIPHeader h, final byte[] data, final int offset) throws KNXFormatException {
		if (h.getServiceType() != SessionStatus)
			throw new KNXIllegalArgumentException("no secure session status");
		if (h.getTotalLength() != 8)
			throw new KNXFormatException("invalid length " + h.getTotalLength() + " for secure session status");

		final int status = data[offset] & 0xff;
		return status;
	}

	// session status is one of:
	private static final int AuthSuccess = 0;
	private static final int AuthFailed = 1;
	private static final int Unauthorized = 2;
	private static final int Timeout = 3;
	private static final int KeepAlive = 4;
	private static final int Close = 5;

	private static String statusMsg(final int status) {
		final String[] msg = { "authorization success", "authorization failed", "unauthorized", "timeout", "keep-alive",
			"close" };
		if (status >= msg.length)
			return "unknown status " + status;
		return msg[status];
	}

	private static final Duration sessionTimeout = Duration.ofSeconds(60);

	void closeDormantSessions() {
		sessions.forEach(this::checkSessionTimeout);
	}

	// if we don't receive a valid secure packet for 60 seconds, we close the session (and any open connections)
	private void checkSessionTimeout(final int sessionId, final Session session) {
		final long now = System.nanoTime() / 1_000_000;
		final Duration dormant = Duration.ofMillis(now - session.lastUpdate);
		if (dormant.compareTo(sessionTimeout) > 0) {
			logger.info("secure session {} timed out after {} seconds - close session", sessionId, dormant.toSeconds());
			sessionTimeout(sessionId, session);
		}
	}

	private void sessionTimeout(final int sessionId, final Session session) {
		final long seq = session.sendSeq.getAndIncrement();
		sendStatusInfo(sessionId, (int) seq, Timeout, session.client);
		// TODO remove all secure client connections of this session
		sessions.remove(sessionId);
		TcpLooper.lastSessionTimedOut(session.client);
	}

	private void closeSession(final int sessionId, final Session session) {
		// TODO remove all secure client connections of this session, without notifying client
		final long seq = session.sendSeq.getAndIncrement();
		sendStatusInfo(sessionId, (int) seq, Close, session.client);
		sessions.remove(sessionId);
	}

	private Key deviceAuthKey() {
		try {
			return createSecretKey(ios.getProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance, pidDeviceAuth, 1, 1));
		}
		catch (final KnxPropertyException e) {
			final byte[] key = new byte[16];
			new SecureRandom().nextBytes(key);
			return createSecretKey(key);
		}
	}

	private Key userPwdHash(final int userId) {
		return createSecretKey(ios.getProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, objectInstance, pidUserPwdHashes, userId, 1));
	}

	byte[] newSecurePacket(final int sessionId, final long seq, final int msgTag, final byte[] knxipPacket) {
		final Key secretKey = sessions.get(sessionId).secretKey;
		return SecureConnection.newSecurePacket(sessionId, seq, sno, msgTag, knxipPacket, secretKey);
	}

	byte[] newSecurePacket(final int sessionId, final byte[] knxipPacket) {
		final long seq = sessions.get(sessionId).sendSeq.getAndIncrement();
		final int msgTag = 0;
		return newSecurePacket(sessionId, seq, msgTag, knxipPacket);
	}

	private void encrypt(final byte[] mac, final Key secretKey) {
		SecureConnection.encrypt(mac, 0, secretKey, securityInfo(new byte[16], 0, 0xff00));
	}

	private byte[] cbcMacSimple(final Key secretKey, final byte[] data, final int offset, final int length) {
		final byte[] log = Arrays.copyOfRange(data, offset, offset + length);
		logger.trace("authenticating (length {}): {}", length, toHex(log, " "));

		try {
			final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			final IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

			final byte[] padded = Arrays.copyOfRange(data, offset, (length + 15) / 16 * 16);
			final byte[] result = cipher.doFinal(padded);
			final byte[] mac = Arrays.copyOfRange(result, result.length - macSize, result.length);
			return mac;
		}
		catch (final GeneralSecurityException e) {
			throw new KnxSecureException("calculating CBC-MAC of " + toHex(log, " "), e);
		}
	}

	private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		final KeyPairGenerator gen = KeyPairGenerator.getInstance("X25519");
		return gen.generateKeyPair();
	}

	private static byte[] keyAgreement(final PrivateKey privateKey, final byte[] spk) throws GeneralSecurityException {
		final byte[] reversed = spk.clone();
		reverse(reversed);
		final KeySpec spec = new XECPublicKeySpec(NamedParameterSpec.X25519, new BigInteger(1, reversed));
		final PublicKey pubKey = KeyFactory.getInstance("X25519").generatePublic(spec);
		final KeyAgreement ka = KeyAgreement.getInstance("X25519");
		ka.init(privateKey);
		ka.doPhase(pubKey, true);
		return ka.generateSecret();
	}

	private static byte[] sessionKey(final byte[] sharedSecret) {
		try {
			final MessageDigest digest = MessageDigest.getInstance("SHA-256");
			final byte[] hash = digest.digest(sharedSecret);
			return Arrays.copyOfRange(hash, 0, 16);
		}
		catch (final NoSuchAlgorithmException e) {
			// every platform is required to support SHA-256
			throw new KnxSecureException("platform does not support SHA-256 algorithm", e);
		}
	}

	private static Key createSecretKey(final byte[] key) {
		if (key.length != 16)
			throw new KNXIllegalArgumentException("KNX secret key has to be 16 bytes in length");
		return new SecretKeySpec(key, 0, key.length, "AES");
	}

	private static byte[] securityInfo(final byte[] data, final int offset, final int lengthInfo) {
		final byte[] secInfo = Arrays.copyOfRange(data, offset, offset + 16);
		secInfo[14] = (byte) (lengthInfo >> 8);
		secInfo[15] = (byte) lengthInfo;
		return secInfo;
	}

	private static byte[] deriveSerialNumber(final InetAddress addr) {
		if (addr != null) {
			try {
				final NetworkInterface netif = NetworkInterface.getByInetAddress(addr);
				if (netif != null) {
					final byte[] hardwareAddress = netif.getHardwareAddress();
					if (hardwareAddress != null)
						return Arrays.copyOf(hardwareAddress, 6);
				}
			}
			catch (final SocketException e) {}
		}
		return new byte[6];
	}

	// NYI check for reuse of session ID on overflow, currently we assume ID is already free
	private static int newSessionId() {
		return (int) (sessionCounter.getAndIncrement() % 0xfffe) + 1;
	}

	private static byte[] xor(final byte[] a, final int offsetA, final byte[] b, final int offsetB, final int len) {
		if (a.length - len < offsetA || b.length - len < offsetB)
			throw new KNXIllegalArgumentException("illegal offset or length");
		final byte[] res = new byte[len];
		for (int i = 0; i < len; i++)
			res[i] = (byte) (a[i + offsetA] ^ b[i + offsetB]);
		return res;
	}

	private static void reverse(final byte[] array) {
		for (int i = 0; i < array.length / 2; i++) {
			final byte b = array[i];
			array[i] = array[array.length - 1 - i];
			array[array.length - 1 - i] = b;
		}
	}
}
