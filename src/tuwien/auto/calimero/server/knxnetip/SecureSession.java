/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2018 B. Malinowsky

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
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.slf4j.Logger;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.knxnetip.KnxSecureException;
import tuwien.auto.calimero.knxnetip.SecureConnection;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;

/** Internal use only. Used for testing. */
class SecureSession {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static final int SecureSvc = 0x0950;
	private static final int SessionReq = 0x0951;
	private static final int SessionRes = 0x0952;
	private static final int SessionAuth = 0x0953;
	private static final int SessionStatus = 0x0954;


	private static final int macSize = 16; // [bytes]
	private static final int keyLength = 32; // [bytes]

	private final DatagramSocket socket;
	private final Logger logger;

	private final byte[] sno;
	private final Key deviceAuthKey;

	private static AtomicLong sessionCounter = new AtomicLong();
	// session ID to session key
	private final Map<Integer, Key> sessions = new HashMap<>();


	SecureSession(final ControlEndpointService ctrlEndpoint) {
		socket = ctrlEndpoint.getSocket();
		logger = ctrlEndpoint.logger;
		sno = deriveSerialNumber(ctrlEndpoint.getSocket().getLocalAddress());
		deviceAuthKey = createSecretKey(new byte[16]);
	}

	void acceptService(final KNXnetIPHeader h, final byte[] data, final int offset, final InetAddress src,
		final int port) throws KNXFormatException, IOException {

		try {
			if (h.getServiceType() == SessionReq) {
				final ByteBuffer res = establishSession(h, data, offset);
				socket.send(new DatagramPacket(res.array(), res.position(), src, port));
			}
			else if (h.getServiceType() == SecureSvc) {
				final int sessionId = ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
				final Key secretKey = sessions.get(sessionId);
				if (secretKey == null) {
					logger.warn("invalid secure session ID {}", sessionId);
					return;
				}

				final Object[] fields = SecureConnection.unwrap(h, data, offset, secretKey);
				final int sid = (int) fields[0];
				final long seq = (long) fields[1];
				final long sno = (long) fields[2];
				final int tag = (int) fields[3];
				final byte[] knxipPacket = (byte[]) fields[4];

				final KNXnetIPHeader svcHeader = new KNXnetIPHeader(knxipPacket, 0);
				logger.trace("received {} {} (session {} seq {} S/N {} tag {})", svcHeader, toHex(knxipPacket, " "),
						sid, seq, sno, tag);
				final long lastValidPacket = System.nanoTime() / 1000_000L;

				if (svcHeader.getServiceType() == SessionAuth) {
					int status = AuthSuccess;
					try {
						final int authContext = sessionAuth(knxipPacket, 6);
						logger.debug("client authorized for session {} context {}", sessionId, authContext);
					} catch (final KnxSecureException e) {
						logger.info("secure session {}: {}", sessionId, e.getMessage());
						status = AuthFailed;
					}
					sendStatusInfo(sessionId, 0, status, src, port);
				}
				else {
					// forward to associated data endpoint service handler
				}
			}
		}
		catch (final KnxSecureException e) {
			logger.error("error processing {} {}", h, e.getMessage());
			sendStatusInfo(0, 0, Unauthorized, src, port);
		}
	}

	private ByteBuffer establishSession(final KNXnetIPHeader h, final byte[] data, final int offset) {

		final byte[] clientKey = Arrays.copyOfRange(data, offset + 8, h.getTotalLength());
		final byte[] privateKey = new byte[keyLength];
		final byte[] publicKey = new byte[keyLength];
		generateKeyPair(privateKey, publicKey);
		final byte[] sessionKey = sessionKey(keyAgreement(privateKey, clientKey));
		final Key secretKey = createSecretKey(sessionKey);

		final int sessionId = newSessionId();
		if (sessionId != 0)
			sessions.put(sessionId, secretKey);
		logger.debug("establish secure session {}", sessionId);
		logger.trace("*** security sensitive information! using session key {} ***", toHex(sessionKey, ""));

		return sessionResponse(sessionId, publicKey, clientKey);
	}

	private ByteBuffer sessionResponse(final int sessionId, final byte[] publicKey, final byte[] clientPublicKey) {
		final int len = sessionId == 0 ? 8 : 0x38;
		final ByteBuffer buf = ByteBuffer.allocate(len);
		buf.put(new KNXnetIPHeader(SessionRes, len - 6).toByteArray());
		buf.putShort((short) sessionId);
		if (sessionId == 0)
			return buf;

		buf.put(publicKey);
		final byte[] xor = xor(publicKey, 0, clientPublicKey, 0, publicKey.length);
		final byte[] mac = cbcMacSimple(xor, 0, xor.length);
		encrypt(mac, sessions.get(sessionId));
		buf.put(mac);
		return buf;
	}

	private int sessionAuth(final byte[] data, final int offset) {
		final ByteBuffer buffer = ByteBuffer.wrap(data, offset, data.length - offset);
		final int authContext = buffer.getShort() & 0xffff;
		final byte[] mac = new byte[macSize];
		buffer.get(mac);

		// TODO keys
		final byte[] serverPublicKey = new byte[keyLength];
		final byte[] clientPublicKey = new byte[keyLength];
		final byte[] xor = xor(serverPublicKey, 0, clientPublicKey, 0, keyLength);
		final byte[] verifyAgainst = cbcMacSimple(xor, 0, keyLength);
		final boolean authenticated = Arrays.equals(mac, verifyAgainst);
		if (!authenticated) {
//			final String packet = toHex(Arrays.copyOfRange(data, offset - 6, offset - 6 + 0x38), " ");
//			throw new KnxSecureException("authentication failed for session auth " + packet);
		}

		// we don't support management
		if (authContext < 2 || authContext > 0x7F)
			throw new KnxSecureException("authorization context out of range [2..127]");
		return authContext;
	}

	private byte[] statusInfo(final int sessionId, final int seq, final int status) {
		final ByteBuffer packet = sessionStatus(status);
		final int msgTag = 0; // NYI
		return newSecurePacket(sessionId, seq, msgTag, packet.array());
	}

	private void sendStatusInfo(final int sessionId, final int seq, final int status, final InetAddress remote, final int port)
		throws IOException {
		final byte[] packet = statusInfo(sessionId, seq, status);
		socket.send(new DatagramPacket(packet, packet.length, remote, port));
	}

	// session status is one of:
	private static final int AuthSuccess = 0;
	private static final int AuthFailed = 1;
	private static final int Unauthorized = 2;
	private static final int Timeout = 3;

	private ByteBuffer sessionStatus(final int status) {
		final ByteBuffer buf = ByteBuffer.allocate(6 + 2);
		buf.put(new KNXnetIPHeader(SessionStatus, 2).toByteArray());
		buf.put((byte) status);
		return buf;
	}

	// if we don't receive a valid secure packet for 2 minutes, we close the session (and the connection if any)
	private void sessionTimeout(final int sessionId, final InetSocketAddress remote) throws IOException {
		sessions.remove(sessionId);
		// NYI
		final int seq = 0;
		sendStatusInfo(sessionId, seq, Timeout, remote.getAddress(), remote.getPort());
	}

	private byte[] newSecurePacket(final int sessionId, final long seq, final int msgTag, final byte[] knxipPacket) {
		final Key secretKey = sessions.get(sessionId);
		return SecureConnection.newSecurePacket(sessionId, seq, sno, msgTag, knxipPacket, secretKey);
	}

	private void encrypt(final byte[] mac, final Key secretKey) {
		SecureConnection.encrypt(mac, 0, secretKey, securityInfo(new byte[16], 0, 0xff00));
	}

	private byte[] cbcMacSimple(final byte[] data, final int offset, final int length) {
		final byte[] log = Arrays.copyOfRange(data, offset, offset + length);
		logger.trace("authenticating (length {}): {}", length, toHex(log, " "));

		try {
			final Cipher cipher = Cipher.getInstance("AES/CBC/ZeroBytePadding");
			final IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
			cipher.init(Cipher.ENCRYPT_MODE, deviceAuthKey, ivSpec);

			final byte[] result = cipher.doFinal(data, offset, length);
			final byte[] mac = Arrays.copyOfRange(result, result.length - macSize, result.length);
			return mac;
		}
		catch (final GeneralSecurityException e) {
			throw new KnxSecureException("calculating CBC-MAC of " + toHex(log, " "), e);
		}
	}

	private static void generateKeyPair(final byte[] privateKey, final byte[] publicKey) {
		new SecureRandom().nextBytes(privateKey);
		X25519.scalarMultBase(privateKey, 0, publicKey, 0);
	}

	private static byte[] keyAgreement(final byte[] privateKey, final byte[] spk) {
		final byte[] sharedSecret = new byte[keyLength];
		X25519.scalarMult(privateKey, 0, spk, 0, sharedSecret, 0);
		return sharedSecret;
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
}
