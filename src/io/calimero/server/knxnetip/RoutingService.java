/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2016, 2022 B. Malinowsky

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

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

import io.calimero.CloseEvent;
import io.calimero.FrameEvent;
import io.calimero.KNXException;
import io.calimero.KNXFormatException;
import io.calimero.KNXListener;
import io.calimero.KnxRuntimeException;
import io.calimero.cemi.CEMI;
import io.calimero.cemi.CEMIFactory;
import io.calimero.cemi.CEMILDataEx;
import io.calimero.device.ios.KnxipParameterObject;
import io.calimero.knxnetip.KNXConnectionClosedException;
import io.calimero.knxnetip.KNXnetIPRouting;
import io.calimero.knxnetip.SecureConnection;
import io.calimero.knxnetip.servicetype.KNXnetIPHeader;
import io.calimero.knxnetip.servicetype.PacketHelper;
import io.calimero.knxnetip.servicetype.RoutingLostMessage;
import io.calimero.knxnetip.util.ServiceFamiliesDIB.ServiceFamily;
import io.calimero.log.LogService;
import io.calimero.log.LogService.LogLevel;
import io.calimero.mgmt.PropertyAccess.PID;

final class RoutingService extends ServiceLooper
{
	private boolean closing;

	private class RoutingServiceHandler extends KNXnetIPRouting
	{
		RoutingServiceHandler(final NetworkInterface netif, final InetAddress mcGroup,
			final boolean enableLoopback) throws KNXException {
			super(mcGroup);
			init(netif, enableLoopback, false);
			logger = LogService.getLogger("io.calimero.server.knxnetip." + getName());
		}

		// forwarder for RoutingService dispatch, called from handleServiceType
		@Override
		protected boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset,
			final InetAddress src, final int port) throws KNXFormatException, IOException
		{
			return super.handleServiceType(h, data, offset, src, port);
		}

		@Override
		public String getName()
		{
			return "KNX IP routing service " + ctrlEndpt.getAddress().getHostAddress();
		}

		@Override
		protected DatagramChannel channel() { return super.channel(); }

		@Override
		public void send(final CEMI frame, final BlockingMode mode) throws KNXConnectionClosedException {
			var send = frame;
			if (frame instanceof CEMILDataEx && !((CEMILDataEx) frame).additionalInfo().isEmpty()) {
				send = CEMIFactory.copy(frame);
				((CEMILDataEx) send).additionalInfo().clear();
			}
			super.send(send, mode);
		}

		public void send(final RoutingLostMessage lost) throws KNXConnectionClosedException
		{
			send(PacketHelper.toPacket(lost));
		}

		@Override
		public String toString()
		{
			return getName();
		}

		@Override
		protected void close(final int initiator, final String reason, final LogLevel level, final Throwable t)
		{
			// quit routing service before, so the UdpSocketLooper has its quit flag set and won't re-throw
			// any I/O or socket exception while exiting
			closing = true;
			RoutingService.this.quit();
			super.close(initiator, reason, level, t);
		}
	}

	final RoutingServiceHandler r;
	private final RoutingServiceContainer svcCont;
	private final boolean secure;

	RoutingService(final KNXnetIPServer server, final RoutingServiceContainer sc, final boolean enableLoopback)	{
		super(server, null, false, 512, 0);
		svcCont = sc;

		final var ios = server.getInterfaceObjectServer();
		final int oi = server.objectInstance(sc);
		final var knxipObject = KnxipParameterObject.lookup(ios, oi);

		final byte[] groupKey = knxipObject.getOrDefault(KnxipParameterObject.Pid.BackboneKey, new byte[0]);
		secure = knxipObject.securedService(ServiceFamily.Routing) && groupKey.length == 16;

		final var mcGroup = knxipObject.inetAddress(PID.ROUTING_MULTICAST_ADDRESS);

		final KNXnetIPRouting inst;
		try {
			final NetworkInterface netif = networkInterface();
			if (secure) {
				inst = SecureConnection.newRouting(netif, mcGroup, groupKey, sc.latencyTolerance());
				r = new RoutingServiceHandler(netif, mcGroup, enableLoopback) {
					@Override
					public void send(final RoutingLostMessage lost) throws KNXConnectionClosedException {
						// NYI sending routing lost message
						logger.warn("NYI sending routing lost message");
					}

					@Override
					public String getName() { return inst.getName(); }

					@Override
					protected void close(final int initiator, final String reason, final LogLevel level,
							final Throwable t) {
						closing = true;
						inst.close();
						super.close(initiator, reason, level, t);
					}
				};
				// add listener to inst after r got initialized
				inst.addConnectionListener(new KNXListener() {
					@Override
					public void frameReceived(final FrameEvent e) {}

					@Override
					public void connectionClosed(final CloseEvent e) { r.close(); }
				});
			}
			else {
				r = new RoutingServiceHandler(netif, mcGroup, enableLoopback);
				inst = r;
			}
		}
		catch (SocketException | KNXException e) {
			throw wrappedException(e);
		}
		catch (final InterruptedException e) {
			Thread.currentThread().interrupt();
			throw wrappedException(e);
		}

		s = r.channel().socket();
		fireRoutingServiceStarted(svcCont, inst);
	}

	@Override
	protected void receive(final byte[] buf) throws IOException {
		final ByteBuffer buffer = ByteBuffer.wrap(buf);
		final var source = r.channel().receive(buffer);
		buffer.flip();
		onReceive((InetSocketAddress) source, buf, buffer.position(), buffer.remaining());
	}

	private NetworkInterface networkInterface() throws SocketException {
		final String name = svcCont.networkInterface();
		if ("any".equals(name))
			return null;
		final NetworkInterface netif = NetworkInterface.getByName(name);
		if (netif == null)
			throw new KnxRuntimeException("no network interface with the specified name '" + name + "'");
		return netif;
	}

	ServiceContainer getServiceContainer()
	{
		return svcCont;
	}

	@Override
	boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset, final InetSocketAddress src)
			throws KNXFormatException, IOException
	{
		if (secure)
			return true;
		return r.handleServiceType(h, data, offset, src.getAddress(), src.getPort());
	}

	void sendRoutingLostMessage(final int lost, final int state) throws KNXConnectionClosedException
	{
		final RoutingLostMessage msg = new RoutingLostMessage(lost, state);
		r.send(msg);
	}

	@Override
	public void quit()
	{
		super.quit();
		if (!closing)
			r.close();
	}

	@Override
	public String toString() {
		return svcCont.getName() + " " + r.getName();
	}

	private void fireRoutingServiceStarted(final ServiceContainer sc, final KNXnetIPRouting r)
	{
		final ServiceContainerEvent sce = new ServiceContainerEvent(server, ServiceContainerEvent.ROUTING_SVC_STARTED, sc, r);
		server.fireOnServiceContainerChange(sce);
	}
}
