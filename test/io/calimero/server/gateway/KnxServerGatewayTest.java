/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2025 B. Malinowsky

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

package io.calimero.server.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.calimero.GroupAddress;
import io.calimero.IndividualAddress;
import io.calimero.KNXAddress;
import io.calimero.KNXFormatException;
import io.calimero.Priority;
import io.calimero.cemi.CEMILData;
import io.calimero.device.ios.InterfaceObject;
import io.calimero.device.ios.InterfaceObjectServer;
import io.calimero.internal.EventListeners;
import io.calimero.internal.Executor;
import io.calimero.knxnetip.util.DeviceDIB;
import io.calimero.knxnetip.util.HPAI;
import io.calimero.link.KNXNetworkLink;
import io.calimero.link.NetworkLinkListener;
import io.calimero.link.medium.KNXMediumSettings;
import io.calimero.link.medium.TPSettings;
import io.calimero.mgmt.PropertyAccess;
import io.calimero.mgmt.PropertyAccess.PID;
import io.calimero.server.ServerConfiguration;
import io.calimero.server.gateway.SubnetConnector.InterfaceType;
import io.calimero.server.knxnetip.DefaultServiceContainer;
import io.calimero.server.knxnetip.KNXnetIPServer;
import io.calimero.server.knxnetip.ServiceContainer;

class KnxServerGatewayTest
{
	private KnxServerGateway gw;
	private KNXnetIPServer server;

	@BeforeEach
	void init() throws Exception
	{
		server = setupServer("test");
		final ServiceContainer sc = new DefaultServiceContainer("test container", "any",
				new HPAI((InetAddress) null, 5647),
				KNXMediumSettings.create(DeviceDIB.MEDIUM_TP1, new IndividualAddress(1, 1, 1)), false, true, false, false);
		server.addServiceContainer(sc);
		final SubnetConnector connector = SubnetConnector.newWithUserLink(sc, DummyLink.class.getName(), null, "");
		connector.openNetworkLink();

		final var container = new ServerConfiguration.Container(List.of(), connector, Set.of(), List.of());
		final var config = new ServerConfiguration("gateway", "friendly server name", true, List.of(), List.of(),
				List.of(container));

		gw = new KnxServerGateway(server, config);
	}

	private static final int MAIN_LCGRPCONFIG = 54;
	private static final int SUB_LCGRPCONFIG = 55;

	private static KNXnetIPServer setupServer(final String name)
	{
		final var config = new ServerConfiguration(name, "friendly server name", true, List.of(), List.of(), List.of());
		final KNXnetIPServer s = new KNXnetIPServer(config);
		final InterfaceObjectServer ios = s.getInterfaceObjectServer();
		ios.addInterfaceObject(InterfaceObject.ROUTER_OBJECT);
		ios.setProperty(InterfaceObject.ROUTER_OBJECT, 1, MAIN_LCGRPCONFIG, 1, 1, new byte[] {0});
		ios.setProperty(InterfaceObject.ROUTER_OBJECT, 1, SUB_LCGRPCONFIG, 1, 1, new byte[] {0});
		return s;
	}

	@AfterEach
	void tearDown() {
		server.shutdown();
	}

	@Test
	void run() throws InterruptedException
	{
		final KNXnetIPServer s = setupServer("test 2");
		final var lo = InetAddress.getLoopbackAddress();
		final var sc = new DefaultServiceContainer("test container 2", "any", new HPAI(lo, 0), new TPSettings(),
				false, false, false, false);
		s.addServiceContainer(sc);
		final var connector = SubnetConnector.newCustom(sc, InterfaceType.Emulate);

		final var container = new ServerConfiguration.Container(List.of(), connector, Set.of(), List.of());
		final var config = new ServerConfiguration("test GW 2", "friendly test GW 2", true, List.of(), List.of(),
				List.of(container));

		final KnxServerGateway gw2 = new KnxServerGateway(s, config);
		Thread t = Executor.execute(gw2, "gw2");
		Thread.sleep(1000);
		assertTrue(t.isAlive());
		gw2.quit();

		t = Executor.execute(gw, "gw");
		Thread.sleep(2000);
		assertTrue(t.isAlive());
		gw.quit();
	}

	@Test
	void quit() throws InterruptedException
	{
		final Thread t = Executor.execute(gw, "gw");
		Thread.sleep(2000);
		assertTrue(t.isAlive());
		gw.quit();
		Thread.sleep(500);
		assertFalse(t.isAlive());
	}

	@Test
	void getName()
	{
		assertEquals("gateway", gw.getName());
	}

	private final List<GroupAddress> addrList = new ArrayList<>();
	private final Set<GroupAddress> addrSet = new HashSet<>();
	private InterfaceObjectServer ios;

	@Test
	void addressLookupPerformance()
	{
		// load address table for group address filtering
		for (int i = 1; i < 100; i++)
			addrList.add(new GroupAddress(0, 0, i));

		// fill address set
		addrSet.addAll(addrList);

		// fill interface object property
		// create byte array table
		final int size = addrList.size();
		final byte[] table = new byte[size * 2];
		int idx = 0;
		for (final GroupAddress ga : addrList) {
			table[idx++] = (byte) (ga.getRawAddress() >> 8);
			table[idx++] = (byte) ga.getRawAddress();
		}
		final var config = new ServerConfiguration("calimero-server", "", false, List.of(), List.of(), List.of());
		final KNXnetIPServer server = new KNXnetIPServer(config);
		ios = server.getInterfaceObjectServer();
		// create interface object and set the address table object property
		ios.addInterfaceObject(InterfaceObject.ADDRESSTABLE_OBJECT);
		ios.setProperty(InterfaceObject.ADDRESSTABLE_OBJECT, 1, PID.TABLE, 1, size, table);

		final int loops = 100000;
		long start = System.currentTimeMillis();
		for (int i = 0; i < loops; ++i)
			inGroupAddressTable(addrList.get(i % addrList.size()));
		long end = System.currentTimeMillis();
		System.out.println("group address table lookup: " + (end - start));

		start = System.currentTimeMillis();
		for (int i = 0; i < loops; ++i)
			inGroupAddressSet(addrList.get(i % addrList.size()));
		end = System.currentTimeMillis();
		System.out.println("group address set lookup: " + (end - start));
	}

	// lookup performance using IOS get property
	private boolean inGroupAddressTable(final GroupAddress addr)
	{
		final byte[] data = ios.getProperty(InterfaceObject.ADDRESSTABLE_OBJECT, 1, PropertyAccess.PID.TABLE, 0, 1);
		final int elems = ((data[0] & 0xff) << 8) | (data[1] & 0xff);
		if (elems == 0)
			return true;
		final byte[] addrTable = ios.getProperty(InterfaceObject.ADDRESSTABLE_OBJECT, 1, PropertyAccess.PID.TABLE, 1,
				elems);
		final byte hi = (byte) (addr.getRawAddress() >> 8);
		final byte lo = (byte) addr.getRawAddress();
		for (int i = 0; i < addrTable.length; i += 2)
			if (hi == addrTable[i] && lo == addrTable[i + 1])
				return true;
		return false;
	}

	// lookup performance using local address set
	private boolean inGroupAddressSet(final GroupAddress addr)
	{
		// implements KNX group address filtering
		return addrSet.contains(addr);
	}

	// dummy link for setting up gateway
	static class DummyLink implements KNXNetworkLink
	{
		private final EventListeners<NetworkLinkListener> listeners = new EventListeners<>();

		// has to be public for creation by subnet connector
		public DummyLink(@SuppressWarnings("unused") final Object[] __) {}

		@Override
		public void addLinkListener(final NetworkLinkListener l)
		{
			listeners.add(l);
		}

		@Override
		public void removeLinkListener(final NetworkLinkListener l)
		{
			listeners.remove(l);
		}

		@Override
		public void setHopCount(final int count) {}

		@Override
		public int getHopCount()
		{
			return 6;
		}

		@Override
		public void setKNXMedium(final KNXMediumSettings settings) {}

		@Override
		public KNXMediumSettings getKNXMedium()
		{
			return null;
		}

		@Override
		public void send(final CEMILData msg, final boolean waitForCon) {}

		@Override
		public void sendRequest(final KNXAddress dst, final Priority p, final byte... nsdu) {
			try {
				send(new CEMILData(CEMILData.MC_LDATA_REQ, new IndividualAddress("0.0.0"), dst, nsdu, p), false);
			}
			catch (final KNXFormatException e) {
				fail(e);
			}
		}

		@Override
		public void sendRequestWait(final KNXAddress dst, final Priority p, final byte... nsdu) {
			try {
				send(new CEMILData(CEMILData.MC_LDATA_REQ, new IndividualAddress("0.0.0"), dst, nsdu, p), true);
			}
			catch (final KNXFormatException e) {
				fail(e);
			}
		}

		@Override
		public String getName()
		{
			return "link";
		}

		@Override
		public boolean isOpen()
		{
			return true;
		}

		@Override
		public void close() {}
	}
}
