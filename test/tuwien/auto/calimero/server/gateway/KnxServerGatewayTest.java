/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2011 B. Malinowsky

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

package tuwien.auto.calimero.server.gateway;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.exception.KNXFormatException;
import tuwien.auto.calimero.exception.KNXIllegalStateException;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.knxnetip.util.DeviceDIB;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.NetworkLinkListener;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.server.InterfaceObject;
import tuwien.auto.calimero.server.InterfaceObjectServer;
import tuwien.auto.calimero.server.KNXPropertyException;
import tuwien.auto.calimero.server.knxnetip.DefaultServiceContainer;
import tuwien.auto.calimero.server.knxnetip.KNXnetIPServer;
import tuwien.auto.calimero.server.knxnetip.ServiceContainer;

/**
 * @author B. Malinowsky
 */
public class KnxServerGatewayTest extends TestCase
{
	private KnxServerGateway gw;
	private KNXnetIPServer server;
	private SubnetConnector[] subnetConnectors;

	/**
	 * @param name
	 */
	public KnxServerGatewayTest(final String name)
	{
		super(name);
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception
	{
		super.setUp();
		server = new KNXnetIPServer();
		final InterfaceObjectServer ios = server.getInterfaceObjectServer();
		ios.addInterfaceObject(InterfaceObject.ROUTER_OBJECT);

		final ServiceContainer sc = new DefaultServiceContainer("test container", new HPAI(
				(InetAddress) null, 5647), DeviceDIB.MEDIUM_TP1, new IndividualAddress(1, 1, 1));
		server.addServiceContainer(sc);
		final KNXNetworkLink link = new DummyLink();
		final SubnetConnector b = new SubnetConnector(sc, link, 1);

		subnetConnectors = new SubnetConnector[] { b };
		gw = new KnxServerGateway("gateway", server, subnetConnectors);
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception
	{
		server.shutdown();
		super.tearDown();
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.gateway.KnxServerGateway#KnxServerGateway(
	 * java.lang.String, tuwien.auto.calimero.server.knxnetip.KNXnetIPServer,
	 * tuwien.auto.calimero.server.gateway.SubnetConnector[])}.
	 */
	public final void testKnxServerGateway()
	{
		/*final KnxServerGateway gw2 =*/ new KnxServerGateway("testGW", new KNXnetIPServer(),
				new SubnetConnector[] {});
	}

	/**
	 * Test method for {@link tuwien.auto.calimero.server.gateway.KnxServerGateway#run()}.
	 * 
	 * @throws InterruptedException
	 */
	public final void testRun() throws InterruptedException
	{
		try {
			final KnxServerGateway gw2 = new KnxServerGateway("testGW", new KNXnetIPServer(),
					new SubnetConnector[] {});
			gw2.run();
			fail();
		}
		catch (final KNXIllegalStateException e) {
			// ok no svc containers added
		}

		Thread t;
		(t = new Thread(gw)).start();
		Thread.sleep(4000);
		assertTrue(t.isAlive());
		gw.quit();
	}

	/**
	 * Test method for {@link tuwien.auto.calimero.server.gateway.KnxServerGateway#quit()} .
	 * 
	 * @throws InterruptedException
	 */
	public final void testQuit() throws InterruptedException
	{
		Thread t;
		(t = new Thread(gw)).start();
		Thread.sleep(4000);
		assertTrue(t.isAlive());
		gw.quit();
		Thread.sleep(500);
		assertFalse(t.isAlive());
	}

	/**
	 * Test method for {@link tuwien.auto.calimero.server.gateway.KnxServerGateway#getName()}.
	 */
	public final void testGetName()
	{
		assertEquals("gateway", gw.getName());
	}

	private final List addrList = new ArrayList();
	private final Set addrSet = new HashSet();
	private InterfaceObjectServer ios;

	/**
	 * Test gateway group address lookup performance
	 * 
	 * @throws KNXPropertyException
	 */
	public final void testAddressLookupPerformance() throws KNXPropertyException
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
		for (int i = 0; i < size; i++) {
			final GroupAddress ga = (GroupAddress) addrList.get(i);
			table[idx++] = (byte) (ga.getRawAddress() >> 8);
			table[idx++] = (byte) ga.getRawAddress();
		}
		final KNXnetIPServer server = new KNXnetIPServer();
		ios = server.getInterfaceObjectServer();
		// create interface object and set the address table object property
		ios.addInterfaceObject(InterfaceObject.ADDRESSTABLE_OBJECT);
		ios.setProperty(InterfaceObject.ADDRESSTABLE_OBJECT, 1, PID.TABLE, 1, size, table);

		final int loops = 100000;
		long start = System.currentTimeMillis();
		for (int i = 0; i < loops; ++i)
			inGroupAddressTable((GroupAddress) addrList.get(i % addrList.size()));
		long end = System.currentTimeMillis();
		System.out.println("group address table lookup: " + (end - start));

		start = System.currentTimeMillis();
		for (int i = 0; i < loops; ++i)
			inGroupAddressSet((GroupAddress) addrList.get(i % addrList.size()));
		end = System.currentTimeMillis();
		System.out.println("group address set lookup: " + (end - start));
	}

	// lookup performance using IOS get property
	private boolean inGroupAddressTable(final GroupAddress addr)
	{
		try {
			final byte[] data = ios.getProperty(InterfaceObject.ADDRESSTABLE_OBJECT, 1,
					PropertyAccess.PID.TABLE, 0, 1);
			final int elems = ((data[0] & 0xff) << 8) | data[1] & 0xff;
			if (elems == 0)
				return true;
			final byte[] addrTable = ios.getProperty(InterfaceObject.ADDRESSTABLE_OBJECT, 1,
					PropertyAccess.PID.TABLE, 1, elems);
			final byte hi = (byte) (addr.getRawAddress() >> 8);
			final byte lo = (byte) addr.getRawAddress();
			for (int i = 0; i < addrTable.length; i += 2)
				if (hi == addrTable[i] && lo == addrTable[i + 1])
					return true;
			return false;
		}
		catch (final KNXPropertyException e) {
			return true;
		}
	}

	// lookup performance using local address set
	private boolean inGroupAddressSet(final GroupAddress addr)
	{
		// implements KNX group address filtering
		return addrSet.contains(addr);
	}

	// dummy link for setting up gateway
	private class DummyLink implements KNXNetworkLink
	{
		private final EventListeners listeners = new EventListeners();

		public DummyLink()
		{}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink
		 * #addLinkListener(tuwien.auto.calimero.link.event.NetworkLinkListener)
		 */
		public void addLinkListener(final NetworkLinkListener l)
		{
			listeners.add(l);
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink
		 * #removeLinkListener(tuwien.auto.calimero.link.event.NetworkLinkListener)
		 */
		public void removeLinkListener(final NetworkLinkListener l)
		{
			listeners.remove(l);
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink#setHopCount(int)
		 */
		public void setHopCount(final int count)
		{}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink#getHopCount()
		 */
		public int getHopCount()
		{
			return 6;
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink
		 * #setKNXMedium(tuwien.auto.calimero.link.medium.KNXMediumSettings)
		 */
		public void setKNXMedium(final KNXMediumSettings settings)
		{}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink#getKNXMedium()
		 */
		public KNXMediumSettings getKNXMedium()
		{
			return null;
		}

		/**
		 * @param msg
		 * @param waitForCon
		 * @see tuwien.auto.calimero.link.KNXNetworkLink #send(tuwien.auto.calimero.cemi.CEMILData,
		 *      boolean)
		 */
		public void send(final CEMILData msg, final boolean waitForCon)
		{}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink
		 * #sendRequest(tuwien.auto.calimero.KNXAddress, tuwien.auto.calimero.Priority,
		 * byte[])
		 */
		public void sendRequest(final KNXAddress dst, final Priority p, final byte[] nsdu)
		{
			try {
				send(new CEMILData(CEMILData.MC_LDATA_REQ, new IndividualAddress("0.0.0"), dst,
						nsdu, p), false);
			}
			catch (final KNXFormatException e) {
				e.printStackTrace();
			}
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink
		 * #sendRequestWait(tuwien.auto.calimero.KNXAddress,
		 * tuwien.auto.calimero.Priority, byte[])
		 */
		public void sendRequestWait(final KNXAddress dst, final Priority p, final byte[] nsdu)
		{
			try {
				send(new CEMILData(CEMILData.MC_LDATA_REQ, new IndividualAddress("0.0.0"), dst,
						nsdu, p), true);
			}
			catch (final KNXFormatException e) {
				e.printStackTrace();
			}
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink#getName()
		 */
		public String getName()
		{
			return "link";
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink#isOpen()
		 */
		public boolean isOpen()
		{
			return true;
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink#close()
		 */
		public void close()
		{}
	}
}
