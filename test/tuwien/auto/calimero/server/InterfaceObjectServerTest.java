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
*/

package tuwien.auto.calimero.server;

import java.util.Collection;
import java.util.Iterator;

import junit.framework.TestCase;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.exception.KNXException;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.mgmt.PropertyClient.PropertyKey;
import tuwien.auto.calimero.server.InterfaceObjectServer.IosResourceHandler;

/**
 * @author B. Malinowsky
 */
public class InterfaceObjectServerTest extends TestCase
{
	private static final String propertiesFile = "test/properties.xml";

	private InterfaceObjectServer ios;

	/**
	 * @param name
	 */
	public InterfaceObjectServerTest(final String name)
	{
		super(name);
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception
	{
		super.setUp();
		ios = new InterfaceObjectServer(false);
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception
	{
		super.tearDown();
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#InterfaceObjectServer(boolean)} .
	 * 
	 * @throws KNXException
	 */
	public final void testInterfaceObjectServer() throws KNXException
	{
		final InterfaceObjectServer s = new InterfaceObjectServer(false);
		final InterfaceObject[] ios = s.getInterfaceObjects();
		for (int i = 0; i < ios.length; i++) {
			System.out.println(ios[i]);
		}
		final Description d = s.getDescription(0, 1);
		System.out.println(d);
		final Description set = new Description(0, 0, 1, 0, 15, false, 1, 1, 3, 3);
		s.setDescription(set, true);

		System.out.println(s.getDescription(0, 1));
		s.saveInterfaceObjects("savedProperties.xml");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#setResourceHandler (tuwien.auto.calimero.server.InterfaceObjectServer.IosResourceHandler)}
	 * .
	 */
	public final void testSetResourceHandler()
	{
		ios.setResourceHandler(null);
		ios.setResourceHandler(new IosResourceHandler()
		{
			public void save(final String resource, final Collection definitions)
				throws KNXException
			{}

			public Collection load(final String resource) throws KNXException
			{
				return null;
			}

			public void saveProperties(final String resource, final Collection descriptions,
				final Collection values) throws KNXException
			{}

			public void saveInterfaceObjects(final String resource, final Collection ifObjects)
				throws KNXException
			{}

			public void loadProperties(final String resource, final Collection descriptions,
				final Collection values) throws KNXException
			{}

			public Collection loadInterfaceObjects(final String resource) throws KNXException
			{
				return null;
			}
		});
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#loadDefinitions(java.lang.String)} .
	 * 
	 * @throws KNXException
	 */
	public final void testLoadDefinitions() throws KNXException
	{
		ios.loadDefinitions(propertiesFile);
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#loadInterfaceObjects(java.lang.String)}
	 * .
	 * 
	 * @throws KNXException
	 */
	public final void testLoadInterfaceObjects() throws KNXException
	{
		ios.loadInterfaceObjects("testLoadInterfaceObjects.xml");
		final Description d = ios.getDescription(0, 1);
		final InterfaceObject[] objects = ios.getInterfaceObjects();
		for (int i = 0; i < objects.length; i++) {
			final InterfaceObject interfaceObject = objects[i];
			System.out.println("" + interfaceObject);
			for (final Iterator k = interfaceObject.values.keySet().iterator(); k.hasNext();) {
				final PropertyKey key = (PropertyKey) k.next();
				System.out.println(DataUnitBuilder.toHex((byte[]) interfaceObject.values.get(key),
						""));
			}
		}
		System.out.println(d.getPDT());
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#saveInterfaceObjects(java.lang.String)}
	 * .
	 * 
	 * @throws KNXException
	 */
	public final void testSaveInterfaceObjects() throws KNXException
	{
		ios.addInterfaceObject(InterfaceObject.KNXNETIP_PARAMETER_OBJECT);
		ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
				PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 1, 4, new byte[] { 1, 1, 2, 2,
					3, 3, 4, 4 });
		ios.saveInterfaceObjects("testSaveInterfaceObjects.xml");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#getInterfaceObjects()}.
	 */
	public final void testGetInterfaceObjects()
	{
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#addInterfaceObject(int)}.
	 */
	public final void testAddInterfaceObject()
	{
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#addServerListener(tuwien.auto.calimero.server.InterfaceObjectServerListener)}
	 * .
	 */
	public final void testAddServerListener()
	{
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#removeServerListener(tuwien.auto.calimero.server.InterfaceObjectServerListener)}
	 * .
	 */
	public final void testRemoveServerListener()
	{
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#getProperty(int, int, int, int)} .
	 */
	public final void testGetPropertyIntIntIntInt()
	{
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#setProperty(int, int, int, int, byte[])}
	 * .
	 */
	public final void testSetPropertyIntIntIntIntByteArray()
	{
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#setProperty(int, int, int, int, int, byte[])}
	 * .
	 */
	public final void testSetPropertyIntIntIntIntIntByteArray()
	{
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#getProperty(int, int, int, int, int)}
	 * .
	 */
	public final void testGetPropertyIntIntIntIntInt()
	{
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#setProperty(int, int, int, java.lang.String)}
	 * .
	 */
	public final void testSetPropertyIntIntIntString()
	{
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#getPropertyTranslated(int, int, int, int)}
	 * .
	 */
	public final void testGetPropertyTranslated()
	{
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#setDescription(tuwien.auto.calimero.mgmt.Description, boolean)}
	 * .
	 */
	public final void testSetDescription()
	{
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.server.InterfaceObjectServer#getDescription(int, int)}.
	 */
	public final void testGetDescription()
	{
		fail("Not yet implemented");
	}

	public final void testResetElements() throws KNXException
	{
		ios.addInterfaceObject(InterfaceObject.KNXNETIP_PARAMETER_OBJECT);
		// get KNXnet/IP parameter object to set some additional addresses
		final InterfaceObject[] objs = ios.getInterfaceObjects();
		int objIdx = -1;
		for (int i = 0; i < objs.length; i++) {
			final InterfaceObject io = objs[i];
			if (io.getType() == InterfaceObject.KNXNETIP_PARAMETER_OBJECT) {
				objIdx = i;
				break;
			}
		}
		ios.setDescription(new Description(objIdx, 0,
				PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 0, 0, true, 0, 20, 3, 3), true);
		Description d = ios.getDescription(objIdx,
				PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES);
		assertTrue(d.getCurrentElements() == 0);

		// set addresses
		ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
				PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 1, 3, new byte[] { 1, 1, 1, 2,
					1, 3 });
		d = ios.getDescription(objIdx, PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES);
		assertTrue(d.getCurrentElements() == 3);

		// try not allowed ways to access current number of elements

		try {
			ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
					PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 0, 2, new byte[] { 0, 0, });
			fail("only one element allowed");
		}
		catch (final KNXException e) {
			// ok
		}

		try {
			ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
					PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 0, 1, new byte[] { 1, 0, });
			fail("only 0 value allowed");
		}
		catch (final KNXException e) {
			// ok
		}

		try {
			ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
					PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 0, 1,
					new byte[] { 0, 0, 0, });
			fail("only byte array length 2 allowed");
		}
		catch (final KNXException e) {
			// ok
		}

		// try correct way to reset current number of elements
		ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
				PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 0, 1, new byte[] { 0, 0, });
		d = ios.getDescription(objIdx, PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES);
		assertTrue(d.getCurrentElements() == 0);
	}
}
