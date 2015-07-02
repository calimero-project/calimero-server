/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2015 B. Malinowsky

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

package tuwien.auto.calimero.server;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.PropertyClient;
import tuwien.auto.calimero.mgmt.PropertyClient.PropertyKey;
import tuwien.auto.calimero.server.InterfaceObjectServer.IosResourceHandler;

/**
 * An interface object is a common structure to hold KNX properties.
 * <p>
 * An interface object is configured to a certain interface object type, with the type either being
 * a predefined type using one of the type constants listed by this class, or a user-defined object
 * type.<br>
 * KNX properties are usually associated to be used within a specific object type (stated in the
 * corresponding property definition), or can be used in interface objects of any type (with such
 * KNX properties referred to as 'global' properties in their definition).
 * <p>
 * Each interface object contains the mandatory property
 * {@link tuwien.auto.calimero.mgmt.PropertyAccess.PID#OBJECT_TYPE} at property index 0, i.e., as
 * its first property entry.
 * <p>
 * Interface objects are managed by an {@link InterfaceObjectServer}, with each interface object
 * uniquely identified by its object index ({@link #getIndex()}.<br>
 * KNX properties contained in an interface object are usually accessed and modified using KNX
 * property services.
 *
 * @author B. Malinowsky
 */
public class InterfaceObject
{
	/** Interface object type 'device object' ({@value DEVICE_OBJECT}). */
	public static final int DEVICE_OBJECT = 0;

	/** Interface object type 'address table object' ({@value ADDRESSTABLE_OBJECT}). */
	public static final int ADDRESSTABLE_OBJECT = 1;

	/**
	 * Interface object type 'association table object' ({@value ASSOCIATIONTABLE_OBJECT}).
	 */
	public static final int ASSOCIATIONTABLE_OBJECT = 2;

	/**
	 * Interface object type 'application program object' ({@value APPLICATIONPROGRAM_OBJECT}).
	 */
	public static final int APPLICATIONPROGRAM_OBJECT = 3;

	/**
	 * Interface object type 'interface program object' ({@value INTERFACEPROGRAM_OBJECT}).
	 */
	public static final int INTERFACEPROGRAM_OBJECT = 4;

	// never used in practice
	// public static final int EIB_OBJECT_ASSOCIATIONTABLE_OBJECT = 5;

	/**
	 * Interface object type 'router object' ({@value ROUTER_OBJECT}).
	 */
	public static final int ROUTER_OBJECT = 6;

	/**
	 * Interface object type 'LTE address filter table object' ({@value
	 * LTE_ADDRESS_FILTER_TABLE_OBJECT}).
	 */
	public static final int LTE_ADDRESS_FILTER_TABLE_OBJECT = 7;

	/** Interface object type 'cEMI server object' ({@value CEMI_SERVER_OBJECT}). */
	public static final int CEMI_SERVER_OBJECT = 8;

	/**
	 * Interface object type 'group object table object' ({@value GROUP_OBJECT_TABLE_OBJECT}).
	 */
	public static final int GROUP_OBJECT_TABLE_OBJECT = 9;

	/** Interface object type 'polling master' ({@value POLLING_MASTER}). */
	public static final int POLLING_MASTER = 10;

	/**
	 * Interface object type 'KNXnet/IP parameter object' ({@value KNXNETIP_PARAMETER_OBJECT}).
	 */
	public static final int KNXNETIP_PARAMETER_OBJECT = 11;

	/** Interface object type 'application controller' ({@value APPLICATION_CONTROLLER}). */
	public static final int APPLICATION_CONTROLLER = 12;

	/** Interface object type 'file server object' ({@value FILE_SERVER_OBJECT}). */
	public static final int FILE_SERVER_OBJECT = 13;

	/** Interface object type 'RF medium object' ({@value RF_MEDIUM_OBJECT}). */
	public static final int RF_MEDIUM_OBJECT = 19;

	// list holding Description objects or null entries
	List<Description> descriptions = new ArrayList<>();
	// map key is PropertyKey, map value is byte[]
	Map<PropertyKey, byte[]> values = new HashMap<>();

	private final int type;
	private volatile int idx;

	/**
	 * Creates a new interface object of the specified object type.
	 * <p>
	 *
	 * @param objectType either one of the predefined interface object types listed by this class,
	 *        or a user specific object type
	 */
	public InterfaceObject(final int objectType)
	{
		type = objectType;
	}

	InterfaceObject(final int objectType, final int index)
	{
		this(objectType);
		setIndex(index);
	}

	/**
	 * Returns the type of this interface object.
	 * <p>
	 * The type is either one of the predefined interface object types listed by this class, or a
	 * user specific object type.
	 *
	 * @return interface object type as int
	 */
	public int getType()
	{
		return type;
	}

	/**
	 * Returns a human readable representation of the interface object's type.
	 * <p>
	 *
	 * @return interface object type as string
	 */
	public String getTypeName()
	{
		return PropertyClient.getObjectTypeName(type);
	}

	/**
	 * Returns the current position of this interface object within the array of interface objects
	 * in the interface object server.
	 * <p>
	 *
	 * @return zero based index as int
	 */
	public int getIndex()
	{
		return idx;
	}

//	/**
//	 * Returns the list of all KNX properties currently contained in this interface
//	 * object.
//	 * <p>
//	 *
//	 * @return a list with all KNX properties
//	 */
//	public Collection getProperties()
//	{
//		return values.values();
//	}

	/*public*/void load(final IosResourceHandler rh, final String resource) throws KNXException
	{
		final List<Description> loadDescriptions = new ArrayList<>();
		final List<byte[]> loadValues = new ArrayList<>();
		rh.loadProperties(resource, loadDescriptions, loadValues);

		final Iterator<byte[]> k = loadValues.iterator();
		for (final Iterator<Description> i = loadDescriptions.iterator(); i.hasNext()
				&& k.hasNext();) {
			final Description d = i.next();
			final byte[] v = k.next();

			setDescription(d);
			values.put(new PropertyKey(d.getObjectType(), d.getPID()), v);
		}
	}

	/*public*/void save(final IosResourceHandler rh, final String resource) throws KNXException
	{
		// list to save with descriptions, containing no null entries
		final List<Description> saveDesc = new ArrayList<>(descriptions);
		saveDesc.removeAll(Arrays.asList(new Object[] { null }));
		// list to save with values
		final List<byte[]> saveVal = new ArrayList<>();
		// values with no description
		final Map<PropertyKey, byte[]> remaining = new HashMap<>(values);

		final byte[] empty = new byte[0];
		for (final Iterator<Description> i = saveDesc.iterator(); i.hasNext();) {
			final Description d = i.next();
			final PropertyKey key = new PropertyKey(d.getObjectType(), d.getPID());
			final byte[] data = values.get(key);
			// descriptions with no values get an empty array assigned
			if (data == null)
				saveVal.add(empty);
			else {
				remaining.remove(key);
				saveVal.add(data.clone());
			}
		}
		// add values where no description was set, creating a default description
		for (final Iterator<PropertyKey> i = remaining.keySet().iterator(); i.hasNext();) {
			final PropertyKey key = i.next();
			saveDesc.add(new Description(idx, type, key.getPID(), saveVal.size(), 0, true, 0, 0, 0,
					0));
			saveVal.add(remaining.get(key).clone());
		}
		// save them
		rh.saveProperties(resource, saveDesc, saveVal);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString()
	{
		return PropertyClient.getObjectTypeName(type) + ", object index " + idx;
	}

	// this method also ensures the value array is truncated accordingly
	void setDescription(final Description d)
	{
		// increase array size until we can insert at requested index
		final int index = d.getPropIndex();
		while (index >= descriptions.size())
			descriptions.add(null);
		descriptions.add(index, d);
		// truncate property elements based on max. allowed elements
		truncateValueArray(d.getPID(), d.getMaxElements());
	}

	void setIndex(final int index)
	{
		idx = index;
	}

	void truncateValueArray(final int pid, final int maxElements)
	{
		final PropertyKey key = new PropertyKey(getType(), pid);
		final byte[] v = values.get(key);
		if (v != null) {
			if (maxElements == 0) {
				values.put(key, null);
				return;
			}
			// extract first two bytes
			final int elems = (v[0] & 0xff) << 8 | v[1] & 0xff;
			if (elems > maxElements) {
				final int elemsFieldSize = 2;
				final int typeSize = (v.length - elemsFieldSize) / elems;
				final byte[] ba = new byte[elemsFieldSize + maxElements * typeSize];
				System.arraycopy(v, elemsFieldSize, ba, elemsFieldSize, ba.length - elemsFieldSize);
				ba[0] = (byte) (maxElements >> 8);
				ba[1] = (byte) maxElements;
				values.put(key, ba);
			}
		}
	}
}
