/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2014 B. Malinowsky

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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.EventListener;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.Settings;
import tuwien.auto.calimero.cemi.CEMIDevMgmt;
import tuwien.auto.calimero.dptxlator.DPTXlator;
import tuwien.auto.calimero.dptxlator.PropertyTypes;
import tuwien.auto.calimero.dptxlator.TranslatorTypes;
import tuwien.auto.calimero.exception.KNXException;
import tuwien.auto.calimero.exception.KNXFormatException;
import tuwien.auto.calimero.exception.KNXIllegalArgumentException;
import tuwien.auto.calimero.exception.KNXIllegalStateException;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.log.LogLevel;
import tuwien.auto.calimero.log.LogManager;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.mgmt.PropertyAdapter;
import tuwien.auto.calimero.mgmt.PropertyClient;
import tuwien.auto.calimero.mgmt.PropertyClient.Property;
import tuwien.auto.calimero.mgmt.PropertyClient.PropertyKey;
import tuwien.auto.calimero.mgmt.PropertyClient.ResourceHandler;
import tuwien.auto.calimero.xml.Attribute;
import tuwien.auto.calimero.xml.Element;
import tuwien.auto.calimero.xml.EntityResolver;
import tuwien.auto.calimero.xml.KNXMLException;
import tuwien.auto.calimero.xml.XMLFactory;
import tuwien.auto.calimero.xml.XMLReader;
import tuwien.auto.calimero.xml.XMLWriter;

/**
 * An interface object server holds {@link InterfaceObject}s and offers property services for the
 * contained KNX properties.
 * <p>
 * Property access through the property services provided by this class are the preferred way for
 * property access.<br>
 * The interface server provides the {@link IosResourceHandler} to load and save interface object
 * server information from and to a resource. The default resource handler implementation uses an
 * xml format layout. The resource identifier for an xml resource is resolved by
 * {@link EntityResolver}, which accepts common URI specifications.
 * <p>
 * A server instance can maintain KNX property definitions. Such property definitions are used to
 * fill in default values for property descriptions and validation purposes on property access.
 * Definitions are loaded from a definition resource, e.g., a file, handed to the server.<br>
 * For definition resources, by default an xml resource handler implementing the
 * {@link tuwien.auto.calimero.mgmt.PropertyClient.ResourceHandler} interface is used. It supports
 * the same xml schema layout as the default resource handler in the {@link PropertyClient}.
 *
 * @author B. Malinowsky
 */
public class InterfaceObjectServer implements PropertyAccess
{
	private final LogService logger;

	private IosResourceHandler rh;

	// the list of interface objects is not expected to change frequently
	private final List objects;

	private final PropertyClient client;
	private final IosAdapter adapter;

	private final boolean strictMode;

	private final EventListeners listeners = new EventListeners();

	/**
	 * Creates a new interface object server.
	 * <p>
	 * The strict property mode determines the handling of access to properties by the server. If
	 * strict mode is enabled, standard conform procedures are enforced, if disabled, the server
	 * allows a more lazy, convenient, access to properties.<br>
	 * This flag affects behavior for the following property services<br>
	 * - in strict mode:
	 * <ul>
	 * <li>set property: only allowed if corresponding property description exists</li>
	 * </ul>
	 * - in lazy mode:
	 * <ul>
	 * <li>set property: allowed even if corresponding property description does not exist</li>
	 * </ul>
	 * This constructor creates and initializes the following Interface Objects:<br>
	 * - InterfaceObject.DEVICE_OBJECT<br>
	 * - InterfaceObject.CEMI_SERVER_OBJECT<br>
	 * See {@link #addInterfaceObject(int)} for details on creation.
	 *
	 * @param strictPropertyMode <code>true</code> if server shall enforce strict mode,
	 *        <code>false</code> otherwise
	 * @throws KNXFormatException
	 */
	public InterfaceObjectServer(final boolean strictPropertyMode) throws KNXFormatException
	{
		strictMode = strictPropertyMode;

		logger = LogManager.getManager().getLogService("Interface Object Server");
		adapter = new IosAdapter();
		client = new PropertyClient(adapter);

		objects = new ArrayList();

		// AN033 3.2.6: minimum required interface objects for a cEMI server
		// are a device object and a cEMI server object
		addInterfaceObject(InterfaceObject.DEVICE_OBJECT);
		addInterfaceObject(InterfaceObject.CEMI_SERVER_OBJECT);
	}

	/**
	 * Sets a new default Interface Object Server resource handler used in the load/save methods by
	 * this server.
	 * <p>
	 * By default, an xml property file handler is used.
	 *
	 * @param handler the new property resource handler, or <code>null</code> to use the default
	 *        handler
	 */
	public synchronized void setResourceHandler(final IosResourceHandler handler)
	{
		rh = handler;
	}

	/**
	 * Loads property definitions from a resource for use by this IOS.
	 * <p>
	 * If previously set by {@link InterfaceObjectServer#setResourceHandler(
	 * tuwien.auto.calimero.server.InterfaceObjectServer.IosResourceHandler)},
	 * this method uses that resource handler. Otherwise, it uses the default property server
	 * resource handler of this class.
	 *
	 * @param resource the identifier of a resource to load
	 * @throws KNXException on errors in the property resource handler
	 */
	public synchronized void loadDefinitions(final String resource) throws KNXException
	{
		client.addDefinitions(PropertyClient.loadDefinitions(resource, rh));
	}

	/**
	 * Loads interface objects from the specified resource into this interface object server using
	 * the resource handler set by
	 * {@link #setResourceHandler(InterfaceObjectServer.IosResourceHandler)}.
	 * <p>
	 * Any interface objects previously added to this IOS instance are not affected.
	 *
	 * @param resource resource storage location identifier passed to the used IOS resource handler
	 * @throws KNXException on problems loading the interface objects, as thrown by the IOS resource
	 *         handler
	 */
	public void loadInterfaceObjects(final String resource) throws KNXException
	{
		IosResourceHandler h;
		synchronized (this) {
			if (rh == null)
				setResourceHandler(new XmlSerializer(logger));
			h = rh;
		}
		final Collection c = h.loadInterfaceObjects(resource);
		// we insert the objects in iteration order, but correcting the loaded interface
		// object to match the insertion index. this is to avoid null entries in the
		// objects list.
		for (final Iterator i = c.iterator(); i.hasNext();) {
			final InterfaceObject io = (InterfaceObject) i.next();
			synchronized (objects) {
				final int index = objects.size();
				io.setIndex(index);
				objects.add(io);
			}
			// necessary to update index property value to match io index
			initIoProperties(io, false);
		}
		updateIoList();
	}

	/**
	 * Saves the interface objects contained in this interface object server to the specified
	 * resource using the resource handler set by
	 * {@link #setResourceHandler(InterfaceObjectServer.IosResourceHandler)}.
	 * <p>
	 *
	 * @param resource resource storage location identifier passed to the used IOS resource handler
	 * @throws KNXException on problems saving the interface objects, as thrown by the IOS resource
	 *         handler
	 */
	public void saveInterfaceObjects(final String resource) throws KNXException
	{
		final IosResourceHandler h;
		synchronized (this) {
			if (rh == null)
				setResourceHandler(new XmlSerializer(logger));
			h = rh;
		}
		final InterfaceObject[] objects = getInterfaceObjects();
		h.saveInterfaceObjects(resource, Arrays.asList(objects));
	}

	/**
	 * Returns an array with interface objects currently managed by the interface object server.
	 * <p>
	 * Modifications to the array do not alter the internal list of interface objects kept by the
	 * server.<br>
	 * If the server does not contain any interface objects, an array of length 0 is returned.
	 *
	 * @return array of interface objects
	 */
	public InterfaceObject[] getInterfaceObjects()
	{
		synchronized (objects) {
			return (InterfaceObject[]) objects.toArray(new InterfaceObject[objects.size()]);
		}
	}

	/**
	 * Adds an interface object of the specified type to this Interface Object Server.
	 * <p>
	 * A new interface object of that type is created and added at the end of Interface Objects
	 * contained in the IOS, with its index set to the chosen index position.
	 * <p>
	 * In this version of the implementation (might change in the future) the following properties
	 * and property descriptions are set:<br>
	 * - {@link tuwien.auto.calimero.mgmt.PropertyAccess.PID#OBJECT_TYPE} and property description,
	 * representing the interface object type<br>
	 * - PID.OBJECT_INDEX and property description, holding the index of the interface object<br>
	 *
	 * @param objectType Interface Object type, see {@link InterfaceObject} constants
	 */
	public void addInterfaceObject(final int objectType)
	{
		final InterfaceObject io;
		final int index;
		synchronized (objects) {
			index = objects.size();
			io = new InterfaceObject(objectType, index);
			objects.add(io);
			updateIoList();
		}
		initIoProperties(io, true);
	}

	/**
	 * Removes the specified interface object from the list of interface objects maintained by this
	 * Interface Object Server.
	 * <p>
	 *
	 * @param io the interface object to remove
	 */
	public void removeInterfaceObject(final InterfaceObject io)
	{
		synchronized (objects) {
			objects.remove(io);
		}
	}

	/**
	 * Adds the specified event listener <code>l</code> to receive events from this interface object
	 * server.
	 * <p>
	 * If <code>l</code> was already added as listener, no action is performed.
	 *
	 * @param l the listener to add
	 */
	public void addServerListener(final InterfaceObjectServerListener l)
	{
		listeners.add(l);
	}

	/**
	 * Removes the specified event listener <code>l</code>, so it does no longer receive events from
	 * this interface object server.
	 * <p>
	 * If <code>l</code> was not added in the first place, no action is performed.
	 *
	 * @param l the listener to remove
	 */
	public void removeServerListener(final InterfaceObjectServerListener l)
	{
		listeners.remove(l);
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.mgmt.PropertyAccess#getProperty(int, int, int, int)
	 */
	public byte[] getProperty(final int objectIndex, final int propertyId, final int start,
		final int elements) throws KNXPropertyException
	{
		return adapter.getProperty(objectIndex, propertyId, start, elements);
	}

	/**
	 * {@inheritDoc} The current number of value elements maintained by a property can be reset to 0
	 * elements the following way: invoke for the property in question, with parameters
	 * <code>start = 0</code>, <code>elements = 1</code>, and <code>data = { 0, 0 }</code> . This
	 * removes all value elements of that property, with the current number of elements (as obtained
	 * by {@link #getDescription(int, int)}) becoming 0.
	 */
	public void setProperty(final int objectIndex, final int propertyId, final int start,
		final int elements, final byte[] data) throws KNXPropertyException
	{
		adapter.setProperty(objectIndex, propertyId, start, elements, data);
	}

	/**
	 * See {@link #setProperty(int, int, int, int, byte[])}, but uses the object type and object
	 * instance to refer to the interface object.
	 * <p>
	 *
	 * @param objectType object type of the interface object containing the KNX property
	 * @param objectInstance object instance of the interface object in the server, 1 refers to the
	 *        first instance
	 * @param propertyId see {@link #setProperty(int, int, int, int, byte[])}
	 * @param start see {@link #setProperty(int, int, int, int, byte[])}
	 * @param elements see {@link #setProperty(int, int, int, int, byte[])}
	 * @param data see {@link #setProperty(int, int, int, int, byte[])}
	 * @throws KNXPropertyException see {@link #setProperty(int, int, int, int, byte[])}
	 */
	public void setProperty(final int objectType, final int objectInstance, final int propertyId,
		final int start, final int elements, final byte[] data) throws KNXPropertyException
	{
		adapter.setProperty(objectType, objectInstance, propertyId, start, elements, data);
	}

	/**
	 * See {@link #getProperty(int, int, int, int)}, but uses the object type and object instance to
	 * refer to the interface object.
	 * <p>
	 *
	 * @param objectType object type of the interface object containing the KNX property
	 * @param objectInstance object instance of the interface object in the server, 1 refers to the
	 *        first instance
	 * @param propertyId see {@link #getProperty(int, int, int, int)}
	 * @param start see {@link #getProperty(int, int, int, int)}
	 * @param elements see {@link #getProperty(int, int, int, int)}
	 * @return see {@link #getProperty(int, int, int, int)}
	 * @throws KNXPropertyException see {@link #getProperty(int, int, int, int)}
	 */
	public byte[] getProperty(final int objectType, final int objectInstance, final int propertyId,
		final int start, final int elements) throws KNXPropertyException
	{
		return adapter.getProperty(objectType, objectInstance, propertyId, start, elements);
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.mgmt.PropertyAccess
	 * #setProperty(int, int, int, java.lang.String)
	 */
	public void setProperty(final int objIndex, final int propertyId, final int position,
		final String value) throws KNXException
	{
		client.setProperty(objIndex, propertyId, position, value);
	}

	/**
	 * Gets one or more elements of a property with the returned data set in a DPT translator of the
	 * associated data type.
	 * <p>
	 *
	 * @param objIndex interface object index in the device
	 * @param pid property identifier
	 * @param start index of the first array element to get
	 * @param elements number of elements to get in the property
	 * @return a DPT translator containing the returned the element data
	 * @throws KNXException on adapter errors while querying the property element or data type
	 *         translation problems
	 */
	public DPTXlator getPropertyTranslated(final int objIndex, final int pid, final int start,
		final int elements) throws KNXException
	{
		return client.getPropertyTranslated(objIndex, pid, start, elements);
	}

	/**
	 * Sets the property description for a KNX property.
	 * <p>
	 * The property description is set to describe the property contained in the interface object
	 * referred to by <code>d.getObjectIndex()</code>. If the object index refers to a global
	 * property, the description describes a KNX property allowed in any interface object. An
	 * already existing property description for that property is replaced by <code>d</code>. Actual
	 * property values for the property described do not have to exist yet.
	 * <p>
	 * The interface object server checks the description against the referred interface object to
	 * ensure a valid property description. If the caller allows corrections to the description,
	 * differing description entries are adjusted so they match (e.g., the object type). If no
	 * corrections are allowed, an {@link KNXIllegalArgumentException} is thrown if validation
	 * failed.<br>
	 * A caller can benefit from this behavior and leave the object type, property index, current
	 * elements, and property data type (PDT) empty and let the server fill in those details.
	 *
	 * @param d the KNX property description to set
	 * @param allowCorrections <code>true</code> to allow corrections by the interface object server
	 *        to the description, <code>false</code> otherwise
	 */
	public void setDescription(final Description d, final boolean allowCorrections)
	{
		// do some validity checks before setting the description
		// tells us whether we have to create a corrected description before inserting
		boolean adjust = false;

		final InterfaceObject io = getIfObject(d.getObjectIndex());

		final int type = io.getType();
		if (d.getObjectType() != type) {
			if (!allowCorrections)
				throw new KNXIllegalArgumentException("interface object type differs");
			adjust = true;
		}

		int idx;
		int existingIdx = 0;
		int pdt = 0;
		// check if a description already exists
		try {
			final Description chk = getDescription(d.getObjectIndex(), d.getPID());
			existingIdx = chk.getPropIndex();
			idx = existingIdx;
			pdt = chk.getPDT();
		}
		catch (final KNXPropertyException e) {
			// no existing description, find an empty position index
			idx = io.descriptions.indexOf(null);
			if (idx == -1)
				idx = io.descriptions.size();
		}
		// ensure object type property is on first position
		if (d.getPID() == PID.OBJECT_TYPE) {
			if (d.getPropIndex() != 0) {
				if (!allowCorrections)
					throw new KNXIllegalArgumentException(
							"property 'object type' (PID 1) only allowed at index 0");
				adjust = true;
				idx = 0;
			}
		}
		else if (d.getPropIndex() == 0) {
			if (!allowCorrections)
				throw new KNXIllegalArgumentException(
						"only property 'object type' (PID 1) allowed at index 0");
			adjust = true;
		}
		else
			idx = d.getPropIndex();

		if (d.getMaxElements() < d.getCurrentElements()) {
			if (!allowCorrections)
				throw new KNXIllegalArgumentException("maximum elements less than current elements");
		}

		if (d.getPDT() == 0 && allowCorrections) {
			// if no existing description or no pdt was set
			if (pdt == 0) {
				final Property p = getDefinition(type, d.getPID());
				if (p != null)
					pdt = p.getPDT();
			}
			if (pdt != 0)
				adjust = true;
		}
		else
			pdt = d.getPDT();

		// check if we have to remove an existing description (which might be located at
		// a different index)
		// Note: existingIdx = 0 refers to a non existing description and an existing
		// description at index 0
		// But index 0 is a special case because the object-type property description is
		// fixed to that position; therefore, we never have to remove it, it is always
		// replaced correctly
		if (existingIdx != 0)
			io.descriptions.set(existingIdx, null);

		// NB: the current elements field used here is meaningless
		final Description set = adjust ? new Description(d.getObjectIndex(), type, d.getPID(), idx,
				pdt, d.isWriteEnabled(), d.getCurrentElements(), d.getMaxElements(),
				d.getReadLevel(), d.getWriteLevel()) : d;
		io.setDescription(set);
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.mgmt.PropertyAccess#getDescription(int, int)
	 */
	public Description getDescription(final int objIndex, final int pid)
		throws KNXPropertyException
	{
		try {
			return client.getDescription(objIndex, pid);
		}
		catch (final KNXException e) {
			// forward all KNXPropertyExceptions from our adapter
			if (e instanceof KNXPropertyException)
				throw (KNXPropertyException) e;
			// KNXException is currently thrown by PropertyClient.getObjectType,
			// quite unnecessary to use that base type exception (maybe rework).
			final KNXPropertyException pe = new KNXPropertyException(e.getMessage());
			pe.setStackTrace(e.getStackTrace());
			throw pe;
		}
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.mgmt.PropertyAccess#getDescriptionByIndex(int, int)
	 */
	public Description getDescriptionByIndex(final int objIndex, final int propIndex)
		throws KNXPropertyException
	{
		try {
			return client.getDescriptionByIndex(objIndex, propIndex);
		}
		catch (final KNXException e) {
			// forward all KNXPropertyExceptions from our adapter
			if (e instanceof KNXPropertyException)
				throw (KNXPropertyException) e;
			// KNXException is currently thrown by PropertyClient.getObjectType,
			// quite unnecessary to use that base type exception (maybe rework).
			// note that we loose the stack trace up to here
			final KNXPropertyException pe = new KNXPropertyException(e.getMessage());
			pe.setStackTrace(e.getStackTrace());
			throw pe;
		}
	}

	private void updateIoList()
	{
		final InterfaceObject io = (InterfaceObject) objects.get(0);
		if (io == null || io.getType() != InterfaceObject.DEVICE_OBJECT)
			throw new KNXIllegalStateException("IOS is missing mandatory device object");
		// the IO_LIST property values have to be in ascending order
		// first, read the object types out
		final int items = objects.size();
		final int[] types = new int[items];
		int k = 0;
		for (final Iterator i = objects.iterator(); i.hasNext();)
			types[k++] = ((InterfaceObject) i.next()).getType();

		// now sort'em asc
		Arrays.sort(types);
		// write them into byte array format
		final byte[] value = new byte[(items + 1) * 2];
		value[0] = (byte) (items >> 8);
		value[1] = (byte) items;
		for (int i = 0; i < types.length; ++i) {
			final int type = types[i];
			value[2 + 2 * i] = (byte) (type >> 8);
			value[2 + 2 * i + 1] = (byte) type;
		}
		((InterfaceObject) objects.get(0)).values.put(new PropertyKey(
				InterfaceObject.DEVICE_OBJECT, PID.IO_LIST), value);
	}

	void initIoProperties(final InterfaceObject io, final boolean createDescription)
	{
		final int objectType = io.getType();
		final int index = io.getIndex();
		// add object type property to the interface object
		io.values.put(new PropertyKey(objectType, PID.OBJECT_TYPE), new byte[] { 0, 1,
			(byte) (objectType >> 8), (byte) objectType });
		if (createDescription)
			adapter.createNewDescription(index, PID.OBJECT_TYPE);

		// AN104: global property PID.OBJECT_INDEX holds index of the if-object
		io.values.put(new PropertyKey(objectType, PID.OBJECT_INDEX), new byte[] { 0, 1,
			(byte) (index >> 8), (byte) index });
		if (createDescription)
			adapter.createNewDescription(index, PID.OBJECT_INDEX);
	}

	private void firePropertyChanged(final InterfaceObject io, final int propertyId,
		final int start, final int elements, final byte[] data)
	{
		final PropertyEvent fe = new PropertyEvent(this, io, propertyId, start, elements, data);
		final EventListener[] el = listeners.listeners();
		for (int i = 0; i < el.length; i++) {
			final InterfaceObjectServerListener l = (InterfaceObjectServerListener) el[i];
			try {
				l.onPropertyValueChanged(fe);
			}
			catch (final RuntimeException e) {
				removeServerListener(l);
				logger.error("removed event listener", e);
			}
		}
	}

	private Property getDefinition(final int objectType, final int pid)
	{
		final Map defs = client.getDefinitions();
		if (defs == null)
			return null;
		Property p = (Property) defs.get(new PropertyKey(objectType, pid));
		if (p == null && pid < 50)
			p = (Property) defs.get(new PropertyKey(pid));
		return p;
	}

	private InterfaceObject getIfObject(final int objIndex)
	{
		synchronized (objects) {
			for (final Iterator i = objects.iterator(); i.hasNext();) {
				final InterfaceObject io = (InterfaceObject) i.next();
				if (io.getIndex() == objIndex)
					return io;
			}
		}
		throw new KNXIllegalArgumentException("interface object index " + objIndex
				+ " past last interface object");
	}

	private InterfaceObject findByObjectType(final int objectType, final int objectInstance)
		throws KNXPropertyException
	{
		synchronized (objects) {
			int inst = 0;
			for (final Iterator i = objects.iterator(); i.hasNext();) {
				final InterfaceObject io = (InterfaceObject) i.next();
				if (io.getType() == objectType && ++inst == objectInstance)
					return io;
			}
			throw new KNXPropertyException("no object instance " + objectInstance + " of "
					+ PropertyClient.getObjectTypeName(objectType) + " in IOS");
		}
	}

	private static int toInt(final byte[] data)
	{
		if (data.length == 1)
			return data[0] & 0xff;
		if (data.length == 2)
			return (data[0] & 0xff) << 8 | data[1] & 0xff;
		return (data[0] & 0xff) << 24 | (data[1] & 0xff) << 16 | (data[2] & 0xff) << 8 | data[3]
				& 0xff;
	}

	// Adapter only throws KNXPropertyException on get/set property/desc
	private final class IosAdapter implements PropertyAdapter
	{
		IosAdapter()
		{}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.mgmt.PropertyAdapter
		 * #setProperty(int, int, int, int, byte[])
		 */
		public void setProperty(final int objIndex, final int pid, final int start,
			final int elements, final byte[] data) throws KNXPropertyException
		{
			setProperty(getIfObject(objIndex), pid, start, elements, data);
		}

		public void setProperty(final int objectType, final int objectInstance,
			final int propertyId, final int start, final int elements, final byte[] data)
			throws KNXPropertyException
		{
			setProperty(findByObjectType(objectType, objectInstance), propertyId, start, elements,
					data);
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.mgmt.PropertyAdapter#getProperty(int, int, int, int)
		 */
		public byte[] getProperty(final int objIndex, final int pid, final int start,
			final int elements) throws KNXPropertyException
		{
			return getProperty(getIfObject(objIndex), pid, start, elements);
		}

		public byte[] getProperty(final int objectType, final int objectInstance,
			final int propertyId, final int start, final int elements) throws KNXPropertyException
		{
			return getProperty(findByObjectType(objectType, objectInstance), propertyId, start,
					elements);
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.mgmt.PropertyAdapter#getDescription(int, int, int)
		 */
		public byte[] getDescription(final int objIndex, final int pid, final int propIndex)
			throws KNXPropertyException
		{
			final InterfaceObject io = getIfObject(objIndex);
			Description d = null;
			if (pid != 0)
				d = findByPid(io.descriptions, pid);
			else {
				if (propIndex >= io.descriptions.size())
					throw new KNXIllegalArgumentException("property index past last property");
				d = (Description) io.descriptions.get(propIndex);
			}
			if (d != null) {
				// actual property values might not exist yet
				int elems = 0;
				try {
					elems = toInt(getProperty(objIndex, pid, 0, 1));
				}
				catch (final KNXPropertyException e) {}
				return new Description(objIndex, d.getObjectType(), d.getPID(), d.getPropIndex(),
						d.getPDT(), d.isWriteEnabled(), elems, d.getMaxElements(),
						d.getReadLevel(), d.getWriteLevel()).toByteArray();
			}
			throw new KNXPropertyException("no description found for "
					+ PropertyClient.getObjectTypeName(io.getType())
					+ (pid != 0 ? " PID " + pid : " property index " + propIndex));
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.mgmt.PropertyAdapter#getName()
		 */
		public String getName()
		{
			return "Calimero IOS adapter";
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.mgmt.PropertyAdapter#isOpen()
		 */
		public boolean isOpen()
		{
			return true;
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.mgmt.PropertyAdapter#close()
		 */
		public void close()
		{}

		private void setProperty(final InterfaceObject io, final int pid, final int start,
			final int elements, final byte[] data) throws KNXPropertyException
		{
			final PropertyKey key = new PropertyKey(io.getType(), pid);
			byte[] values = (byte[]) io.values.get(key);

			if (start == 0) {
				// Document Application IF Layer (03/04/01) v1.1, 4.2.1:
				// Write value 0 on index 0 to reset element values
				if (elements == 1 && data.length == 2 && data[0] == 0 && data[1] == 0) {
					io.truncateValueArray(pid, 0);
					return;
				}
				throw new KNXPropertyException("current number of elements is read-only",
						CEMIDevMgmt.ErrorCodes.READ_ONLY);
			}

			// try to get property type size, using the following order:
			// 1) query description
			// 2) query definitions
			// 3) use dptId
			// 4) trust input parameters and calculate type size

			// NYI optimization: remember type size value once we read it out from
			// somewhere for subsequent use (also nice to have when saving the
			// interface objects to a resource)
			int typeSize = 0;
			int pdt = 0;
			String dptId = null;
			Description d = null;
			try {
				d = new Description(io.getType(), getDescription(io, pid, 0));
				pdt = d.getPDT();
			}
			catch (final KNXPropertyException e) {
				if (strictMode)
					throw new KNXPropertyException("strict mode: no description found for "
							+ io.getTypeName() + " PID " + pid);
				final Property p = getDefinition(io.getType(), pid);
				if (p != null) {
					pdt = p.getPDT();
					dptId = p.getDPT();
				}
			}
			if (pdt != 0)
				try {
					typeSize = PropertyTypes.createTranslator(pdt).getTypeSize();
					// round bit values up to 1 byte
					if (typeSize == 0)
						typeSize = 1;
				}
				catch (final KNXException e) {}
			if (typeSize == 0 && dptId != null)
				try {
					typeSize = TranslatorTypes.createTranslator(0, dptId).getTypeSize();
					// round bit values up to 1 byte
					if (typeSize == 0)
						typeSize = 1;
				}
				catch (final KNXException e) {}

			// if typeSize != 0, enforce correct type size, otherwise trust input
			if (typeSize == 0)
				typeSize = data.length / elements;
			else if (typeSize != data.length / elements)
				throw new KNXPropertyException("property type size is " + typeSize + ", not "
						+ data.length / elements, CEMIDevMgmt.ErrorCodes.TYPE_CONFLICT);

			// I dynamically increase the value array if the new element size exceeds
			// the current element size, and adjust the current element number
			// correspondingly.
			final int size = start + elements - 1;
			if (values == null || size > (values.length - 2) / typeSize) {
				// max elements of 100 randomly chosen in absence of a user setting
				final int maxElements = d == null ? 100 : d.getMaxElements();
				if (size > maxElements)
					throw new KNXPropertyException("property values index range [" + start + "..."
							+ size + "] exceeds " + maxElements + " maximum elements",
							CEMIDevMgmt.ErrorCodes.PROP_INDEX_RANGE_ERROR);
				// create resized array
				final byte[] resize = new byte[2 + size * typeSize];
				resize[0] = (byte) (size >> 8);
				resize[1] = (byte) size;
				// copy over existing values, if any
				if (values != null)
					for (int i = 2; i < values.length; ++i)
						resize[i] = values[i];

				io.values.put(key, resize);
				values = resize;
			}
			int k = 0;
			for (int i = 2 + (start - 1) * typeSize; i < 2 + size * typeSize; ++i)
				values[i] = data[k++];

			firePropertyChanged(io, pid, start, elements, data);
		}

		private byte[] getProperty(final InterfaceObject io, final int pid, final int start,
			final int elements) throws KNXPropertyException
		{
			final byte[] values = (byte[]) io.values.get(new PropertyKey(io.getType(), pid));

			if (start == 0) {
				if (elements > 1)
					throw new KNXPropertyException("current number of elements consists "
							+ "of 1 element only", CEMIDevMgmt.ErrorCodes.UNSPECIFIED_ERROR);

				if (values != null)
					return new byte[] { values[0], values[1] };

				// no current number of elements field yet since values array is null:
				// check if description exists, if yes return 0 elements, otherwise throw
				if (findByPid(io.descriptions, pid) != null)
					return new byte[] { 0, 0 };
			}

			if (values == null)
				throw new KNXPropertyException("property ID " + pid + " in " + io.getTypeName()
						+ " (index " + io.getIndex() + ") not found",
						CEMIDevMgmt.ErrorCodes.VOID_DP);

			final int currElems = (values[0] & 0xff) << 8 | values[1] & 0xff;
			final int size = start + elements - 1;
			if (currElems < size)
				throw new KNXPropertyException(
						"requested elements exceed past last property value",
						CEMIDevMgmt.ErrorCodes.PROP_INDEX_RANGE_ERROR);
			final int typeSize = (values.length - 2) / currElems;
			final byte[] data = new byte[elements * typeSize];
			int d = 0;
			for (int i = 2 + (start - 1) * typeSize; i < 2 + size * typeSize; ++i)
				data[d++] = values[i];
			return data;
		}

		private byte[] getDescription(final InterfaceObject io, final int pid, final int propIndex)
			throws KNXPropertyException
		{
			Description d = null;
			if (pid != 0)
				d = findByPid(io.descriptions, pid);
			else {
				if (propIndex >= io.descriptions.size())
					throw new KNXIllegalArgumentException("property index " + propIndex
							+ " past last property");
				d = (Description) io.descriptions.get(propIndex);
			}
			if (d != null) {
				// actual property values might not exist yet
				int elems = 0;
				try {
					elems = toInt(getProperty(io, pid, 0, 1));
				}
				catch (final KNXPropertyException e) {}
				return new Description(io.getIndex(), d.getObjectType(), d.getPID(),
						d.getPropIndex(), d.getPDT(), d.isWriteEnabled(), elems,
						d.getMaxElements(), d.getReadLevel(), d.getWriteLevel()).toByteArray();
			}
			throw new KNXPropertyException("no description found for "
					+ PropertyClient.getObjectTypeName(io.getType())
					+ (pid != 0 ? " PID " + pid : " property index " + propIndex));
		}

		private Description createNewDescription(final int objIndex, final int pid)
		{
			Description d;
			final int objectType = getObjectType(objIndex);
			int pdt = 0;
			final Property p = getDefinition(objectType, pid);
			if (p != null)
				pdt = p.getPDT();
			final InterfaceObject io = getIfObject(objIndex);
			final int pIndex = io.descriptions.size();
			int elems = 0;
			try {
				elems = toInt(getProperty(objIndex, pid, 0, 1));
			}
			catch (final KNXPropertyException e) {}
			final int maxElems = 100;
			// level is between 0 (max. access rights) and 3 (min. rights),
			// or 0 (max. access rights) and 15 (min. rights)
			final int readLevel = 0;
			final int writeLevel = 0;
			d = new Description(objIndex, objectType, pid, pIndex, pdt, true, elems, maxElems,
					readLevel, writeLevel);
			io.descriptions.add(d);
			return d;
		}

		private Description findByPid(final List descriptions, final int pid)
		{
			// descriptions are stored at their property index in the list,
			// so the list can contain null entries
			for (final Iterator i = descriptions.iterator(); i.hasNext();) {
				final Description d = (Description) i.next();
				if (d != null && d.getPID() == pid)
					return d;
			}
			return null;
		}

		private int getObjectType(final int objIndex)
		{
			return getIfObject(objIndex).getType();
		}
	}

	/**
	 * Interface for serializing and deserializing Interface Object Server (IOS) information.
	 * <p>
	 * This interface provides methods to load and save interface objects, together with the
	 * contained KNX properties. A property item includes the property description, and property
	 * element values.<br>
	 * The resource format used to persist the data is implementation specific.
	 */
	public static interface IosResourceHandler extends ResourceHandler
	{
		/**
		 * Reads interface object data from a resource identified by <code>resource</code> , and
		 * creates {@link InterfaceObject}s.
		 * <p>
		 *
		 * @param resource identifies the resource to read from
		 * @return a collection of all loaded interface objects of type {@link InterfaceObject}
		 * @throws KNXException on errors accessing the resource, parsing the data, or creating the
		 *         interface objects
		 */
		Collection loadInterfaceObjects(final String resource) throws KNXException;

		/**
		 * Saves interface objects to a resource identified by <code>resource</code>.
		 * <p>
		 * All information maintained by an interface object are subject to serialization, this
		 * includes all of its KNX property information.
		 *
		 * @param resource identifies the resource to save to
		 * @param ifObjects a collection of interface objects, type {@link InterfaceObject}, to save
		 * @throws KNXException on errors accessing the resource, or saving the data
		 */
		void saveInterfaceObjects(final String resource, final Collection ifObjects)
			throws KNXException;

		/**
		 * Reads KNX property data from a resource identified by <code>resource</code>, and loads
		 * description information into objects of type {@link Description} and KNX property element
		 * values as <code>byte[]</code> objects.
		 * <p>
		 * When the method returns, <code>descriptions</code> and <code>values</code> contain the
		 * loaded {@link Description} and <code>byte[]</code> objects, respectively.
		 *
		 * @param resource identifies the resource to read from
		 * @param descriptions a collection with the loaded description objects added to it
		 * @param values a collection with the loaded property element values added to it, of type
		 *        <code>byte[]</code>
		 * @throws KNXException on errors accessing the resource, parsing the data, or object
		 *         creation
		 */
		void loadProperties(final String resource, final Collection descriptions,
			final Collection values) throws KNXException;

		/**
		 * Saves KNX property information to a resource identified by <code>resource</code>.
		 * <p>>
		 * The two collections <code>descriptions</code> and <code>values</code> holding the KNX
		 * property descriptions and property element data are associated by the collection's
		 * iterators {@link Collection#iterator()}: the n<sup>th</sup> description element returned
		 * by the <code>descriptions</code> iterator corresponds to the n<sup>th</sup> value element
		 * returned by the <code>values</code> iterator.
		 *
		 * @param resource identifies the resource to save to
		 * @param descriptions a collection of property descriptions, of type {@link Description}
		 * @param values a collection of property value data, of type <code>byte[]</code>; every
		 *        <code>values</code> entry corresponds to one <code>descriptions</code> entry,
		 *        aligned by the {@link Iterator#next()} behavior of the supplied collections
		 * @throws KNXException
		 */
		void saveProperties(final String resource, final Collection descriptions,
			final Collection values) throws KNXException;
	}

	private static class XmlSerializer implements IosResourceHandler
	{
		private static final String TAG_IOS = "interfaceObjects";

		private static final String TAG_OBJECT = "object";
		private static final String ATTR_OBJECTTYPE = "type";

		private static final String TAG_PROPERTY = "property";
		private static final String ATTR_PID = "pid";
		private static final String ATTR_INDEX = "index";
		private static final String ATTR_PDT = "pdt";
		private static final String ATTR_RW = "rw";
		private static final String ATTR_WRITE = "writeEnabled";
		private static final String ATTR_ELEMS = "elements";
		private static final String ATTR_MAXELEMS = "maxElements";

		private static final String TAG_DATA = "data";

		private ResourceHandler rh;

		private XMLReader r;
		private XMLWriter w;

		private final LogService logger;

		XmlSerializer(final LogService l)
		{
			logger = l;
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.mgmt.PropertyClient.ResourceHandler
		 * #load(java.lang.String)
		 */
		public Collection load(final String resource) throws KNXException
		{
			return rh.load(resource);
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.mgmt.PropertyClient.ResourceHandler
		 * #save(java.lang.String, java.util.Collection)
		 */
		public void save(final String resource, final Collection properties) throws KNXException
		{
			rh.save(resource, properties);
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.server.InterfaceObjectServer.IOSResourceHandler
		 * #loadInterfaceObjects(java.lang.String)
		 */
		public Collection loadInterfaceObjects(final String resource) throws KNXException
		{
			r = XMLFactory.getInstance().createXMLReader(resource);
			final List list = new ArrayList();
			try {
				if (r.read() != XMLReader.START_TAG || !r.getCurrent().getName().equals(TAG_IOS))
					throw new KNXMLException("no interface objects");
				while (r.read() != XMLReader.END_DOC) {
					final Element e = r.getCurrent();
					if (r.getPosition() == XMLReader.START_TAG) {
						if (e.getName().equals(TAG_OBJECT)) {
							// on no type attribute, toInt() throws, that's ok
							final int type = toInt(e.getAttribute(ATTR_OBJECTTYPE));
							final int index = toInt(e.getAttribute(ATTR_INDEX));
							final InterfaceObject io = new InterfaceObject(type, index);
							list.add(io);
							io.load(this, resource);
						}
					}
					else if (r.getPosition() == XMLReader.END_TAG && e.getName().equals(TAG_IOS))
						break;
				}
				return list;
			}
			catch (final NumberFormatException e) {
				throw new KNXFormatException("loading interface objects, " + e.getMessage());
			}
			finally {
				r.close();
			}
		}

		/* (non-Javadoc)
		 * @see tuwien.auto.calimero.server.InterfaceObjectServer.IOSResourceHandler
		 * #saveInterfaceObjects(java.lang.String, java.util.Collection)
		 */
		public void saveInterfaceObjects(final String resource, final Collection objects)
			throws KNXException
		{
			w = XMLFactory.getInstance().createXMLWriter(resource);
			try {
				w.writeDeclaration(true, "UTF-8");
				w.writeComment("Calimero 2 " + Settings.getLibraryVersion()
						+ " interface objects, saved on " + new Date().toString());
				w.writeElement(TAG_IOS, null, null);
				for (final Iterator i = objects.iterator(); i.hasNext();) {
					final InterfaceObject io = (InterfaceObject) i.next();
					final List att = new ArrayList();
					att.add(new Attribute(ATTR_OBJECTTYPE, Integer.toString(io.getType())));
					att.add(new Attribute(ATTR_INDEX, Integer.toString(io.getIndex())));
					w.writeElement(TAG_OBJECT, att, null);
					io.save(this, resource);
					w.endElement();
				}
			}
			finally {
				w.close();
			}
		}

		public void loadProperties(final String resource, final Collection descriptions,
			final Collection values) throws KNXException
		{
			try {
				int type = 0;
				int oi = 0;
				if (r.getCurrent().getName().equals(TAG_OBJECT)) {
					type = toInt(r.getCurrent().getAttribute(ATTR_OBJECTTYPE));
					oi = toInt(r.getCurrent().getAttribute(ATTR_INDEX));
				}
				// For every added property description, one property element value is
				// required; this toggle bit makes sure we keep aligned in case a xml
				// property element does not contain a data element. And since we are
				// not validating the xml schema, this should be enough.
				boolean valueExpected = false;
				final byte[] emptyValue = new byte[0];

				while (r.read() != XMLReader.END_DOC) {
					final Element e = r.getCurrent();
					if (r.getPosition() == XMLReader.START_TAG) {
						if (e.getName().equals(TAG_PROPERTY)) {
							final int index = toInt(e.getAttribute(ATTR_INDEX));
							final int elems = toInt(e.getAttribute(ATTR_ELEMS));
							final int maxElems = toInt(e.getAttribute(ATTR_MAXELEMS));
							final int rw = parseRW(e.getAttribute(ATTR_RW));
							final int rLevel = rw >> 8;
							final int wLevel = rw & 0xff;
							final Description d = new Description(oi, type,
									toInt(e.getAttribute(ATTR_PID)), index,
									toInt(e.getAttribute(ATTR_PDT)),
									toInt(e.getAttribute(ATTR_WRITE)) == 1, elems, maxElems,
									rLevel, wLevel);
							descriptions.add(d);
							if (valueExpected)
								values.add(emptyValue);
							valueExpected = true;
							if (logger.isLoggable(LogLevel.TRACE))
								logger.trace(d.toString());
						}
						else if (e.getName().equals(TAG_DATA)) {
							r.complete(e);
							final String s = e.getCharacterData();
							if (logger.isLoggable(LogLevel.TRACE))
								logger.trace(s);
							final int odd = s.length() % 2;
							final byte[] data = new byte[s.length() / 2 + odd];
							if (odd == 1)
								data[0] = Byte.parseByte(s.substring(0, 1), 16);
							for (int i = 1; i < data.length; ++i)
								data[i] = Byte.parseByte(s.substring(i * 2 - odd, i * 2 + 2 - odd),
										16);
							values.add(data);
							valueExpected = false;
						}
					}
					else if (r.getPosition() == XMLReader.END_TAG && e.getName().equals(TAG_OBJECT))
						break;
				}
			}
			catch (final NumberFormatException e) {
				throw new KNXFormatException("loading properties, " + e.getMessage());
			}
		}

		public void saveProperties(final String resource, final Collection descriptions,
			final Collection values) throws KNXException
		{
			if (values.size() < descriptions.size())
				throw new KNXIllegalArgumentException("values size " + values.size()
						+ " less than descriptions size " + descriptions.size());
			final Iterator k = values.iterator();
			for (final Iterator i = descriptions.iterator(); i.hasNext();) {
				final Description d = (Description) i.next();
				final byte[] data = (byte[]) k.next();
				final List att = new ArrayList();
				att.add(new Attribute(ATTR_INDEX, Integer.toString(d.getPropIndex())));
				att.add(new Attribute(ATTR_PID, Integer.toString(d.getPID())));
				att.add(new Attribute(ATTR_PDT, d.getPDT() == -1 ? "<tbd>" : Integer.toString(d
						.getPDT())));
				att.add(new Attribute(ATTR_ELEMS, Integer.toString(d.getCurrentElements())));
				att.add(new Attribute(ATTR_MAXELEMS, Integer.toString(d.getMaxElements())));
				att.add(new Attribute(ATTR_RW, Integer.toString(d.getReadLevel()) + "/"
						+ Integer.toString(d.getWriteLevel())));
				att.add(new Attribute(ATTR_WRITE, d.isWriteEnabled() ? "1" : "0"));
				w.writeElement(TAG_PROPERTY, att, null);
				w.writeElement(TAG_DATA, null, DataUnitBuilder.toHex(data, ""));
				w.endElement();
				w.endElement();
			}
			while (k.hasNext()) {
				final byte[] data = (byte[]) k.next();
				final List att = new ArrayList();
				w.writeElement(TAG_PROPERTY, att, null);
				w.writeElement(TAG_DATA, null, DataUnitBuilder.toHex(data, ""));
				w.endElement();
				w.endElement();
			}
		}

		private static int parseRW(final String rw)
		{
			final String s = rw.toLowerCase();
			int read = 0;
			int write = 0;
			boolean slash = false;
			for (int i = 0; i < s.length(); i++) {
				final char c = s.charAt(i);
				if (c == '/')
					slash = true;
				else if (c >= '0' && c <= '9')
					if (slash)
						write = write * 10 + c - '0';
					else
						read = read * 10 + c - '0';
			}
			return read << 8 | write;
		}

		private static int toInt(final String s) throws NumberFormatException
		{
			if (s != null) {
				if (s.equals("<tbd>"))
					return -1;
				return s.length() == 0 ? 0 : Integer.decode(s).intValue();
			}
			throw new NumberFormatException("no integer number: " + s);
		}
	}
}
