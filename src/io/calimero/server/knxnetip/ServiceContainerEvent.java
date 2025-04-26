/*
    Calimero 3 - A library for KNX network access
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

package io.calimero.server.knxnetip;

import java.util.EventObject;

import io.calimero.knxnetip.KNXnetIPConnection;

/**
 * Encapsulates common events of a service container.
 *
 * @author B. Malinowsky
 */
public class ServiceContainerEvent extends EventObject
{
	/** The service container is added to a KNXnet/IP server. */
	public static final int ADDED_TO_SERVER = 1;
	/** The service container is removed from a KNXnet/IP server. */
	public static final int REMOVED_FROM_SERVER = 2;
	/** The routing service of the service container started. */
	public static final int ROUTING_SVC_STARTED = 3;
	/** The routing service of the service container stopped. */
	public static final int ROUTING_SVC_STOPPED = 4;

	private final int type;
	private final ServiceContainer sc;
	private final KNXnetIPConnection conn;

	/**
	 * Creates a new service container event.
	 *
	 * @param source the KNXnet/IP server object
	 * @param reason specifies the reason for this event, using an event type
	 * @param svcCont the service container related with this event
	 */
	public ServiceContainerEvent(final KNXnetIPServer source, final int reason,
		final ServiceContainer svcCont)
	{
		super(source);
		sc = svcCont;
		type = reason;
		conn = null;
	}

	/**
	 * Creates a new service container event holding a KNXnet/IP connection.
	 *
	 * @param source the KNXnet/IP server object
	 * @param reason specifies the reason for this event, using an event type
	 * @param svcCont the service container related with this event
	 * @param connection a KNXnet/IP connection object
	 */
	public ServiceContainerEvent(final KNXnetIPServer source, final int reason,
		final ServiceContainer svcCont, final KNXnetIPConnection connection)
	{
		super(source);
		sc = svcCont;
		type = reason;
		conn = connection;
	}

	/**
	 * Returns the event type, supplied as reason during creation of this service container event.
	 *
	 * @return the event type
	 */
	public final int getEventType()
	{
		return type;
	}

	/**
	 * Returns the service container related with this event.
	 *
	 * @return the service container object
	 */
	public final ServiceContainer getContainer()
	{
		return sc;
	}

	/**
	 * Returns a KNXnet/IP connection related with this event, or <code>null</code> if this event is
	 * not related to any service container connection.
	 *
	 * @return the KNXnetIPConnection object, or <code>null</code>
	 */
	public final KNXnetIPConnection getConnection()
	{
		return conn;
	}
}
