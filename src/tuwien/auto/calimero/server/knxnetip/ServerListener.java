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

package tuwien.auto.calimero.server.knxnetip;

import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.knxnetip.KNXnetIPConnection;
import tuwien.auto.calimero.server.InterfaceObjectServerListener;

/**
 * A listener for use with a {@link KNXnetIPServer}.
 * <p>
 * 
 * @author B. Malinowsky
 */
public interface ServerListener extends InterfaceObjectServerListener
{
	/**
	 * Notifies about a new data connection request from a client and gives the callee a chance to
	 * accept or reject the connection.
	 * <p>
	 * Depending on the return code of this method, the connection, i.e., the <code>conn</code>
	 * object, is either accepted and activated (on returning <code>true</code>) or rejected (on
	 * returning <code>false</code>). On accept, the connection is added to the list of active
	 * connection in the KNXnet/IP server and the client end point of the connection can proceed. On
	 * reject, the client is notified in the subsequent connection-request response that no more
	 * connections are accepted (KNXnet/IP error code NO_MORE_CONNECTIONS) and the
	 * <code>connection</code> object is closed and its resources freed.
	 * <p>
	 * During invocation of this method, do not use <code>connection</code> for sending frames. The
	 * connection is not fully activated yet, and is allowed to be in any intermediate state;
	 * behavior at this stage is implementation defined and subject to change.
	 * 
	 * @param connection the new connection to be accepted or rejected, the callee can store a
	 *        reference to it for later use
	 * @param assignedDeviceAddress the KNX device address assigned to this connection
	 * @return <code>true</code> to accept the connect, <code>false</code> to reject
	 */
	boolean acceptDataConnection(KNXnetIPConnection connection,
		IndividualAddress assignedDeviceAddress);

	/**
	 * Notifies about a change related to a service container.
	 * <p>
	 * 
	 * @param sce contains details about the service container event
	 */
	void onServiceContainerChange(ServiceContainerEvent sce);

	/**
	 * Notifies that the server received a reset request.
	 * <p>
	 * Based on this notification, the notifying server should be restarted by calling
	 * {@link KNXnetIPServer#shutdown()} and {@link KNXnetIPServer#launch()}.
	 * 
	 * @param se contains details about the shutdown/launch request
	 */
	void onResetRequest(ShutdownEvent se);

	/**
	 * Notifies that the server will shutdown.
	 * <p>
	 * 
	 * @param se contains details about the shutdown event
	 */
	void onShutdown(ShutdownEvent se);
}
