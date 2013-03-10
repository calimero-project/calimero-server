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

package tuwien.auto.calimero.server.knxnetip;

import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.knxnetip.util.DeviceDIB;
import tuwien.auto.calimero.knxnetip.util.HPAI;

/**
 * A service container offers KNXnet/IP service types in a {@link KNXnetIPServer}.
 * <p>
 * The service container's control endpoint uniquely identifies the service container to clients on
 * the KNXnet/IP server side. A service container is usually connected to a KNX subnetwork. Hence, a
 * service container contained in a server provides the control endpoint through which the server
 * offers services to its clients.<br>
 * A KNXnet/IP server contains one or more service containers.
 * <p>
 * Many of the configuration settings stored in a service container are used in the device
 * description of a KNXnet/IP server and used in the device description information block (
 * {@link DeviceDIB}) of that server instance.
 * 
 * @author B. Malinowsky
 */
public interface ServiceContainer
{
	/**
	 * Returns the service container name.
	 * <p>
	 * Preferably, the name shall allow an identification within a set of service containers, and
	 * provide a descriptive name for the container. The name might be checked for uniqueness when
	 * used in service container collections by other classes. Therefore, a unique, but yet
	 * descriptive name should be chosen and returned here.
	 * 
	 * @return the service container name as non-empty, non-null string
	 */
	String getName();

	/**
	 * Returns the control endpoint which uniquely identifies the service container to a client.
	 * <p>
	 * 
	 * @return the host protocol address information containing the control endpoint
	 * @see HPAI
	 */
	HPAI getControlEndpoint();

	/**
	 * Returns the KNX medium of the connected KNX subnet.
	 * <p>
	 * 
	 * @return KNX medium
	 */
	int getKNXMedium();

	/**
	 * Returns the KNX subnet address of the KNX subnet this service container is connected to.
	 * <p>
	 * 
	 * @return KNX subnet individual address
	 */
	IndividualAddress getSubnetAddress();

	/**
	 * Activates or deactivates the service container.
	 * <p>
	 * A deactivated service container is not listed in search responses during discovery by the
	 * server.
	 * 
	 * @param activate <code>true</code> to activate, <code>false</code> to deactivate
	 */
	void setActivationState(boolean activate);

	/**
	 * Returns the activation state of the service container.
	 * <p>
	 * 
	 * @return <code>true</code> if activated, <code>false</code> otherwise
	 */
	boolean isActivated();

	/**
	 * Returns whether the control endpoint should be reused for client-server data connections.
	 * <p>
	 * Reuse of a control endpoint means, that connection requests addressed to that control
	 * endpoint will share the control endpoint during the time the connection is established. If a
	 * control endpoint is reused, no new data endpoint is created at the server host, e.g., no new
	 * free UDP port is required.<br>
	 * But note, only one active connection at the service container can take advantage of control
	 * endpoint reuse at a time. If another connection request occurs during an active connection,
	 * the server might decide to create new data endpoints anyway or reject subsequent connection
	 * requests, depending on implementation.
	 * 
	 * @return <code>true</code> if the control endpoint should be reused, <code>false</code>
	 *         otherwise
	 */
	boolean reuseControlEndpoint();

	/**
	 * Returns whether network monitoring, i.e., bus monitor connections, to this service container
	 * is allowed or not.
	 * <p>
	 * 
	 * @return <code>true</code> if network monitoring is allowed, <code>false</code> otherwise
	 */
	boolean isNetworkMonitoringAllowed();
}
