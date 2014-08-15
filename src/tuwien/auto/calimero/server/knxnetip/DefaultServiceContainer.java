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

import java.net.InetAddress;
import java.util.Arrays;

import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.exception.KNXIllegalArgumentException;
import tuwien.auto.calimero.knxnetip.util.DeviceDIB;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;

/**
 * The default implementation of the {@link ServiceContainer}.
 * <p>
 * It allows for UDP communication only.
 * 
 * @author B. Malinowsky
 */
public class DefaultServiceContainer implements ServiceContainer
{
	private volatile boolean activated = true;
	private final String id;
	private final HPAI ctrlEndpt;
	private final int medium;
	private final IndividualAddress subnetAddr;
	private final boolean reuseEndpt;
	private final boolean networkMonitor;

	/**
	 * Creates a new service container with the supplied parameters.
	 * <p>
	 * The control endpoint of this service container must contain UDP host protocol information.
	 * 
	 * @param name service container name; the name shall allow an identification within a set of
	 *        service containers, and provide a descriptive name of the container. Therefore, a
	 *        unique, but yet descriptive name should be chosen. See also {@link #getName()}
	 * @param controlEndpoint control endpoint address information which uniquely identifies this
	 *        service container to KNXnet/IP clients, UDP host protocol only, the HPAI has to
	 *        contain an IP address not 0; if parameter is <code>null</code>, a control endpoint is
	 *        created using the local host address and ephemeral port assignment
	 * @param knxMedium KNX medium of the KNX subnet this service container is connected to, use one
	 *        of the constants listed in {@link KNXMediumSettings}
	 * @param knxSubnet KNX address of the connected KNX subnet, usually an address identifying the
	 *        area and line
	 * @param reuseCtrlEndpt <code>true</code> to reuse control endpoint, <code>false</code>
	 *        otherwise, see {@link #reuseControlEndpoint()}
	 * @param allowNetworkMonitoring <code>true</code> to allow KNXnet/IP bus monitor connections at
	 *        this service container, <code>false</code> otherwise
	 */
	public DefaultServiceContainer(final String name, final HPAI controlEndpoint,
		final int knxMedium, final IndividualAddress knxSubnet, final boolean reuseCtrlEndpt,
		final boolean allowNetworkMonitoring)
	{
		if (name == null)
			throw new NullPointerException("container identifier must not be null");
		id = name;
		if (controlEndpoint == null)
			// create with local host address and ephemeral port
			ctrlEndpt = new HPAI((InetAddress) null, 0);
		else {
			if (controlEndpoint.getHostProtocol() != HPAI.IPV4_UDP)
				throw new KNXIllegalArgumentException("only support for UDP communication");
			ctrlEndpt = controlEndpoint;
		}
		// IP is mandatory, port might be 0 indicating the use of an ephemeral port
		if (Arrays.equals(new byte[4], ctrlEndpt.getRawAddress()))
			throw new KNXIllegalArgumentException("no local host address specified");
		medium = knxMedium;
		subnetAddr = knxSubnet;
		reuseEndpt = reuseCtrlEndpt;
		networkMonitor = allowNetworkMonitoring;
	}

	/**
	 * Creates a new service container with the supplied parameters.
	 * <p>
	 * The control endpoint of this service container must contain UDP host protocol information.<br>
	 * Reuse of control endpoint is not allowed, bus monitor connections are allowed.
	 * 
	 * @param name service container name; the name shall allow an identification within a set of
	 *        service containers, and provide a descriptive name of the container. Therefore, a
	 *        unique, but yet descriptive name should be chosen. See also {@link #getName()}
	 * @param controlEndpoint control endpoint address information which uniquely identifies this
	 *        service container to KNXnet/IP clients, UDP host protocol only, the HPAI has to
	 *        contain an IP address not 0; if parameter is <code>null</code>, a control endpoint is
	 *        created using the local host address and ephemeral port assignment
	 * @param knxMedium KNX medium of the KNX subnet this service container is connected to, use one
	 *        of the constants listed in {@link DeviceDIB}
	 * @param knxSubnet KNX address of the connected KNX subnet, usually an address identifying the
	 *        area and line
	 */
	public DefaultServiceContainer(final String name, final HPAI controlEndpoint,
		final int knxMedium, final IndividualAddress knxSubnet)
	{
		this(name, controlEndpoint, knxMedium, knxSubnet, false, true);
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.server.knxnetip.ServiceContainer#getName()
	 */
	public String getName()
	{
		return id;
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.server.knxnetip.ServiceContainer#getControlEndpoint()
	 */
	public HPAI getControlEndpoint()
	{
		return ctrlEndpt;
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.server.knxnetip.ServiceContainer#getKNXMedium()
	 */
	public int getKNXMedium()
	{
		return medium;
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.server.knxnetip.ServiceContainer#getSubnetAddress()
	 */
	public IndividualAddress getSubnetAddress()
	{
		return subnetAddr;
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.server.knxnetip.ServiceContainer#setActivationState(boolean)
	 */
	public void setActivationState(final boolean activate)
	{
		activated = activate;
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.server.knxnetip.ServiceContainer#isActivated()
	 */
	public boolean isActivated()
	{
		return activated;
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.server.knxnetip.ServiceContainer#reuseControlEndpoint()
	 */
	public boolean reuseControlEndpoint()
	{
		return reuseEndpt;
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.server.knxnetip.ServiceContainer#isNetworkMonitoringAllowed()
	 */
	public boolean isNetworkMonitoringAllowed()
	{
		return networkMonitor;
	}
}
