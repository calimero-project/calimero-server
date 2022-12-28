/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2021 B. Malinowsky

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

import java.net.InetAddress;
import java.time.Duration;
import java.time.temporal.ChronoUnit;

import io.calimero.KNXIllegalArgumentException;
import io.calimero.knxnetip.util.HPAI;
import io.calimero.link.medium.KNXMediumSettings;

/**
 * The default implementation of the {@link ServiceContainer} for UDP communication only.
 *
 * @author B. Malinowsky
 */
public class DefaultServiceContainer implements ServiceContainer
{
	private volatile boolean activated = true;
	private final String id;
	private final String netif;
	private final HPAI ctrlEndpt;
	private final KNXMediumSettings settings;
	private final boolean reuseEndpt;
	private final boolean networkMonitor;
	private final boolean udpOnly;
	private volatile Duration disruptionBufferTimeout;
	private volatile int disruptionBufferLowerPort;
	private volatile int disruptionBufferUpperPort;
	private final boolean baosSupport;

	/**
	 * Creates a new service container with the supplied parameters. The control endpoint of this
	 * service container must contain UDP host protocol information.
	 *
	 * @param name service container name; the name shall allow an identification within a set of
	 *        service containers, and provide a descriptive name of the container. Therefore, a
	 *        unique, but yet descriptive name should be chosen. See also {@link #getName()}
	 * @param netif network interface name for the control endpoint to listen on, might be <code>"any"</code>
	 * @param controlEndpoint control endpoint address information which uniquely identifies this
	 *        service container to KNXnet/IP clients, UDP host protocol only, the HPAI has to
	 *        contain an IP address not 0; if parameter is <code>null</code>, a control endpoint is
	 *        created using the local host address and ephemeral port assignment
	 * @param subnet KNX medium settings of the KNX subnet this service container is connected to
	 * @param reuseCtrlEndpt <code>true</code> to reuse control endpoint, <code>false</code>
	 *        otherwise, see {@link #reuseControlEndpoint()}
	 * @param udpOnly <code>true</code> to allow only UDP client connections (no TCP), <code>false</code> to allow both
	 * @param allowNetworkMonitoring <code>true</code> to allow KNXnet/IP bus monitor connections at
	 *        this service container, <code>false</code> otherwise
	 * @param baosSupport serve BAOS connections
	 */
	public DefaultServiceContainer(final String name, final String netif, final HPAI controlEndpoint,
		final KNXMediumSettings subnet, final boolean reuseCtrlEndpt, final boolean allowNetworkMonitoring,
		final boolean udpOnly, final boolean baosSupport)
	{
		if (name == null)
			throw new NullPointerException("container identifier must not be null");
		id = name;
		this.netif = netif;
		if (controlEndpoint == null)
			// create with local host address and ephemeral port
			ctrlEndpt = new HPAI((InetAddress) null, 0);
		else {
			if (controlEndpoint.getHostProtocol() != HPAI.IPV4_UDP)
				throw new KNXIllegalArgumentException("only support for UDP communication");
			ctrlEndpt = controlEndpoint;
		}
		// IP is mandatory, port might be 0 indicating the use of an ephemeral port
		if (ctrlEndpt.getAddress().isAnyLocalAddress())
			throw new KNXIllegalArgumentException("no local host address specified");
		settings = subnet;
		reuseEndpt = reuseCtrlEndpt;
		networkMonitor = allowNetworkMonitoring;
		this.udpOnly = udpOnly;
		disruptionBufferTimeout = Duration.of(0, ChronoUnit.SECONDS);
		this.baosSupport = baosSupport;
	}

	@Override
	public String getName()
	{
		return id;
	}

	@Override
	public String networkInterface()
	{
		return netif;
	}

	@Override
	public HPAI getControlEndpoint()
	{
		// be careful using HPAI::getAddress, because the IP of the control endpoint can change over time
		return ctrlEndpt;
	}

	@Override
	public final KNXMediumSettings getMediumSettings()
	{
		return settings;
	}

	@Override
	public void setActivationState(final boolean activate)
	{
		activated = activate;
	}

	@Override
	public boolean isActivated()
	{
		return activated;
	}

	@Override
	public boolean reuseControlEndpoint()
	{
		return reuseEndpt;
	}

	@Override
	public boolean isNetworkMonitoringAllowed()
	{
		return networkMonitor;
	}

	public boolean udpOnly() { return udpOnly; }

	public void setDisruptionBuffer(final Duration expirationTimeout, final int lowerPort, final int upperPort)
	{
		if (expirationTimeout.isNegative())
			throw new KNXIllegalArgumentException("disruption buffer timeout " + expirationTimeout + " < 0");
		disruptionBufferTimeout = expirationTimeout;
		disruptionBufferLowerPort = lowerPort;
		disruptionBufferUpperPort = upperPort;
	}

	public final Duration disruptionBufferTimeout()
	{
		return disruptionBufferTimeout;
	}

	public final int[] disruptionBufferPortRange()
	{
		return new int[] { disruptionBufferLowerPort, disruptionBufferUpperPort };
	}

	/**
	 * @return <code>true</code> iff service container should serve BAOS connections, <code>false</code> otherwise
	 */
	boolean baosSupport() { return baosSupport; }
}
