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

import java.nio.file.Path;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

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
	private final int port;
	private final KNXMediumSettings settings;
	private final boolean reuseEndpt;
	private final boolean networkMonitor;
	private final boolean udpOnly;
	private volatile Duration disruptionBufferTimeout;
	private volatile int disruptionBufferLowerPort;
	private volatile int disruptionBufferUpperPort;
	private final boolean baosSupport;
	private volatile Path unixSocketPath;

	/**
	 * Creates a new service container with the supplied parameters. The control endpoint of this
	 * service container must contain UDP host protocol information.
	 *
	 * @param name service container name; the name shall allow an identification within a set of
	 *        service containers, and provide a descriptive name of the container. Therefore, a
	 *        unique, but yet descriptive name should be chosen. See also {@link #getName()}
	 * @param netif network interface name for the control endpoint to listen on, might be <code>"any"</code>
	 * @param port UDP/TCP port of the control endpoint for KNXnet/IP clients
	 * @param subnet KNX medium settings of the KNX subnet this service container is connected to
	 * @param reuseCtrlEndpt <code>true</code> to reuse control endpoint, <code>false</code>
	 *        otherwise, see {@link #reuseControlEndpoint()}
	 * @param udpOnly <code>true</code> to allow only UDP client connections (no TCP), <code>false</code> to allow both
	 * @param allowNetworkMonitoring <code>true</code> to allow KNXnet/IP bus monitor connections at
	 *        this service container, <code>false</code> otherwise
	 * @param baosSupport serve BAOS connections
	 */
	public DefaultServiceContainer(final String name, final String netif, final int port,
			final KNXMediumSettings subnet, final boolean reuseCtrlEndpt, final boolean allowNetworkMonitoring,
			final boolean udpOnly, final boolean baosSupport) {
		if (name == null)
			throw new NullPointerException("container identifier must not be null");
		id = name;
		this.netif = netif;
		this.port = port;
		settings = subnet;
		reuseEndpt = reuseCtrlEndpt;
		networkMonitor = allowNetworkMonitoring;
		this.udpOnly = udpOnly;
		disruptionBufferTimeout = Duration.of(0, ChronoUnit.SECONDS);
		this.baosSupport = baosSupport;
	}

	@Deprecated
	public DefaultServiceContainer(final String name, final String netif, final HPAI controlEndpoint,
			final KNXMediumSettings subnet, final boolean reuseCtrlEndpt, final boolean allowNetworkMonitoring,
			final boolean udpOnly, final boolean baosSupport)
	{
		this(name, netif, controlEndpoint.endpoint().getPort(), subnet, reuseCtrlEndpt, allowNetworkMonitoring,
				udpOnly, baosSupport);
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
	public final int port() { return port; }

	@Override
	@Deprecated
	public HPAI getControlEndpoint()
	{
		// be careful using HPAI::getAddress, because the IP of the control endpoint can change over time
		return new HPAI(null, port);
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

	public final void unixSocketPath(final Path path) { unixSocketPath = path; }

	public final Optional<Path> unixSocketPath() { return Optional.ofNullable(unixSocketPath); }

	/**
	 * {@return <code>true</code> iff service container should serve BAOS connections, <code>false</code> otherwise}
	 */
	public final boolean baosSupport() { return baosSupport; }
}
