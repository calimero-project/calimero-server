/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2023 B. Malinowsky

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

package io.calimero.server;

import java.util.ArrayList;
import java.util.List;

import io.calimero.FrameEvent;
import io.calimero.GroupAddress;
import io.calimero.IndividualAddress;
import io.calimero.KNXAddress;
import io.calimero.KNXFormatException;
import io.calimero.cemi.CEMIFactory;
import io.calimero.cemi.CEMILData;
import io.calimero.internal.EventListeners;
import io.calimero.link.AbstractLink;
import io.calimero.link.KNXLinkClosedException;
import io.calimero.link.KNXNetworkLink;
import io.calimero.link.NetworkLinkListener;
import io.calimero.link.medium.KNXMediumSettings;
import io.calimero.link.medium.PLSettings;
import io.calimero.link.medium.RFSettings;

/**
 * A subnet link implementation used for virtual KNX networks. In such networks, the KNX installation is realized by a
 * network buffer or software KNX devices. The main purpose is to run virtual KNX installations for development,
 * testing, and visualization.
 *
 * @author B. Malinowsky
 */
public class VirtualLink extends AbstractLink<AutoCloseable>
{
	private final List<VirtualLink> deviceLinks = new ArrayList<>();
	private final boolean isDeviceLink;

	public VirtualLink(final String name, final KNXMediumSettings settings)
	{
		this(name, settings, false);
	}

	private VirtualLink(final String name, final KNXMediumSettings settings, final boolean isDeviceLink)
	{
		super(name, settings);
		this.isDeviceLink = isDeviceLink;
	}

	public KNXNetworkLink createDeviceLink(final IndividualAddress device)
	{
		// we could allow this in theory, but not really needed
		if (isDeviceLink)
			throw new IllegalStateException("don't create device link from device link");

		final KNXMediumSettings ms = getKNXMedium();
		final KNXMediumSettings devSettings = KNXMediumSettings.create(ms.getMedium(), device);
		if (ms instanceof PLSettings)
			((PLSettings) devSettings).setDomainAddress(((PLSettings) ms).getDomainAddress());
		if (ms instanceof RFSettings)
			((RFSettings) devSettings).setDomainAddress(((RFSettings) ms).getDomainAddress());

		final VirtualLink devLink = new VirtualLink(device.toString(), devSettings, true);
		devLink.deviceLinks.add(this);
		deviceLinks.add(devLink);
		return devLink;
	}

	@Override
	protected void onSend(final KNXAddress dst, final byte[] msg, final boolean waitForCon)
		throws KNXLinkClosedException
	{}

	@Override
	protected void onSend(final CEMILData msg, final boolean waitForCon)
	{
		logger.debug("send {}{}", (waitForCon ? "(wait for confirmation) " : ""), msg);
		for (final VirtualLink l : deviceLinks)
			send(msg, notifier.getListeners(), l);
	}

	@Override
	protected void onClose()
	{}

	private void send(final CEMILData msg, final EventListeners<NetworkLinkListener> confirmation,
		final VirtualLink uplink)
	{
		if (!accept(uplink, msg))
			return;

		try {
			// send a .con for a .req
			if (msg.getMessageCode() == CEMILData.MC_LDATA_REQ) {
				final CEMILData f = (CEMILData) CEMIFactory.create(CEMILData.MC_LDATA_CON, msg.getPayload(), msg);
				final FrameEvent e = new FrameEvent(this, f);
				confirmation.fire(l -> l.confirmation(e));
			}
			// forward .ind as is, but convert req. to .ind and also remove repeat flag
			final CEMILData f = msg.getMessageCode() == CEMILData.MC_LDATA_IND ? msg : CEMIFactory.create(null, null,
					(CEMILData) CEMIFactory.create(CEMILData.MC_LDATA_IND, msg.getPayload(), msg), false, false);
			final FrameEvent e = new FrameEvent(this, f);
			// if we are a device link sending to the uplink, send the .ind to all other device links of that uplink
			if (isDeviceLink)
				uplink.deviceLinks.stream().filter(l -> accept(l, msg))
						.forEach(link -> link.notifier.getListeners().fire(l -> l.indication(e)));
			// send the .ind to our uplink
			uplink.notifier.getListeners().fire(l -> l.indication(e));
		}
		catch (final KNXFormatException e) {
			logger.error("create cEMI for KNX link {} using: {}", uplink.getName(), msg, e);
		}
	}

	// if the uplink is a device link:
	//   -) accept all group destinations, i.e., indicate all
	//   -) accept our device individual address as destination
	//   -) filter out other individual addresses given as device destination
	// if the uplink is not a device link:
	//   -) accept all
	private static boolean accept(final VirtualLink uplink, final CEMILData msg)
	{
		if (uplink.isDeviceLink) {
			final KNXAddress dst = msg.getDestination();
			if (dst instanceof GroupAddress)
				return true;
			return dst.equals(uplink.getKNXMedium().getDeviceAddress());
		}
		return true;
	}
}
