/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2016 B. Malinowsky

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
import java.util.EventListener;
import java.util.Iterator;
import java.util.List;

import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.cemi.CEMIFactory;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.exception.KNXFormatException;
import tuwien.auto.calimero.exception.KNXIllegalStateException;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.link.AbstractLink;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.NetworkLinkListener;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.link.medium.PLSettings;
import tuwien.auto.calimero.link.medium.RFSettings;

/**
 * A subnet link implementation used for virtual KNX networks. In such networks, the KNX
 * installation is realized by a network buffer or software KNX devices. The main purpose is to run
 * virtual KNX installations for development, testing, and visualization.
 *
 * @author B. Malinowsky
 */
public class VirtualLink extends AbstractLink
{
	// we use this listener list, not the (threaded) EventNotifier of our super type
	private final EventListeners listeners = new EventListeners();
	private final List deviceLinks = new ArrayList();

	private final boolean isDeviceLink;

	public VirtualLink(final String name, final KNXMediumSettings settings)
	{
		this(name, settings, false);
	}

	private VirtualLink(final String name, final KNXMediumSettings settings,
		final boolean isDeviceLink)
	{
		super(name, settings);
		this.isDeviceLink = isDeviceLink;
	}

	public KNXNetworkLink createDeviceLink(final IndividualAddress device)
	{
		// we could allow this in theory, but not really needed
		if (isDeviceLink)
			throw new KNXIllegalStateException("don't create device link from device link");
	
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

	public void addLinkListener(final NetworkLinkListener l)
	{
		listeners.add(l);
	}

	public void removeLinkListener(final NetworkLinkListener l)
	{
		listeners.remove(l);
	}

	protected void onSend(final KNXAddress dst, final byte[] msg, final boolean waitForCon)
		throws KNXLinkClosedException
	{}

	protected void onSend(final CEMILData msg, final boolean waitForCon)
	{
		for (final Iterator i = deviceLinks.iterator(); i.hasNext();) {
			final VirtualLink l = (VirtualLink) i.next();
			send(msg, listeners, l);
		}
	}

	protected void onClose()
	{}

	private void send(final CEMILData msg, final EventListeners confirmation,
		final VirtualLink uplink)
	{
		// if the uplink is a device link:
		// we indicate all group destinations, and our device individual address,
		// filter out other individual addresses for device destination
		if (uplink.isDeviceLink) {
			if (msg.getDestination() instanceof GroupAddress)
				; // accept
			else if (!msg.getDestination().equals(uplink.getKNXMedium().getDeviceAddress()))
				return;
		}

		try {
			// send a .con for a .req
			EventListener[] el = confirmation.listeners();
			if (msg.getMessageCode() == CEMILData.MC_LDATA_REQ) {
				final CEMILData f = (CEMILData) CEMIFactory.create(CEMILData.MC_LDATA_CON,
						msg.getPayload(), msg);
				final FrameEvent e = new FrameEvent(this, f);
				for (int i = 0; i < el.length; i++) {
					final NetworkLinkListener l = (NetworkLinkListener) el[i];
					l.confirmation(e);
				}
			}
			// forward .ind as is, but convert req. to .ind
			final CEMILData f = msg.getMessageCode() == CEMILData.MC_LDATA_IND ? msg
					: (CEMILData) CEMIFactory.create(CEMILData.MC_LDATA_IND, msg.getPayload(), msg);
			el = uplink.listeners.listeners();
			final FrameEvent e = new FrameEvent(this, f);
			for (int i = 0; i < el.length; i++) {
				final NetworkLinkListener l = (NetworkLinkListener) el[i];
				l.indication(e);
			}
		}
		catch (final KNXFormatException e) {
			logger.error("create cEMI for KNX link " + uplink.getName() + " using: " + msg, e);
		}
	}
}
