/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2020 B. Malinowsky

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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.Keyring;
import tuwien.auto.calimero.datapoint.StateDP;
import tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB;
import tuwien.auto.calimero.server.gateway.SubnetConnector;
import tuwien.auto.calimero.server.knxnetip.KNXnetIPServer;
import tuwien.auto.calimero.server.knxnetip.RoutingServiceContainer;
import tuwien.auto.calimero.server.knxnetip.ServiceContainer;

/**
 * Configuration for a KNXnet/IP server.
 *
 * @see KNXnetIPServer#KNXnetIPServer(ServerConfiguration)
 */
public class ServerConfiguration {

	/**
	 * Contains the configuration for a service container managed by the KNXnet/IP server.
	 */
	public static final class Container {
		private static final String secureSymbol = new String(Character.toChars(0x1F512));

		// server side

		private final List<IndividualAddress> additionalAddresses;
		private final int securedServices;
		private final Map<Integer, List<IndividualAddress>> tunnelingUsers;
		private final Keyring keyring;
		private final Map<String, byte[]> keyfile;

		// subnet side

		private final SubnetConnector connector;
		private final List<GroupAddress> groupAddressFilter;
		private final List<StateDP> timeServer;


		Container(final List<IndividualAddress> additionalAddresses, final SubnetConnector connector,
				final List<GroupAddress> groupAddressFilter, final List<StateDP> timeServerDatapoints) {
			this(additionalAddresses, 0, Map.of(), null, Map.of(), connector, groupAddressFilter, timeServerDatapoints);
		}

		Container(final List<IndividualAddress> additionalAddresses,
				final int securedServices, final Map<Integer, List<IndividualAddress>> tunnelingUsers,
				final Keyring keyring, final Map<String, byte[]> keyfile, final SubnetConnector connector,
				final List<GroupAddress> groupAddressFilter, final List<StateDP> timeServerDatapoints) {

			this.additionalAddresses = List.copyOf(additionalAddresses);
			this.tunnelingUsers = Map.copyOf(tunnelingUsers);
			this.securedServices = securedServices;
			this.keyring = keyring;
			this.keyfile = Map.copyOf(keyfile);

			this.connector = connector;
			this.groupAddressFilter = List.copyOf(groupAddressFilter);
			this.timeServer = List.copyOf(timeServerDatapoints);
		}


		public List<IndividualAddress> additionalAddresses() { return additionalAddresses; }

		public int securedServices() { return securedServices; }

		public Map<Integer, List<IndividualAddress>> tunnelingUsers() { return tunnelingUsers; }

		public Optional<Keyring> keyring() { return Optional.ofNullable(keyring); }

		public Map<String, byte[]> keyfile() { return keyfile; }

		public SubnetConnector subnetConnector() { return connector; }

		public List<GroupAddress> groupAddressFilter() { return groupAddressFilter; }

		public List<StateDP> timeServer() { return timeServer; }

		@Override
		public String toString() {
			final ServiceContainer sc = subnetConnector().getServiceContainer();

			final String activated = sc.isActivated() ? "" : " [not activated]";
			String mcast = "disabled";
			String secureRouting = "";
			final int securedServices = securedServices();
			final var keyfile = keyfile();

			if ((sc instanceof RoutingServiceContainer)) {
				mcast = "multicast group " + ((RoutingServiceContainer) sc).routingMulticastAddress().getHostAddress();

				final boolean secureRoutingRequired = (securedServices & (1 << ServiceFamiliesDIB.ROUTING)) != 0;
				if (secureRoutingRequired && keyfile.getOrDefault("group.key", new byte[0]).length == 16)
					secureRouting = secureSymbol + " ";
			}
			final String type = subnetConnector().toString();
			String filter = "";
			if (!groupAddressFilter().isEmpty())
				filter = "\n\tGroup address filter " + groupAddressFilter();

			final boolean secureUnicastRequired = (securedServices & (1 << ServiceFamiliesDIB.TUNNELING)) != 0;
			final String unicastSecure = secureUnicastRequired && keyfile.get("user.1") != null ? secureSymbol + " "
					: "";
			final String unicast = "" + sc.getControlEndpoint().getPort();
			// @formatter:off
			return String.format("%s%s:\n"
					+ "\tlisten on %s (%sport %s), KNX IP %srouting %s\n"
					+ "\t%s connection: %s%s",
					sc.getName(), activated, sc.networkInterface(), unicastSecure, unicast, secureRouting, mcast, type,
					sc.getMediumSettings(), filter);
			// @formatter:on
		}
	}


	private final String name;
	private final String friendly;
	private final boolean discovery;
	private final List<String> discoveryNetifs;
	private final List<String> outgoingNetifs;
	private final URI iosResource;
	private final List<Container> containers;


	public ServerConfiguration(final String name, final String friendlyName, final boolean discovery,
			final List<String> discoveryNetifs, final List<String> outgoingNetifs, final URI iosResource,
			final List<Container> containers) {
		this.name = name;
		if (!StandardCharsets.ISO_8859_1.newEncoder().canEncode(friendlyName))
			throw new IllegalArgumentException("Cannot encode '" + friendlyName + "' using ISO-8859-1 charset");
		friendly = friendlyName;
		this.discovery = discovery;
		this.discoveryNetifs = List.copyOf(discoveryNetifs);
		this.outgoingNetifs = List.copyOf(outgoingNetifs);
		this.iosResource = iosResource;
		this.containers = List.copyOf(containers);
	}

	public String name() { return name; }

	public String friendlyName() { return friendly; }

	public boolean runDiscovery() { return discovery; }

	public List<String> discoveryNetifs() { return discoveryNetifs; }

	public List<String> outgoingNetifs() { return outgoingNetifs; }

	public Optional<URI> iosResource() { return Optional.ofNullable(iosResource); }

	public List<Container> containers() { return containers; }

	@Override
	public String toString() {
		// @formatter:off
		return String.format("%s '%s' - %s service container%s, discovery%s",
				name, friendly,
				containers.size(), containers.size() > 1 ? "s" : "",
				discovery ? ": listen on " + discoveryNetifs() + " send on " + outgoingNetifs() : " disabled");
		// @formatter:on
	}
}
