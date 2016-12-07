/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2016 B. Malinowsky

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

package tuwien.auto.calimero.server.gateway;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.knxnetip.KNXnetIPConnection;

class ReplayBuffer<T extends FrameEvent>
{
	private static final Logger logger = LoggerFactory.getLogger("calimero.server.gateway.ReplayBuffer");

	private final Map<KNXnetIPConnection, Object[]> connectionToKey = Collections.synchronizedMap(new HashMap<>());
	private final Map<KNXnetIPConnection, Long> completedEvent = Collections.synchronizedMap(new HashMap<>());

	private static final long maxBufferSize = 350;
	private final List<T> buffer = new ArrayList<>();

	private final long keepDisruptedConnection; // [ms]

	public ReplayBuffer(final Duration expireDisruptedConnectionAfter)
	{
		keepDisruptedConnection = expireDisruptedConnectionAfter.toMillis();
	}

	public boolean isDisrupted(final KNXnetIPConnection c)
	{
		return !disruptedCandidates(c).isEmpty();
	}

	private List<KNXnetIPConnection> disruptedCandidates(final KNXnetIPConnection c)
	{
		final Object[] key = keyFor(c);
		synchronized (connectionToKey) {
			final List<KNXnetIPConnection> exactMatch = find(c, key, 2);
			if (!exactMatch.isEmpty()) {
				logger.info("found exact match for {} in disrupted connections: {}", key, exactMatch);
				return exactMatch;
			}
			final List<KNXnetIPConnection> matchedHosts = find(c, key, 1);

			final List<KNXnetIPConnection> closedOnly = new ArrayList<>(matchedHosts);
			closedOnly.removeIf(e -> e.getState() != KNXnetIPConnection.CLOSED);
			if (!closedOnly.isEmpty()) {
				logger.info("found match for {} in closed disrupted connections: {}", key, closedOnly);
				return closedOnly;
			}

			// TODO with the current implementation, the following wrong outcome is possible: using host-matching only,
			// a (truly disrupted) connection in open state is initially found, because no new subnet event has
			// arrived yet. Hence, that connection is removed from matchedHosts set as it is not missing events,
			// therefore, it is not a disrupted candidate.
			// A future connect attempt then might match that connection again even though it shouldn't.

			// we matched open connections by host, check if any connection is missing events
			matchedHosts.removeIf(e -> !isMissingEvents(e));
			logger.info("match for {} in open connections with missing events: {}", key, matchedHosts);
			return matchedHosts;
		}
	}

	private boolean isMissingEvents(final KNXnetIPConnection c)
	{
		final Long lastTx = completedEvent.get(c);
		if (lastTx == null)
			return false;
		return lastTx < latestEventCount();
	}

	// only call iff synchronized on connectionToKey
	private List<KNXnetIPConnection> find(final KNXnetIPConnection c, final Object[] key, final int compare)
	{
		final List<KNXnetIPConnection> remove = new ArrayList<>();
		final List<KNXnetIPConnection> found = new ArrayList<>();
		for (final Entry<KNXnetIPConnection, Object[]> e : connectionToKey.entrySet()) {
			final long timestamp = (Long) e.getValue()[2];
			final KNXnetIPConnection conn = e.getKey();
			if ((timestamp + keepDisruptedConnection) < System.currentTimeMillis()) {
				logger.info("remove expired disrupted connection {}", conn);
				remove.add(conn);
			}
			else if (conn != c) { // we ignore c itself in the entry set, otherwise it would always show up in found
				if (compare(e.getValue(), key) == compare)
					found.add(conn);
			}
		}
		remove.forEach(this::remove);
		return found;
	}

	public void add(final KNXnetIPConnection c)
	{
		logger.debug("activate replay buffer for {}", c);
		connectionToKey.put(c, keyFor(c));
	}

	public void recordEvent(final T e)
	{
		synchronized (buffer) {
			while (buffer.size() >= maxBufferSize)
				buffer.remove(0);
			buffer.add(e);
		}
		logger.trace("record {} as event '{}'", e, e.id());
	}

	// returns list of pending events for connection
	public Collection<T> replay(final KNXnetIPConnection conn)
	{
		final List<KNXnetIPConnection> candidates = disruptedCandidates(conn);
		if (candidates.isEmpty())
			return Collections.emptyList();

		synchronized (buffer) {
			// we select and terminate a single matching connection with the oldest successful event
			long last = Long.MAX_VALUE;
			KNXnetIPConnection selected = null;
			for (final KNXnetIPConnection c : candidates) {
				final long l = completedEvent.get(c);
				if (l < last) {
					last = l;
					selected = c;
				}
			}
			remove(selected);

			// pending events
			final int fromIndex = findEvent(last) + 1;
			final int events = buffer.size() - fromIndex;
			if (fromIndex == 0) {
				logger.warn("{} has ≥ {} events pending with a buffer size of {}, up to {} events "
						+ "will be missing", conn, events, buffer.size(), buffer.get(0).id() - last);
			}

			logger.info("{} has {} pending events for replay: ({}..{}]", conn, events, last, latestEventCount());
			return new ArrayList<>(buffer.subList(fromIndex, buffer.size()));
		}
	}

	// call only iff synchronized on buffer
	private int findEvent(final long last)
	{
		for (int i = 0; i < buffer.size(); i++)
			if (buffer.get(i).id() == last)
				return i;
		return -1;
	}

	public void completeEvent(final KNXnetIPConnection c, final T e)
	{
		synchronized (connectionToKey) {
			final Object[] key = connectionToKey.get(c);
			if (key == null)
				return;
			key[2] = System.currentTimeMillis();
		}
		completedEvent.put(c, e.id());
		logger.debug("{} successfully completed event '{}/{}'", c, e.id(), latestEventCount());
	}

	private long latestEventCount()
	{
		synchronized (buffer) {
			return buffer.get(buffer.size() - 1).id();
		}
	}

	public void remove(final KNXnetIPConnection c)
	{
		completedEvent.remove(c);
		final Object[] key = connectionToKey.remove(c);
		logger.trace("remove {} (ID {})", c, key);
	}

	private static Object[] keyFor(final KNXnetIPConnection c)
	{
		final InetSocketAddress remote = c.getRemoteAddress();
		final Object[] key = new Object[] { remote.getAddress().getHostAddress(), remote.getPort(),
			System.currentTimeMillis() };
		return key;
	}

	// returns 0: no match, 1: key[0] matches to[0], 2: match 1 and key[1] matches to[1]
	private static int compare(final Object[] key, final Object[] to)
	{
		if (key[0].equals(to[0])) {
			if (key[1].equals(to[1]))
				return 2;
			return 1;
		}
		return 0;
	}
}
