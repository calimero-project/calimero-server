/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2016, 2024 B. Malinowsky

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

package io.calimero.server.gateway;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;

import java.lang.System.Logger;
import java.lang.invoke.MethodHandles;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import io.calimero.FrameEvent;
import io.calimero.knxnetip.KNXnetIPConnection;
import io.calimero.log.LogService;

final class ReplayBuffer<T extends FrameEvent>
{
	private static final Logger logger = LogService.getLogger(MethodHandles.lookup().lookupClass());

	private record Key(String hostAddress, int port, long timestamp) {
		Key(final InetSocketAddress remote) {
			this(remote.getAddress().getHostAddress(), remote.getPort(), System.currentTimeMillis());
		}
	}

	private final Map<KNXnetIPConnection, Key> connectionToKey = Collections.synchronizedMap(new HashMap<>());
	private final Map<KNXnetIPConnection, Long> completedEvent = Collections.synchronizedMap(new HashMap<>());

	private static final long maxBufferSize = 350;
	private final List<T> buffer = new ArrayList<>();

	private final long keepDisruptedConnection; // [ms]

	ReplayBuffer(final Duration expireDisruptedConnectionAfter)
	{
		keepDisruptedConnection = expireDisruptedConnectionAfter.toMillis();
	}

	public boolean isDisrupted(final KNXnetIPConnection c)
	{
		return !disruptedCandidates(c).isEmpty();
	}

	private List<KNXnetIPConnection> disruptedCandidates(final KNXnetIPConnection c)
	{
		final Key key = new Key(c.getRemoteAddress());
		synchronized (connectionToKey) {
			final List<KNXnetIPConnection> exactMatch = find(c, key, 2);
			if (!exactMatch.isEmpty()) {
				logger.log(INFO, "found exact match for {0} in disrupted connections: {1}", key, exactMatch);
				return exactMatch;
			}
			final List<KNXnetIPConnection> matchedHosts = find(c, key, 1);

			final List<KNXnetIPConnection> closedOnly = new ArrayList<>(matchedHosts);
			closedOnly.removeIf(e -> e.getState() != KNXnetIPConnection.CLOSED);
			if (!closedOnly.isEmpty()) {
				logger.log(INFO, "found match for {0} in closed disrupted connections: {1}", key, closedOnly);
				return closedOnly;
			}

			// TODO with the current implementation, the following wrong outcome is possible: using host-matching only,
			// a (truly disrupted) connection in open state is initially found, because no new subnet event has
			// arrived yet. Hence, that connection is removed from matchedHosts set as it is not missing events,
			// therefore, it is not a disrupted candidate.
			// A future connect attempt then might match that connection again even though it shouldn't.

			// we matched open connections by host, check if any connection is missing events
			matchedHosts.removeIf(e -> !isMissingEvents(e));
			logger.log(INFO, "match for {0} in open connections with missing events: {1}", key, matchedHosts);
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
	private List<KNXnetIPConnection> find(final KNXnetIPConnection c, final Key key, final int compare)
	{
		final List<KNXnetIPConnection> remove = new ArrayList<>();
		final List<KNXnetIPConnection> found = new ArrayList<>();
		for (final Entry<KNXnetIPConnection, Key> e : connectionToKey.entrySet()) {
			final long timestamp = e.getValue().timestamp();
			final KNXnetIPConnection conn = e.getKey();
			if ((timestamp + keepDisruptedConnection) < System.currentTimeMillis()) {
				logger.log(DEBUG, "remove expired disrupted connection {0}", conn);
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
		logger.log(DEBUG, "activate replay buffer for {0}", c);
		connectionToKey.put(c, new Key(c.getRemoteAddress()));
	}

	public void recordEvent(final T e)
	{
		synchronized (buffer) {
			while (buffer.size() >= maxBufferSize)
				buffer.remove(0);
			buffer.add(e);
		}
		logger.log(TRACE, "record {0} as event ''{1}''", e, e.id());
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
				logger.log(WARNING, "{0} has ≥ {1} events pending with a buffer size of {2}, up to {3} events "
						+ "will be missing", conn, events, buffer.size(), buffer.get(0).id() - last);
			}

			logger.log(INFO, "{0} has {1} pending events for replay: ({2}..{3}]", conn, events, last, latestEventCount());
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
			final Key key = connectionToKey.get(c);
			if (key == null)
				return;
			connectionToKey.put(c, new Key(key.hostAddress(), key.port(), System.currentTimeMillis()));
		}
		completedEvent.put(c, e.id());
		logger.log(DEBUG, "{0} successfully completed event ''{1}/{2}''", c, e.id(), latestEventCount());
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
		final Key key = connectionToKey.remove(c);
		if (key != null)
			logger.log(TRACE, "remove {0} ({1})", c, key);
	}

	// returns 0: no match, 1: key.hostAddress matches to.hostAddress, 2: match 1 and key.port matches to.port
	private static int compare(final Key key, final Key to)
	{
		if (key.hostAddress().equals(to.hostAddress())) {
			if (key.port() == to.port())
				return 2;
			return 1;
		}
		return 0;
	}
}
