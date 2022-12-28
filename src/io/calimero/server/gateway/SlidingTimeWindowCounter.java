/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2019, 2020 B. Malinowsky

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

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

final class SlidingTimeWindowCounter {
	private final String id;
	private final long shiftInterval;
	private final AtomicInteger counter = new AtomicInteger();
	private final int[] buckets;
	private volatile long lastBucketShift = System.nanoTime();

	SlidingTimeWindowCounter(final String id, final Duration timeWindow, final ChronoUnit interval) {
		this.id = id;
		shiftInterval = interval.getDuration().toSeconds();
		final long length = timeWindow.toSeconds() / shiftInterval;
		buckets = new int[(int) length];
	}

	public void increment() {
		maybeShiftBuckets();
		add(1);
	}

	private void add(final int n) { counter.addAndGet(n); }

	public int average() {
		return (int) Math.ceil(IntStream.of(buckets()).summaryStatistics().getAverage());
	}

	private void maybeShiftBuckets() {
		final long now = System.nanoTime();
		final long nanosPerSecond = 1_000_000_000L;
		int shift = (int) ((now - lastBucketShift) / nanosPerSecond / shiftInterval);
		if (shift > 0) {
			synchronized (buckets) {
				shift = (int) ((now - lastBucketShift) / nanosPerSecond / shiftInterval);
				if (shift > 0) {
					lastBucketShift = now;
					shiftBuckets(shift);
				}
			}
		}
	}

	private void shiftBuckets(final int shift) {
		final int move = Math.min(buckets.length, shift);
		final var arr = buckets();
		System.arraycopy(arr, 0, arr, move, arr.length - move);
		for (int i = 0; i < move; i++)
			buckets[i] = 0;
	}

	@Override
	public String toString() {
		return IntStream.of(buckets()).mapToObj(Integer::toString).collect(Collectors.joining(" | ", id + " [ ", " ]"))
				.toString();
	}

	private int[] buckets() {
		synchronized (buckets) {
			buckets[0] += counter.getAndSet(0);
		}
		return buckets;
	}
}
