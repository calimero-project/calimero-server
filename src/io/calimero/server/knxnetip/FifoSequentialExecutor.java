/*
    Calimero 3 - A library for KNX network access
    Copyright (c) 2025, 2025 B. Malinowsky

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

import java.lang.System.Logger.Level;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import io.calimero.internal.Executor;

final class FifoSequentialExecutor implements java.util.concurrent.Executor {
	private final String name;
	private final System.Logger logger;

	private final Queue<Runnable> tasks = new ConcurrentLinkedQueue<>();
	private final AtomicBoolean running = new AtomicBoolean();

	public FifoSequentialExecutor(final String name, final System.Logger logger) {
		this.name = name;
		this.logger = logger;
	}

	@Override
	public void execute(final Runnable command) {
		tasks.add(command);
		tryRun();
	}

	private void tryRun() {
		if (tasks.isEmpty())
			return;
		if (running.compareAndSet(false, true))
			Executor.execute(this::runTasks);
	}

	private void runTasks() {
		Thread.currentThread().setName(name);
		for (var task = tasks.poll(); task != null; task = tasks.poll()) {
			try {
				task.run();
			}
			catch (final Throwable t) {
				logger.log(Level.ERROR, "error running task", t);
			}
		}
		running.set(false);
		tryRun();
	}
}
