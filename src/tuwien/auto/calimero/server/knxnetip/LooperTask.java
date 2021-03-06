/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2016, 2021 B. Malinowsky

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

import java.util.Optional;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import org.slf4j.Logger;

import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.log.LogService.LogLevel;

// interrupt policy: cleanup and exit
class LooperTask implements Runnable {
	private static final ScheduledThreadPoolExecutor looperPool = new ScheduledThreadPoolExecutor(Integer.MAX_VALUE,
		r -> {
			final Thread t = new Thread(r, "looper thread");
			t.setDaemon(true);
			return t;
		});

	static {
		looperPool.setKeepAliveTime(30, TimeUnit.SECONDS);
		looperPool.allowCoreThreadTimeOut(true);
	}

	public static void execute(final LooperTask task) {
		task.scheduledFuture = looperPool.schedule(task, 0, TimeUnit.SECONDS);
	}

	private static final int retryDelay = 10; // [s]

	public static void scheduleWithRetry(final LooperTask task) {
		task.scheduledFuture = looperPool.scheduleWithFixedDelay(task, 0, retryDelay, TimeUnit.SECONDS);
	}

	private final Logger logger;
	private final String serviceName;
	private final int maxRetries;
	private final Supplier<ServiceLooper> supplier;
	private volatile ServiceLooper looper;
	private int attempt;

	private volatile ScheduledFuture<?> scheduledFuture;

	// maxRetries: -1: always retry, 0 none, 1: at most one retry, ...
	LooperTask(final KNXnetIPServer server, final String serviceName,
		final int retryAttempts, final Supplier<ServiceLooper> serviceSupplier)
	{
		logger = server.logger;
		this.serviceName = serviceName;
		maxRetries = retryAttempts >= -1 ? retryAttempts : 0;
		supplier = serviceSupplier;
	}

	@Override
	public void run()
	{
		Thread.currentThread().setName(serviceName);

		if (maxRetries != -1)
			++attempt;

		try {
			looper = supplier.get();
			// reset for the next reconnection attempt
			attempt = 0;
			logger.info(looper.server.getName() + " " + looper + " is up and running");
			looper.run();
			cleanup(LogLevel.INFO, null);
		}
		catch (final RuntimeException e) {
			final String s = attempt > 0 ? " (attempt " + attempt + "/" + (maxRetries + 1) + ")" : "";
			if (maxRetries == -1 || attempt <= maxRetries)
				logger.warn("initialization of {} failed{}, retry in {} seconds", serviceName, s, retryDelay, e);
			else {
				logger.error("error initializing {}{}", serviceName, s, e);
				quit();
			}
		}
		Thread.currentThread().setName("idle looper thread");
	}

	@Override
	public String toString() {
		return serviceName;
	}

	Optional<ServiceLooper> looper() {
		return Optional.ofNullable(looper);
	}

	void quit() {
		scheduledFuture.cancel(true);
		// we quit the looper, because interrupts are ignored on non-interruptible sockets
		// only call cleanup if there is no looper, otherwise cleanup is called in run()
		looper().ifPresentOrElse(ServiceLooper::quit, () -> cleanup(LogLevel.INFO, null));
	}

	void cleanup(final LogLevel level, final Throwable t) {
		LogService.log(logger, level, serviceName + " closed", t);
	}
}
