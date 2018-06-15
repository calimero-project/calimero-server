/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2016, 2018 B. Malinowsky

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
import java.util.function.Supplier;

import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.log.LogService.LogLevel;

// interrupt policy: cleanup and exit
class LooperThread extends Thread
{
	private final KNXnetIPServer server;
	private final int maxRetries;
	private final Supplier<ServiceLooper> supplier;
	private volatile ServiceLooper looper;
	private volatile boolean quit;

	// maxRetries: -1: always retry, 0 none, 1: at most one retry, ...
	LooperThread(final KNXnetIPServer server, final String serviceName,
		final int retryAttempts, final Supplier<ServiceLooper> serviceSupplier)
	{
		super(serviceName);
		this.server = server;
		setDaemon(true);
		maxRetries = retryAttempts >= -1 ? retryAttempts : 0;
		supplier = serviceSupplier;
	}

	@Override
	public void run()
	{
		final int inc = maxRetries == -1 ? 0 : 1;
		int attempt = 0;
		while (!quit) {
			if (attempt > maxRetries) {
				quit = true;
				break;
			}
			attempt += inc;
			try {
				looper = supplier.get();
				// reset for the next reconnection attempt
				attempt = 0;
				server.logger.info(super.getName() + " is up and running");
				looper.run();
				quit |= maxRetries == 0;
				cleanup(LogLevel.INFO, null);
			}
			catch (final RuntimeException e) {
				final String s = attempt > 0 ? " (attempt " + attempt + "/" + (maxRetries + 1) + ")" : "";
				server.logger.error("initialization of {} failed{}", super.getName(), s, e);
				if (maxRetries == -1 || attempt <= maxRetries) {
					final int wait = 10;
					server.logger.info("retry to start " + super.getName() + " in " + wait + " seconds");
					try {
						sleep(wait * 1000);
					}
					catch (final InterruptedException ie) {
						quit();
					}
				}
				else {
					server.logger.error("error setting up " + super.getName());
				}
			}
		}
	}

	synchronized Optional<ServiceLooper> looper() {
		return Optional.ofNullable(looper);
	}

	void quit()
	{
		quit = true;
		interrupt();
		// we quit the looper, because interrupts are ignored on non-interruptible sockets
		// only call cleanup if there is no looper, otherwise cleanup is called in run()
		looper().ifPresentOrElse(ServiceLooper::quit, () -> cleanup(LogLevel.INFO, null));
	}

	void cleanup(final LogLevel level, final Throwable t)
	{
		LogService.log(server.logger, level, super.getName() + " closed", t);
	}
}
