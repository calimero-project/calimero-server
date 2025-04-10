/*
    Calimero 3 - A library for KNX network access
    Copyright (c) 2024, 2025 B. Malinowsky

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

package io.calimero.server.gateway.trace;

import java.io.Closeable;
import java.io.Writer;

import io.calimero.KnxRuntimeException;
import io.calimero.cemi.CEMI;
import io.calimero.server.gateway.trace.CemiFrameTracer.Format;


public sealed interface CemiFrameTracer extends Closeable permits NoopTracer, JsonTracer {
	enum Format {
		Noop, Json;

		public static Format from(final String value) {
			for (final var v : values())
				if (v.name().toLowerCase().equals(value))
					return v;
			throw new KnxRuntimeException("unsupported cEMI trace output format '" + value + "'");
		}
	}

	enum FramePath {
		SubnetToClient("S->C"),
		ClientToSubnet("C->S"),
		LocalToSubnet("L->S"),
		LocalToClient("L->C"),
		ClientToClient("C->C"),
		SubnetToSubnet("S->S"),
		ClientToLocal("C-L");

		private final String symbol;

		FramePath(final String symbol) { this.symbol = symbol; }

		@Override
		public String toString() { return symbol; }
	}


	static void configure(final Format format, final Writer w) { Singleton.initialize(format, w); }

	static CemiFrameTracer instance() { return Singleton.tracer; }

	void trace(CEMI msg, String client, Object subnet, FramePath path);

	@Override
	default void close() {}
}

final class Singleton {
	static volatile CemiFrameTracer tracer = new NoopTracer();

	static void initialize(final Format format, final Writer w) {
		tracer = switch (format) {
			case Noop -> new NoopTracer();
			case Json -> new JsonTracer(w);
		};
	}
}

final class NoopTracer implements CemiFrameTracer {
	@Override
	public void trace(final CEMI msg, final String client, final Object subnet, final FramePath path) {}
}
