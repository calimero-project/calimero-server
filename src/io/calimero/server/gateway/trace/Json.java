/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2023, 2023 B. Malinowsky

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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import io.calimero.KnxRuntimeException;

/** Creates JSON output of records which implement this interface. */
interface Json {
	int Indent = 0;
	String EndOfElement = " ";

	default String toJson() {
		return toJson(new StringBuilder(), 0).toString();
	}

	private StringBuilder toJson(final StringBuilder sb, final int indent) {
		return iterate(Arrays.asList(getClass().getRecordComponents()), "{", "}", "", "",
				RecordComponent::getName, this::recordValue, sb, indent);
	}

	private Object recordValue(final RecordComponent rc) {
		try {
			return rc.getAccessor().invoke(this);
		} catch (IllegalAccessException | InvocationTargetException e) {
			return new KnxRuntimeException("enumerating values of " + this.getClass().getSimpleName(), e);
		}
	}

	private static <T> void toJsonArray(final Iterable<? extends T> elems, final String elemOpener, final String elemCloser,
			final Function<T, String> key, final Function<T, Object> value, final StringBuilder sb, final int indent) {
		iterate(elems, "[", "]", elemOpener, elemCloser, key, value, sb, indent);
	}

	private static <T> StringBuilder iterate(final Iterable<? extends T> elems, final String opener, final String closer,
			final String elemOpener, final String elemCloser, final Function<T, String> key, final Function<T, Object> value,
			final StringBuilder sb, final int indent) {
		sb.append(opener);
		String delim = "";
		for (final T e : elems) {
			sb.append(delim).append(EndOfElement).append(" ".repeat(indent + Indent)).append(elemOpener);
			addKeyValue(key.apply(e), value.apply(e), sb, indent + Indent);
			sb.append(elemCloser);
			delim = ",";
		}
		return sb.append(EndOfElement).append(" ".repeat(indent)).append(closer);
	}

	private static void addKeyValue(final String key, final Object value, final StringBuilder sb, final int indent) {
		if (!key.isEmpty())
			sb.append("\"").append(key).append("\": ");
		if (value == null)
			sb.append("null");
		else if (value instanceof final Json json)
			json.toJson(sb, indent);
		else if (value instanceof Number || value instanceof Boolean)
			sb.append(value);
		else if (value instanceof final Collection<?> c)
			toJsonArray(c, "", "", o -> "", Function.identity(), sb, indent);
		else if (value instanceof final Object[] oa)
			toJsonArray(List.of(oa), "", "", o -> "", Function.identity(), sb, indent);
		else if (value instanceof final Map<?, ?> m)
			toJsonArray(m.entrySet(), "{ ", " }", e -> e.getKey().toString(), Map.Entry::getValue, sb, indent);
		else if (value instanceof final byte[] ba)
			sb.append("\"").append(HexFormat.of().formatHex(ba)).append("\"");
		else
			sb.append("\"").append(escape(value.toString())).append("\"");
	}

	private static String escape(final String value) {
		final var sb = new StringBuilder();
		for (int i = 0; i < value.length(); i++) {
			final char c = value.charAt(i);
			sb.append(switch (c) {
				case '"' -> "\\\"";
				case '\\' -> "\\\\";
				case '/' -> "\\/";
				case '\b' -> "\\b";
				case '\f' -> "\\f";
				case '\n' -> "\\n";
				case '\r' -> "\\r";
				case '\t' -> "\\t";
				default -> c <= 0x1f ? String.format("\\u%04x", (int) c) : c;
			});
		}
		return sb.toString();
	}
}
