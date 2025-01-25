/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2024, 2024 B. Malinowsky

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

import static java.lang.System.Logger.Level.DEBUG;

import java.io.IOException;
import java.io.Writer;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.lang.invoke.MethodHandles;
import java.time.Instant;

import io.calimero.DataUnitBuilder;
import io.calimero.IndividualAddress;
import io.calimero.KNXAddress;
import io.calimero.Priority;
import io.calimero.cemi.CEMI;
import io.calimero.cemi.CEMILData;
import io.calimero.cemi.CEMILDataEx;

final class JsonTracer implements CemiFrameTracer {
	private static final Logger logger = System.getLogger(MethodHandles.lookup().lookupClass().getName());

	private final Writer writer;

	JsonTracer(final Writer writer) { this.writer = writer; }

	@Override
	public void trace(final CEMI msg, final String client, final Object subnet, final FramePath path) {
		try {
			final String json = toJson(msg, client, subnet, path);
			if (json != null) {
				final String s = json + "\n";
				writer.append(s).flush();
			}
		} catch (IOException | RuntimeException e) {
			logger.log(Logger.Level.WARNING, "failed to trace cEMI frame", e);
		}
	}

	@Override
	public void close() {
		try {
			writer.close();
		}
		catch (final IOException e) {
			logger.log(Level.INFO, "error closing cEMI frame trace", e);
		}
	}

	// TODO does not support LocalDevMmgmt, BAOS, or T-Data
	private static String toJson(final CEMI frame, final String client, final Object subnet, final FramePath path) {
		if (frame instanceof final CEMILData ldata) {
			final boolean extended = ldata instanceof CEMILDataEx;
			final var payload = frame.getPayload();
			String tpci = "";
			String apci = "";
			byte[] asdu = null;
			if (payload.length > 1) {
				tpci = DataUnitBuilder.decodeTPCI(DataUnitBuilder.getTPDUService(payload), ldata.getDestination());
				apci = DataUnitBuilder.decodeAPCI(DataUnitBuilder.getAPDUService(payload));
				asdu = DataUnitBuilder.extractASDU(payload);
			}

			// ??? add boolean lengthOptimizedApdu, String decodedAsdu
			record JsonCemiFrame(String svc, boolean extended, IndividualAddress src, KNXAddress dst,
					boolean repetition, int hopCount, Priority priority, boolean ack, boolean sysBcast, boolean con,
					String tpci, String apci, byte[] asdu) implements Json {}
			record JsonTraceEvent(Instant time, Object client, Object subnet, FramePath path, JsonCemiFrame frame) implements Json {}

			final var json = new JsonCemiFrame(svcPrimitive(ldata.getMessageCode()), extended, ldata.getSource(),
					ldata.getDestination(), ldata.isRepetition(), ldata.getHopCount(), ldata.getPriority(),
					ldata.isAckRequested(), ldata.isSystemBroadcast(), ldata.isPositiveConfirmation(), tpci, apci,
					asdu);
			final var jsonTraffic = new JsonTraceEvent(Instant.now(), client, subnet, path, json);
			return jsonTraffic.toJson();
		}
		else { // we shouldn't receive CEMIBusMon, CEMIDevMgmt, or CemiTData here
			// XXX check other formats, at least CEMIBusMon we have to support
			logger.log(DEBUG, "tracer does not support cEMI frame format " + frame.getClass().getSimpleName());
			return null;
		}
	}

	private static String svcPrimitive(final int msgCode) {
		return switch (msgCode) {
			case 0x2B -> "L_Busmon.ind";
			case 0x11 -> "L_Data.req";
			case 0x2E -> "L_Data.con";
			case 0x29 -> "L_Data.ind";
			case 0x10 -> "L_Raw.req";
			case 0x2D -> "L_Raw.ind";
			case 0x2F -> "L_Raw.con";
			case 0x13 -> "L_Poll_Data.req";
			case 0x25 -> "L_Poll_Data.con";
			case 0x41 -> "T_Data_Connected.req";
			case 0x89 -> "T_Data_Connected.ind";
			case 0x4A -> "T_Data_Individual.req";
			case 0x94 -> "T_Data_Individual.ind";
			default -> "0x" + Integer.toHexString(msgCode);
		};
	}
}