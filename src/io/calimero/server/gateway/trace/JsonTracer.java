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

import static java.lang.System.Logger.Level.DEBUG;

import java.io.IOException;
import java.io.Writer;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.util.HexFormat;

import io.calimero.DataUnitBuilder;
import io.calimero.IndividualAddress;
import io.calimero.KNXAddress;
import io.calimero.KNXFormatException;
import io.calimero.Priority;
import io.calimero.cemi.CEMI;
import io.calimero.cemi.CEMIBusMon;
import io.calimero.cemi.CEMIDevMgmt;
import io.calimero.cemi.CEMILData;
import io.calimero.cemi.CEMILDataEx;
import io.calimero.cemi.RFMediumInfo.RSS;
import io.calimero.link.medium.KNXMediumSettings;
import io.calimero.link.medium.RFLData;
import io.calimero.link.medium.RawAckBase;
import io.calimero.link.medium.RawFrame;
import io.calimero.link.medium.RawFrameBase;
import io.calimero.link.medium.RawFrameFactory;
import io.calimero.link.medium.TP1Ack;
import io.calimero.log.LogService;

final class JsonTracer implements CemiFrameTracer {
	private static final Logger logger = LogService.getLogger(MethodHandles.lookup().lookupClass().getName());

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

	private static String toJson(final CEMI frame, final String client, final Object subnet, final FramePath path) {
		record JsonTraceEvent(Instant time, Object client, Object subnet, FramePath path, Json frame) implements Json {}

		Json jsonFrame;
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

			jsonFrame = new JsonCemiFrame(svcPrimitive(ldata.getMessageCode()), extended, ldata.getSource(),
					ldata.getDestination(), ldata.isRepetition(), ldata.getHopCount(), ldata.getPriority(),
					ldata.isAckRequested(), ldata.isSystemBroadcast(), ldata.isPositiveConfirmation(), tpci, apci, asdu);
		}
		else if (frame instanceof final CEMIDevMgmt devMgmt) {
			record JsonCemiFrame(String svc, int objectType, int objectInstance, int pid, int start, int elements,
				String error, byte[] payload) implements Json {}

			jsonFrame = new JsonCemiFrame(svcPrimitiveDevMgmt(devMgmt.getMessageCode()), devMgmt.getObjectType(),
					devMgmt.getObjectInstance(), devMgmt.getPID(), devMgmt.getStartIndex(), devMgmt.getElementCount(),
					devMgmt.getErrorMessage(), devMgmt.getPayload());
		}
		else if (frame instanceof final CEMIBusMon mon) {
			record JsonMonitorIndication(String svc, long relativeTimestamp, int seqNumber, boolean frameError,
				boolean bitError, boolean parityError, boolean lost, byte[] data, Json rawFrame) implements Json {}

			final var medium = KNXMediumSettings.MEDIUM_TP1; // TODO
			final var extBusmon = false; // TODO PL110 only
			Json jsonRawFrame = null;
			try {
				jsonRawFrame = toJson(RawFrameFactory.create(medium, mon.getPayload(), 0, extBusmon));
			}
			catch (final KNXFormatException e) {
				logger.log(DEBUG, "error creating monitor raw frame from " + HexFormat.of().formatHex(mon.getPayload()), e);
			}

			jsonFrame = new JsonMonitorIndication(svcPrimitive(mon.getMessageCode()), mon.getTimestamp(),
					mon.getSequenceNumber(), mon.getFrameError(), mon.getBitError(), mon.getParityError(),
					mon.getLost(), mon.getPayload(), jsonRawFrame);
		}
		else {
			logger.log(DEBUG, "tracer does not support cEMI frame format " + frame.getClass().getSimpleName());
			return null;
		}

		final var jsonTraffic = new JsonTraceEvent(Instant.now(), client, subnet, path, jsonFrame);
		return jsonTraffic.toJson();
	}

	private static Json toJson(final RawFrame rawFrame) {
		if (rawFrame instanceof final RawFrameBase f) {
			final byte[] tpdu = f.getTPDU();
			final String tpci = DataUnitBuilder.decodeTPCI(DataUnitBuilder.getTPDUService(tpdu), f.getDestination());
			final String apci = DataUnitBuilder.decodeAPCI(DataUnitBuilder.getAPDUService(tpdu));
			final byte[] asdu = DataUnitBuilder.extractASDU(tpdu);

			record JsonRawFrame(String svc, boolean extended, IndividualAddress src, KNXAddress dst,
					boolean repetition, int hopCount, Priority priority, String tpci, String apci, byte[] asdu,
					int checksum) implements Json {}
			return new JsonRawFrame(frameFormat(f.getFrameType()), f.extended(), f.getSource(), f.getDestination(),
					f.isRepetition(), f.getHopcount(), f.getPriority(), tpci, apci, asdu, f.getChecksum());
		}
		else if (rawFrame instanceof final RawAckBase ack) {
			record JsonRawAck(String svc, String ackType) implements Json {}
			return new JsonRawAck(frameFormat(ack.getFrameType()), ackType(ack.getAckType()));
		}
		else if (rawFrame instanceof final RFLData rf) {
			final byte[] tpdu = rf.getTpdu();
			final String tpci = DataUnitBuilder.decodeTPCI(DataUnitBuilder.getTPDUService(tpdu), rf.getDestination());
			final String apci = DataUnitBuilder.decodeAPCI(DataUnitBuilder.getAPDUService(tpdu));
			final byte[] asdu = DataUnitBuilder.extractASDU(tpdu);
			final byte[] doa = rf.isSystemBroadcast() ? null : rf.getDoAorSN();
			final byte[] sn = rf.isSystemBroadcast() ? rf.getDoAorSN() : null;

			record JsonRfLData(String svc, IndividualAddress src, KNXAddress dst, int frameNumber,
					boolean systemBroadcast, RSS rss, boolean batteryOk, boolean txOnlyDevice, byte[] doa,
					byte[] sn, String tpci, String apci, byte[] asdu, int checksum) implements Json {}
			return new JsonRfLData(frameFormatRf(rf.getFrameType()), rf.getSource(), rf.getDestination(),
					rf.getFrameNumber(), rf.isSystemBroadcast(), rf.getRss(), rf.isBatteryOk(),
					rf.isTransmitOnlyDevice(), doa, sn, tpci, apci, asdu, 0);
		}
		else if (rawFrame != null)
			logger.log(DEBUG, "unsupported frame type " + rawFrame);
		return null;
	}

	private static String frameFormat(final int format) {
		return switch (format) {
			case RawFrame.LDATA_FRAME -> "L-Data";
			case RawFrame.LPOLLDATA_FRAME -> "L-PollData";
			case RawFrame.ACK_FRAME -> "Ack";
			default -> "" + format;
		};
	}

	private static String frameFormatRf(final int format) {
		final String lte = (format & 0x0c) == 0x04 ? "LTE " : "";
		return lte + switch (format) {
			case 0 -> "L-Data (async)";
			case 1 -> "Fast Ack";
			case 4 -> "L-Data (sync)";
			case 5 -> "BiBat Sync";
			case 6 -> "BiBat Help Call";
			case 7 -> "BiBat Help Call Res";
			case 8 -> "RF Multi L-Data (async)";
			case 9 -> "RF Multi L-Data (async, Ack.req)";
			case 10 -> "RF Multi Repeater Ack";
			default -> "" + format;
		};
	}

	private static String ackType(final int ackType) {
		return switch (ackType) {
			case RawAckBase.ACK -> "ACK";
			case RawAckBase.NAK -> "NAK";
			case TP1Ack.BUSY -> "BUSY";
			case TP1Ack.NAK_BUSY -> "NAK_BUSY";
			default -> "" + ackType;
		};
	}

	private static String svcPrimitiveDevMgmt(final int msgCode) {
		return switch (msgCode) {
			case CEMIDevMgmt.MC_PROPREAD_REQ -> "prop-read.req";
			case CEMIDevMgmt.MC_PROPREAD_CON -> "prop-read.con";
			case CEMIDevMgmt.MC_PROPWRITE_REQ -> "prop-write.req";
			case CEMIDevMgmt.MC_PROPWRITE_CON -> "prop-write.con";
			case CEMIDevMgmt.MC_PROPINFO_IND -> "prop-info.ind";
			case CEMIDevMgmt.MC_FUNCPROP_CMD_REQ -> "funcprop-cmd.req";
			case CEMIDevMgmt.MC_FUNCPROP_READ_REQ -> "funcprop-read.req";
			case CEMIDevMgmt.MC_FUNCPROP_CON -> "funcprop.con";
			case CEMIDevMgmt.MC_RESET_REQ -> "DM reset.req";
			case CEMIDevMgmt.MC_RESET_IND -> "DM reset.ind";
			default -> "0x" + Integer.toHexString(msgCode);
		};
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
