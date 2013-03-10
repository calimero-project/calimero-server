/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2011 B. Malinowsky

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
*/

package tuwien.auto.calimero.server;

import tuwien.auto.calimero.exception.KNXException;

/**
 * Thrown on problems during access of a KNX property.
 * <p>
 * 
 * @author B. Malinowsky
 */
public class KNXPropertyException extends KNXException
{
	private static final long serialVersionUID = 1L;

	private final int code;

	/**
	 * Constructs a new <code>KNXPropertyException</code> without a detail message.
	 * <p>
	 * The status code is assigned 0.
	 */
	public KNXPropertyException()
	{
		code = 0;
	}

	/**
	 * Constructs a new <code>KNXPropertyException</code> with the specified detail message.
	 * <p>
	 * The status code is assigned 0.
	 * 
	 * @param s the detail message
	 */
	public KNXPropertyException(final String s)
	{
		super(s);
		code = 0;
	}

	/**
	 * Constructs a new <code>KNXPropertyException</code> with the specified detail message and a
	 * status or error code indicating the problem during property access.
	 * <p>
	 * Within the library, for the status code one of the codes listed in CEMIDevMgmt.ErrorCodes is
	 * used.
	 * 
	 * @param s the detail message
	 * @param statusCode the status code for the problem
	 */
	public KNXPropertyException(final String s, final int statusCode)
	{
		super(s);
		code = statusCode;
	}

	/**
	 * Returns the status code assigned to this exception.
	 * <p>
	 * If this exception originates from within the library, the status code is one of the codes
	 * listed in CEMIDevMgmt.ErrorCodes.
	 * 
	 * @return status code as int
	 */
	public final int getStatusCode()
	{
		return code;
	}
}
