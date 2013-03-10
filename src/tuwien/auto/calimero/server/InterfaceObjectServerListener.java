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

import java.util.EventListener;

/**
 * A listener for use with a {@link InterfaceObjectServer}.
 * <p>
 * 
 * @author B. Malinowsky
 */
public interface InterfaceObjectServerListener extends EventListener
{
	/**
	 * Notifies about a KNX property value change in the Interface Object Server.
	 * <p>
	 * 
	 * @param pe contains details about the changed property value
	 */
	void onPropertyValueChanged(PropertyEvent pe);
}
