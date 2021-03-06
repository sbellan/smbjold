/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hierynomus.smbj.transport;

import com.hierynomus.smbj.smb2.SMB2Packet;

import java.io.InputStream;
import java.io.OutputStream;

public interface TransportLayer {

    /**
     * Initialize the Transport layer.
     *
     * This is called directly after a connection has been established.
     */
    void init(InputStream in, OutputStream out);

    /**
     * The default port for the specified SMB transport layer.
     *
      * @return the default port
     */
    int getDefaultPort();

    /**
     * Write the packet to the transport.
     * @param packet The packet to write.
     * @return The sequence number of the packet.
     */
    long write(SMB2Packet packet) throws TransportException;

    /**
     * Send the packets as compounded requests
     * MS-SMB2 3.2.4.1.4 Sending Compounded Requests
     * @param packets
     * @throws TransportException
     */
    void writeRequests(boolean related, SMB2Packet... packets) throws TransportException;

}
