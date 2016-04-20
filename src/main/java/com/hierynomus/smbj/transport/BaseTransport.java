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

import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.SMB2MessageFlag;
import com.hierynomus.smbj.smb2.SMB2Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.locks.ReentrantLock;

public abstract class BaseTransport implements TransportLayer {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    protected InputStream in;
    protected OutputStream out;

    private final ReentrantLock writeLock = new ReentrantLock();

    @Override
    public void init(InputStream in, OutputStream out) {
        this.in = in;
        this.out = out;
    }

    @Override
    public long write(SMB2Packet packet) throws TransportException {
        writeLock.lock();
        try {
            try {
                SMBBuffer buffer = new SMBBuffer();
                packet.write(buffer);
                logger.trace("Writing packet {}, sequence number {}", packet.getHeader().getMessage(), packet.getSequenceNumber());
                doWrite(buffer);
                out.flush();
            } catch (IOException ioe) {
                throw new TransportException(ioe);
            }
            return packet.getSequenceNumber();
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public void writeRequests(boolean related, SMB2Packet... packets) throws TransportException {
        if (packets.length < 2) {
            throw new IllegalArgumentException("More than 1 request expected for compounding");
        }
        writeLock.lock();
        try {
            try {
                SMBBuffer buffer = new SMBBuffer();
                SMB2Packet first = packets[0];
                int packetSize = packetSize(first);
                // Align to 8 byte boundary
                int alignmentFill = (8 - packetSize % 8) % 8;
                first.getHeader().setNextCommandOffset(packetSize + alignmentFill);
                first.write(buffer);
                buffer.putRawBytes(new byte[alignmentFill]);

                for (int i = 1; i < packets.length; i++) {
                    if (related) {
                        packets[i].getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_RELATED_OPERATIONS);
                        packets[i].getHeader().setSessionId(0xFFFFFFFFFFFFFFFFl);
                        packets[i].getHeader().setTreeId(0xFFFFFFFFl);
                    }
                    packetSize = packetSize(packets[i]);
                    alignmentFill = (8 - packetSize % 8) % 8;
                    packets[i].getHeader().setNextCommandOffset(packetSize + alignmentFill);
                    packets[i].write(buffer);
                    buffer.putRawBytes(new byte[alignmentFill]);
                }
                logger.trace("Writing {} packets", packets.length);
                doWrite(buffer);
                out.flush();
            } catch (IOException ioe) {
                throw new TransportException(ioe);
            }
        } finally {
            writeLock.unlock();
        }
    }

    private int packetSize(SMB2Packet first) {
        // Write the packet to a temporary buffer so that
        // we can figure out the size of the packet
        // TODO figure out if there is a better way
        SMBBuffer buffer = new SMBBuffer();
        first.write(buffer);
        return buffer.wpos();
    }

    protected abstract void doWrite(SMBBuffer packetData) throws IOException;
}
