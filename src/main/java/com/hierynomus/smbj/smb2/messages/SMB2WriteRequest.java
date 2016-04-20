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
package com.hierynomus.smbj.smb2.messages;

import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.SMB2Dialect;
import com.hierynomus.smbj.smb2.SMB2FileId;
import com.hierynomus.smbj.smb2.SMB2Header;
import com.hierynomus.smbj.smb2.SMB2MessageCommandCode;
import com.hierynomus.smbj.smb2.SMB2Packet;

/**
 * [MS-SMB2].pdf 2.2.21 SMB2 Write Request
 *
 */
public class SMB2WriteRequest extends SMB2Packet {

    private final long offset;
    private final SMB2FileId fileId;
    private final byte[] data;
    private final long length;
    private final long remainingBytes; // Used for write caching

    public SMB2WriteRequest(
            SMB2Dialect negotiatedDialect, SMB2FileId fileId,
            long sessionId, long treeId, byte data[], long length, long offset, long remainingBytes) {
        super(negotiatedDialect, SMB2MessageCommandCode.SMB2_WRITE);
        getHeader().setSessionId(sessionId);
        getHeader().setTreeId(treeId);
        this.fileId = fileId;
        this.data = data;
        this.length = length;
        this.offset = offset;
        this.remainingBytes = remainingBytes;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(49); // StructureSize (2 bytes)
        short dataOffset = SMB2Header.STRUCTURE_SIZE + 48;
        buffer.putUInt16(dataOffset); // OffSet (2 bytes)
        buffer.putUInt32(length); // Length of data (4 bytes)
        buffer.putUInt64(offset); // Offset (8 bytes)
        fileId.write(buffer);  // File Id
        buffer.putUInt32(0); // Channel (4 bytes)
        buffer.putUInt32(remainingBytes); // Remaining bytes (4 bytes)
        buffer.putUInt16(0); // WriteChannelInfoOffset (2 bytes)
        buffer.putUInt16(0); // WriteChannelInfoLength (2 bytes)
        buffer.putUInt32(0); // Flags (4 bytes)
        buffer.putRawBytes(data); // Buffer
    }
}
