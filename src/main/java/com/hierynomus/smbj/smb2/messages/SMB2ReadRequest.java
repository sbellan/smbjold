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
import com.hierynomus.smbj.smb2.SMB2MessageCommandCode;
import com.hierynomus.smbj.smb2.SMB2Packet;

/**
 * [MS-SMB2].pdf 2.2.19 SMB2 READ Request
 *
 */
public class SMB2ReadRequest extends SMB2Packet {

    final long READ_SIZE = 64 * 1024;
    private final long offset;
    private SMB2FileId fileId;

    public SMB2ReadRequest(
            SMB2Dialect negotiatedDialect, SMB2FileId fileId,
            long sessionId, long treeId, long offset) {
        super(negotiatedDialect, SMB2MessageCommandCode.SMB2_READ);
        getHeader().setSessionId(sessionId);
        getHeader().setTreeId(treeId);
        this.fileId = fileId;
        this.offset = offset;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(49); // StructureSize (2 bytes)
        buffer.putByte((byte) 0); // Padding (1 byte)
        buffer.putByte((byte) 0); // Flags (1 byte)
        buffer.putUInt32(READ_SIZE); // Length to read (4 bytes)
        buffer.putUInt64(offset); // Offset (8 bytes)
        fileId.write(buffer);  // File Id
        buffer.putUInt32(1); // Minimum Count (4 bytes)
        buffer.putUInt32(0); // Channel (4 bytes)
        //buffer.putUInt32(READ_SIZE); // Remaining bytes (4 bytes)
        buffer.putUInt32(0);
        buffer.putUInt16(0); // Read channel info offset (2 bytes)
        buffer.putUInt16(0); // Read channel info length (2 bytes)
        buffer.putByte((byte)0); // Buffer
    }
}
