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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.SMB2FileId;
import com.hierynomus.smbj.smb2.SMB2Packet;
import com.hierynomus.smbj.smb2.SMB2StatusCode;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.EnumSet;

/**
 * [MS-SMB2].pdf 2.2.14 SMB2 CREATE Response
 *
 */
public class SMB2CreateResponse extends SMB2Packet {

    private Date creationTime;
    private Date lastAccessTime;
    private Date lastWriteTime;
    private Date changeTime;
    private EnumSet<FileAttributes> fileAttributes;
    private SMB2FileId fileId;
    private EnumSet<AccessMask> accessMasks;


    public SMB2CreateResponse() {
        super();
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        if (header.getStatus() == SMB2StatusCode.STATUS_SUCCESS) {
            buffer.readUInt16(); // Structure Size (2 bytes)
            buffer.readByte(); // OpLock Level (1 byte) - Not used yet
            buffer.readByte(); // Flags (1 byte) - Only for 3.x else Reserved
            buffer.readUInt32(); // Create Action (4 bytes) - Ignored for now
            creationTime = MsDataTypes.readFileTime(buffer); // CreationTime (8 bytes)
            lastAccessTime = MsDataTypes.readFileTime(buffer); // LastAccessTime (8 bytes)
            lastWriteTime = MsDataTypes.readFileTime(buffer); // LastWriteTime (8 bytes)
            changeTime = MsDataTypes.readFileTime(buffer); // ChangeTime (8 bytes)
            buffer.readRawBytes(8); // Allocation Size (8 bytes) - Ignore
            buffer.readRawBytes(8); // EndOfFile (8 bytes)
            fileAttributes = EnumWithValue.EnumUtils.toEnumSet(buffer.readUInt32(),
                    FileAttributes.class);
            buffer.readUInt32(); // Reserved2 (4 bytes)
            fileId = SMB2FileId.read(buffer);

            // Ignore create contexts and the buffer.
            long createContextOffset = buffer.readUInt32();// CreateContextsOffset (4 bytes)
            long createContextLength = buffer.readUInt32();// CreateContextsLength (4 bytes)

            if (createContextOffset != 0) {
                buffer.rpos((int)createContextOffset);
                int currentContextPos = buffer.rpos();
                long chainOffset = 0;
                do {
                    chainOffset = buffer.readUInt32(); // Next (4 bytes)
                    int nameOffset = buffer.readUInt16(); // NameOffset (2 bytes)
                    int nameLength = buffer.readUInt16(); // NameLength (2 bytes)
                    buffer.skip(2); // Reserved (2 bytes)
                    int dataOffset = buffer.readUInt16(); // DataOffset (2 bytes)
                    long dataLength = buffer.readUInt32(); // DataLength (4 bytes)
                    buffer.rpos(currentContextPos + nameOffset);
                    byte[] name = buffer.readRawBytes(nameLength); // Buffer (Name) Variable
                    if (Arrays.equals(name, new byte[] {'M','x','A','c'})) { // MxAc
                        buffer.rpos(currentContextPos + dataOffset);
                        long queryStatus = buffer.readUInt32(); // QueryStatus (4 bytes)
                        long maximalAccess = buffer.readUInt32(); // MaximalAccess (4 bytes)
                        // It uses the same NT_STATUS code
                        if (queryStatus == SMB2StatusCode.STATUS_SUCCESS.getValue()) {
                            accessMasks = EnumWithValue.EnumUtils.toEnumSet(maximalAccess, AccessMask.class);
                        }
                    } else {
                        // Just skip for now
                        buffer.skip((int)(nameLength + dataLength));
                    }
                    currentContextPos += chainOffset;
                    buffer.rpos(currentContextPos);

                } while (chainOffset != 0);
            }

        }
    }

    public Date getCreationTime() {
        return creationTime;
    }

    public Date getLastAccessTime() {
        return lastAccessTime;
    }

    public Date getLastWriteTime() {
        return lastWriteTime;
    }

    public Date getChangeTime() {
        return changeTime;
    }

    public EnumSet<FileAttributes> getFileAttributes() {
        return fileAttributes;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    public EnumSet<AccessMask> getAccessMasks() {
        return accessMasks;
    }
}
