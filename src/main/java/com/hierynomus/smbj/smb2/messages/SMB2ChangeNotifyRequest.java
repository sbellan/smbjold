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

import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.SMB2CompletionFilter;
import com.hierynomus.smbj.smb2.SMB2Dialect;
import com.hierynomus.smbj.smb2.SMB2FileId;
import com.hierynomus.smbj.smb2.SMB2MessageCommandCode;
import com.hierynomus.smbj.smb2.SMB2Packet;

import java.util.EnumSet;

/**
 * [MS-SMB2].pdf 2.2.13 SMB2 CREATE Request
 * <p>
 * TODO
 */
public class SMB2ChangeNotifyRequest extends SMB2Packet {

    private static final int SMB2_WATCH_TREE = 0x0001;
    private final SMB2Dialect dialect;
    private final EnumSet<SMB2CompletionFilter> completionFilter;
    private final SMB2FileId fileId;
    private final long outputBufferLength;
    private final boolean recursive;

    public SMB2ChangeNotifyRequest(SMB2Dialect smbDialect,
                                   long sessionId,
                                   long treeId,
                                   SMB2FileId fileId,
                                   EnumSet<SMB2CompletionFilter> completionFilter,
                                   long outputBufferLength,
                                   boolean recursive) {

        super(smbDialect, SMB2MessageCommandCode.SMB2_CHANGE_NOTIFY);
        getHeader().setSessionId(sessionId);
        getHeader().setTreeId(treeId);
        this.dialect = smbDialect;
        this.fileId = fileId;
        this.completionFilter = completionFilter;
        this.outputBufferLength = outputBufferLength;
        this.recursive = recursive;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(32); // StructureSize (2 bytes)
        int flags = (recursive) ? SMB2_WATCH_TREE : 0;
        buffer.putUInt16(flags);
        buffer.putUInt32(outputBufferLength);
        fileId.write(buffer);
        buffer.putUInt32(EnumWithValue.EnumUtils.toLong(completionFilter));
        buffer.putUInt32(0);
    }
}
