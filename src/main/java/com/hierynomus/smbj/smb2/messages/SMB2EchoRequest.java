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
import com.hierynomus.smbj.smb2.SMB2MessageCommandCode;
import com.hierynomus.smbj.smb2.SMB2Packet;

/**
 * [MS-SMB2].pdf 2.2.28 SMB2 ECHO Request
 */
public class SMB2EchoRequest extends SMB2Packet {

    public SMB2EchoRequest(SMB2Dialect dialect) {
        super(dialect, SMB2MessageCommandCode.SMB2_ECHO);
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(4); // StructureSize (2 bytes)
        buffer.putUInt16(0); // Reserved
    }
}
