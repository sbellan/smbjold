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

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.SMB2Packet;

/**
 * [MS-SMB2].pdf 2.2.7 SMB2 Logoff Request / 2.2.8 SMB Logoff Response
 */
public class SMB2SetInfoResponse extends SMB2Packet {

    public SMB2SetInfoResponse() {
        super();
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.skip(2); // StructureSize (2 bytes)
    }
}
