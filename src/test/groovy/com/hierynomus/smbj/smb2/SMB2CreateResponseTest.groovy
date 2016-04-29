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
package com.hierynomus.smbj.smb2

import com.hierynomus.msdtyp.AccessMask
import com.hierynomus.protocol.commons.EnumWithValue
import com.hierynomus.smbj.common.SMBBuffer
import com.hierynomus.smbj.smb2.messages.SMB2CreateResponse
import spock.lang.Specification

import javax.xml.bind.DatatypeConverter

class SMB2CreateResponseTest extends Specification {

    def "should parse SMB2 Create Response with Maximal Content"() {
        given:
        String hexString1 = "fe534d42400000000000000005002100010000000000000005000000000000000000000001000000010000a0525800000000000000000000000000000000000059000000010000002022a21b2e9fd1010f85dce6399fd1010f85dce6399fd1010f85dce6399fd1010010000000000000001000000000000010000000000000003e9b03001600000001000000160000009800000020000000000000001000040000001800080000004d7841630000000000000000ff011f00";
        byte[] bytes1 = DatatypeConverter.parseHexBinary(hexString1);
        SMB2CreateResponse resp = new SMB2CreateResponse();

        when:
        resp.read(new SMBBuffer(bytes1))

        then:
        resp.accessMasks.contains(AccessMask.FILE_READ_ACCESS)
        resp.accessMasks.contains(AccessMask.FILE_WRITE_ACCESS)
        resp.accessMasks.contains(AccessMask.FILE_APPEND_ACCESS)
        Arrays.equals(([0x3e,0x9b,0x03,0x00,0x16,0x00,0x00,0x00] as byte[]), resp.fileId.persistentHandle)
    }

    def "should parse SMB2 Create Response without Maximal Content"() {
        given:
        String hexString1 = "fe534d4240000000000000000500010001000000000000000400000000000000000000000100000009000000004000000000000000000000000000000000000059000000010000006aa787efa59dd1016aa787efa59dd1016aa787efa59dd101954ff5efa59dd101000000000000000000000000000000001000000000000000030000001000000001000000100000000000000000000000";
        byte[] bytes1 = DatatypeConverter.parseHexBinary(hexString1);
        SMB2CreateResponse resp = new SMB2CreateResponse();

        when:
        resp.read(new SMBBuffer(bytes1))

        then:
        resp.accessMasks == null
        Arrays.equals(([0x03,0x00,0x00,0x00,0x10,0x00,0x00,0x00] as byte[]), resp.fileId.persistentHandle)
    }

}
