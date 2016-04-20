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
package com.hierynomus.msfscc.fileinformation;

import com.hierynomus.ntlm.functions.NtlmFunctions;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;

public class FileInformationFactory {

    /**
     * MS-FSCC 2.4.34.2 FileRenameInformation for SMB2
     */
    public static byte[] getRenameInfo(boolean replaceIfExists, String newName) {
        Buffer.PlainBuffer renBuf = new Buffer.PlainBuffer(Endian.LE);
        renBuf.putByte((byte)(replaceIfExists ? 1 : 0));
        renBuf.skip(7);
        renBuf.putUInt64(0);
        renBuf.putUInt32(newName.length() * 2); // unicode
        renBuf.putRawBytes(NtlmFunctions.unicode(newName));
        return renBuf.getCompactData();
    }

    /**
     * MS-FSCC 2.4.11 FileDispositionInformation for SMB2
     */
    public static byte[] getFileDispositionInfo(boolean deleteOnClose) {
        Buffer.PlainBuffer fileDispBuf = new Buffer.PlainBuffer(Endian.LE);
        fileDispBuf.putByte((byte)(deleteOnClose ? 1 : 0));
        return fileDispBuf.getCompactData();
    }


}
