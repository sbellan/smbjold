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

import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.ntlm.functions.NtlmFunctions;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.SMB2Packet;
import com.hierynomus.smbj.smb2.SMB2StatusCode;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * [MS-SMB2].pdf 2.2.34 SMB2 QUERY_DIRECTORY Response
 * <p>
\ */
public class SMB2QueryDirectoryResponse extends SMB2Packet {

    List<FileInfo> fileInfoList;

    public SMB2QueryDirectoryResponse() {
        super();
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        // TODO how to handle errors correctly
        if (header.getStatus() != SMB2StatusCode.STATUS_SUCCESS) return;

        buffer.skip(2); // StructureSize (2 bytes)
        int outputBufferOffset = buffer.readUInt16(); // Buffer Offset
        int outBufferLength = buffer.readUInt16(); // Buffer length
        fileInfoList = readOutputBuffer(buffer, outputBufferOffset, outBufferLength);
    }

    // Assume response is for FileIdBothDirectoryInformation
    private List<FileInfo> readOutputBuffer(SMBBuffer buffer, int outputBufferOffset, int outBufferLength)
            throws Buffer.BufferException {
        List<FileInfo> _fileInfoList = new ArrayList<>();
        buffer.rpos(outputBufferOffset);
        int offsetStart = outputBufferOffset;
        int nextEntryOffset = offsetStart;
        long fileNameLen = 0;
        long fileIndex = 0;
        String fileName = null;
        long fileAttributes;
        byte[] fileId = null;
        long fileSize;
        while (nextEntryOffset != 0) {
            nextEntryOffset = (int)buffer.readUInt32();
            fileIndex = buffer.readUInt32();
            Date creationTime = MsDataTypes.readFileTime(buffer);
            Date lastAccessTime = MsDataTypes.readFileTime(buffer);
            Date lastWriteTime = MsDataTypes.readFileTime(buffer);
            Date changeTime = MsDataTypes.readFileTime(buffer);
            fileSize = buffer.readUInt64(); // EndOfFile - Ignored
            buffer.readRawBytes(8); // AllocationSize - Ignored
            fileAttributes = buffer.readUInt32(); // File Attributes
            fileNameLen = buffer.readUInt32(); // File name length
            buffer.readUInt32(); // EaSize - Ignored
            buffer.readByte(); // Shortname length (1)
            buffer.readByte(); // Reserved1 (1)
            buffer.readRawBytes(24); // Shortname
            buffer.readUInt16(); // Reserved2
            fileId = buffer.readRawBytes(8);
            fileName = buffer.readString(NtlmFunctions.UNICODE, (int)fileNameLen/2);
            if (!(".".equals(fileName) || "..".equals(fileName))) {
                _fileInfoList.add(new FileInfo(fileName, fileId, fileAttributes, fileSize));
            }
            offsetStart += nextEntryOffset;
            buffer.rpos(offsetStart);
        }
        return _fileInfoList;
    }

    public List<FileInfo> getFileInfoList() {
        return fileInfoList;
    }

    public static class FileInfo {
        byte[] fileId; // This is not the SMB2FileId, but not sure what one can do with this id.
        String fileName;
        long fileAttributes;
        long fileSize;


        public FileInfo(String fileName, byte[] fileId, long fileAttributes, long fileSize) {
            this.fileName = fileName;
            this.fileId = fileId;
            this.fileAttributes = fileAttributes;
            this.fileSize = fileSize;
        }

        public byte[] getFileId() {
            return fileId;
        }

        public String getFileName() {
            return fileName;
        }

        public long getFileAttributes() {
            return fileAttributes;
        }

        @Override
        public String toString() {
            return "FileInfo{" +
                    "fileName='" + fileName + '\'' +
                    "fileSize='" + fileSize + '\'' +
                    ", fileAttributes=" + EnumWithValue.EnumUtils.toEnumSet(fileAttributes, FileAttributes.class) +
                    '}';
        }

    }

    public static class FileInfoFormatter {
        public static void print(List<FileInfo> fileInfos) {
            String format = "%-50s %-10s %-50s\n";
            System.out.printf(format, "Name", "Size", "Attributes");
            System.out.printf(format, "----", "----", "----------");
            for (FileInfo fi: fileInfos) {
                System.out.printf(format, fi.getFileName(), readableFileSize(fi.fileSize),
                        EnumWithValue.EnumUtils.toEnumSet(fi.getFileAttributes(), FileAttributes.class));
            }
        }

        public static String readableFileSize(long size) {
            if(size <= 0) return "0";
            final String[] units = new String[] { "B", "KB", "MB", "GB", "TB", "PB", "EB" };
            int digitGroups = (int) (Math.log10(size)/Math.log10(1024));
            String result = null;
            result = new DecimalFormat("#,##0.#").format(size/Math.pow(1024, digitGroups)) + " " + units[digitGroups];
            return result;
        }
    }
}
