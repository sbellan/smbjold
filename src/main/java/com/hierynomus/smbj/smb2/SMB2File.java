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
package com.hierynomus.smbj.smb2;

import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.msfscc.fileinformation.FileInfo;
import com.hierynomus.msfscc.fileinformation.FileInformationFactory;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.smbj.api.SmbApiException;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.common.SMBTreeConnect;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.smb2.messages.SMB2ChangeNotifyRequest;
import com.hierynomus.smbj.smb2.messages.SMB2ChangeNotifyResponse;
import com.hierynomus.smbj.smb2.messages.SMB2Close;
import com.hierynomus.smbj.smb2.messages.SMB2CreateRequest;
import com.hierynomus.smbj.smb2.messages.SMB2CreateResponse;
import com.hierynomus.smbj.smb2.messages.SMB2QueryDirectoryRequest;
import com.hierynomus.smbj.smb2.messages.SMB2QueryDirectoryResponse;
import com.hierynomus.smbj.smb2.messages.SMB2QueryInfoRequest;
import com.hierynomus.smbj.smb2.messages.SMB2QueryInfoResponse;
import com.hierynomus.smbj.smb2.messages.SMB2ReadRequest;
import com.hierynomus.smbj.smb2.messages.SMB2ReadResponse;
import com.hierynomus.smbj.smb2.messages.SMB2SetInfoRequest;
import com.hierynomus.smbj.smb2.messages.SMB2SetInfoResponse;
import com.hierynomus.smbj.smb2.messages.SMB2WriteRequest;
import com.hierynomus.smbj.smb2.messages.SMB2WriteResponse;
import com.hierynomus.smbj.transport.TransportException;
import com.hierynomus.utils.PathUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.EnumSet;
import java.util.List;

/**
 * Provides operations on already open file and also static methods for open/op/close
 * <p>
 * MS-SMB2.pdf 3.2.1.6 Per Application Open of a File
 */
public class SMB2File {

    private static final Logger logger = LoggerFactory.getLogger(SMB2File.class);

    SMB2FileId fileId;
    SMBTreeConnect treeConnect;
    String fileName;

    long accessMask;
    EnumSet<SMB2ShareAccess> shareAccess;
    EnumSet<SMB2CreateOptions> createOptions;
    EnumSet<FileAttributes> fileAttributes;
    SMB2CreateDisposition createDisposition;

    public SMB2File(SMB2FileId fileId, SMBTreeConnect treeConnect, String fileName, long accessMask,
                    EnumSet<SMB2ShareAccess> shareAccess, EnumSet<SMB2CreateOptions> createOptions,
                    EnumSet<FileAttributes> fileAttributes, SMB2CreateDisposition createDisposition) {
        this.fileId = fileId;
        this.treeConnect = treeConnect;
        this.fileName = fileName;
        this.accessMask = accessMask;
        this.shareAccess = shareAccess;
        this.createOptions = createOptions;
        this.fileAttributes = fileAttributes;
        this.createDisposition = createDisposition;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    public SMBTreeConnect getTreeConnect() {
        return treeConnect;
    }

    public List<FileInfo> list() throws TransportException, SmbApiException {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        // Query Directory Request
        SMB2QueryDirectoryRequest qdr = new SMB2QueryDirectoryRequest(connection.getNegotiatedDialect(),
                session.getSessionId(), treeConnect.getTreeId(),
                getFileId(), FileInformationClass.FileIdBothDirectoryInformation, // FileInformationClass
                // .FileDirectoryInformation,
                EnumSet.of(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.SMB2_REOPEN),
                0, null);
        connection.send(qdr);
        SMB2QueryDirectoryResponse qdresp = (SMB2QueryDirectoryResponse) connection.receive().get(0);
        if (qdresp.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(qdresp.getHeader().getStatus(), qdresp.getHeader().getStatusCode(),
                    "Query directory failed for " + fileName + "/" + fileId, null);
        }
        byte[] outputBuffer = qdresp.getOutputBuffer();

        try {
            return FileInformationFactory.parseFileInformationList(
                    outputBuffer, qdresp.getOutputBufferOffset(), qdresp.getOutBufferLength(), FileInformationClass
                            .FileAllInformation);
        } catch (Buffer.BufferException e) {
            throw new TransportException(e);
        }
    }

    public void write(InputStream srcStream) throws IOException, SmbApiException {
        byte[] buf = new byte[8192];
        int numRead = -1;
        int offset = 0;

        Session session = getTreeConnect().getSession();
        Connection connection = session.getConnection();


        while ((numRead = srcStream.read(buf)) != -1) {
            //logger.debug("Writing {} bytes", numRead);
            SMB2WriteRequest wreq = new SMB2WriteRequest(connection.getNegotiatedDialect(), getFileId(),
                    session.getSessionId(), getTreeConnect().getTreeId(),
                    buf, numRead, offset, 0);
            connection.send(wreq);
            SMB2WriteResponse wresp = (SMB2WriteResponse) connection.receive().get(0);
            if (wresp.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
                throw new SmbApiException(wresp.getHeader().getStatus(), wresp.getHeader().getStatusCode(),
                        "Write failed for " + this, null);
            }
            offset += numRead;
        }
    }

    public void read(OutputStream destStream) throws IOException,
            SmbApiException {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        long offset = 0;
        SMB2ReadRequest rreq = new SMB2ReadRequest(connection.getNegotiatedDialect(), getFileId(),
                session.getSessionId(), treeConnect.getTreeId(), offset);

        connection.send(rreq);
        SMB2ReadResponse rresp = (SMB2ReadResponse) connection.receive().get(0);
        while (rresp.getHeader().getStatus() == SMB2StatusCode.STATUS_SUCCESS &&
                rresp.getHeader().getStatus() != SMB2StatusCode.STATUS_END_OF_FILE) {
            destStream.write(rresp.getData());
            offset += rresp.getDataLength();
            rreq = new SMB2ReadRequest(connection.getNegotiatedDialect(), getFileId(),
                    session.getSessionId(), treeConnect.getTreeId(), offset);
            connection.send(rreq);
            rresp = (SMB2ReadResponse) connection.receive().get(0);
        }

        if (rresp.getHeader().getStatus() != SMB2StatusCode.STATUS_END_OF_FILE) {
            throw new SmbApiException(rresp.getHeader().getStatus(), rresp.getHeader().getStatusCode(),
                    "Read failed for " + this, null);
        }
    }

    /**
     * Read a file and write the data to the given output stream
     *
     * @param treeConnect
     * @param path
     * @param destStream
     * @throws SmbApiException
     * @throws IOException
     */
    public static void read(SMBTreeConnect treeConnect, String path, OutputStream destStream)
            throws SmbApiException, IOException {
        logger.info("Read {}", path);
        SMB2File fileHandle = openFile(treeConnect, path,
                EnumSet.of(SMB2DirectoryAccessMask.GENERIC_READ), SMB2CreateDisposition.FILE_OPEN);

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        try {
            long offset = 0;
            SMB2ReadRequest rreq = new SMB2ReadRequest(connection.getNegotiatedDialect(), fileHandle.getFileId(),
                    session.getSessionId(), treeConnect.getTreeId(), offset);

            connection.send(rreq);
            SMB2ReadResponse rresp = (SMB2ReadResponse) connection.receive().get(0);
            while (rresp.getHeader().getStatus() == SMB2StatusCode.STATUS_SUCCESS &&
                    rresp.getHeader().getStatus() != SMB2StatusCode.STATUS_END_OF_FILE) {
                destStream.write(rresp.getData());
                offset += rresp.getDataLength();
                rreq = new SMB2ReadRequest(connection.getNegotiatedDialect(), fileHandle.getFileId(),
                        session.getSessionId(), treeConnect.getTreeId(), offset);
                connection.send(rreq);
                rresp = (SMB2ReadResponse) connection.receive().get(0);
            }

            if (rresp.getHeader().getStatus() != SMB2StatusCode.STATUS_END_OF_FILE) {
                throw new SmbApiException(rresp.getHeader().getStatus(), rresp.getHeader().getStatusCode(),
                        "Read failed for " + path, null);
            }

        } finally {
            fileHandle.close();
            ;
        }
    }


    /**
     * Write the given input stream to the given path
     *
     * @param treeConnect
     * @param path
     * @param overWrite   if true, overwrite if a file with same name exists.
     * @param srcStream
     * @throws SmbApiException
     * @throws IOException
     */
    public static void write(SMBTreeConnect treeConnect, String path, boolean overWrite, InputStream srcStream)
            throws SmbApiException, IOException {
        logger.info("Write {},{}", path, overWrite);
        SMB2CreateDisposition createDisposition = SMB2CreateDisposition.FILE_OVERWRITE_IF;
        if (!overWrite) createDisposition = SMB2CreateDisposition.FILE_CREATE;
        SMB2File fileHandle =
                openFile(treeConnect, path, EnumSet.of(SMB2DirectoryAccessMask.GENERIC_WRITE), createDisposition);

        try {
            fileHandle.write(srcStream);
        } finally {
            fileHandle.close();
        }
    }

    /**
     * @param treeConnect Tree Connect
     * @param path        Path relative to the connect root.
     *                    Leave null or empty to list the root directory
     * @return List of FileInfo
     * @throws SmbApiException
     * @throws TransportException
     */
    public static List<FileInfo> list(SMBTreeConnect treeConnect, String path)
            throws SmbApiException, TransportException {
        logger.info("List {}", path);

        SMB2File fileHandle = openDirectory(treeConnect, path,
                EnumSet.of(SMB2DirectoryAccessMask.GENERIC_READ),
                EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE, SMB2ShareAccess
                        .FILE_SHARE_READ),
                SMB2CreateDisposition.FILE_OPEN,
                EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));

        try {
            return fileHandle.list();
        } finally {
            if (fileHandle != null) {
                fileHandle.closeSilently();
            }
        }
    }

    /**
     * SMB2 CHANGE NOTIFY
     * <p>
     * This is implemented as blocking call which will wait until any changes have been observed.
     * Clients who expect to be continuously notified should invoke this function again to listen
     * for more changes.
     *
     * @return
     * @throws TransportException
     * @throws SmbApiException
     */
    public static List<SMB2ChangeNotifyResponse.FileNotifyInfo> notify(SMBTreeConnect treeConnect, SMB2File
            fileHandle)
            throws TransportException, SmbApiException {

        int bufferLength = 64 * 1024;

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2ChangeNotifyRequest cnr = new SMB2ChangeNotifyRequest(
                SMB2Dialect.SMB_2_1,
                session.getSessionId(), treeConnect.getTreeId(),
                fileHandle.getFileId(),
                EnumSet.of(
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_DIR_NAME,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_ATTRIBUTES,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_CREATION,
//                                SMB2CompletionFilter.FILE_NOTIFY_CHANGE_SIZE,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_SECURITY,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_STREAM_SIZE,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_STREAM_WRITE),
                bufferLength, true);
        cnr.getHeader().setCreditRequest(256);
        cnr.getHeader().setCreditCost(1);
        connection.send(cnr);

        SMB2ChangeNotifyResponse cnresponse = (SMB2ChangeNotifyResponse) connection.receive().get(0);
        // Wait till we get a permanent response
        while (cnresponse.getHeader().getStatus() == SMB2StatusCode.STATUS_PENDING
                && cnresponse.getHeader().getAsyncId() > 0) {
            cnresponse = (SMB2ChangeNotifyResponse) connection.receive().get(0);
        }
        if (cnresponse.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(cnresponse.getHeader().getStatus(), cnresponse.getHeader().getStatusCode(),
                    "Notify failed for " + fileHandle, null);
        }

        return cnresponse.getFileNotifyInfoList();
    }

    // TODO CHeck it is supposed to delete on close, but should we close the handle in this method?
    public void rm()
            throws TransportException, SmbApiException {
        byte[] dispoInfo = FileInformationFactory.getFileDispositionInfo(true);
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2SetInfoRequest si_req = new SMB2SetInfoRequest(
                connection.getNegotiatedDialect(), session.getSessionId(), treeConnect.getTreeId(),
                SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_FILE, getFileId(), FileInformationClass
                .FileDispositionInformation,
                null, dispoInfo);
        connection.send(si_req);

        SMB2SetInfoResponse receive = (SMB2SetInfoResponse) connection.receive().get(0);
        if (receive.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(receive.getHeader().getStatus(), receive.getHeader().getStatusCode(),
                    "Tree connect request failed for " + this, null);
        }
    }

    public static void rm(SMBTreeConnect treeConnect, String path)
            throws TransportException, SmbApiException {
        logger.info("rm {}", path);
        EnumSet<SMB2DirectoryAccessMask> accessMask =
                EnumSet.of(SMB2DirectoryAccessMask.DELETE);
        SMB2CreateRequest smb2CreateRequest =
                openFileRequest(treeConnect, path, SMB2DirectoryAccessMask.DELETE.getValue(), null, null,
                        SMB2CreateDisposition.FILE_OPEN, EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));

        deleteCommon(treeConnect, path, smb2CreateRequest);
    }

    public static void rmdir(SMBTreeConnect treeConnect, String path, boolean recursive)
            throws TransportException, SmbApiException {
        logger.info("rmdir {},{}", path, recursive);

        //TODO Even with DELETE_CHILD permission, receiving error, so doing the recursive way for now.
        //if (recursive) accessMask.add(SMB2DirectoryAccessMask.FILE_DELETE_CHILD);
        if (recursive) {
            List<FileInfo> list = list(treeConnect, path);
            for (FileInfo fi : list) {
                if (!EnumWithValue.EnumUtils.isSet(fi.getFileAttributes(), FileAttributes.FILE_ATTRIBUTE_DIRECTORY)) {
                    rm(treeConnect, PathUtils.get(path, fi.getFileName()));
                } else {
                    rmdir(treeConnect, PathUtils.get(path, fi.getFileName()), recursive);
                }
            }
            rmdir(treeConnect, path, false);
        } else {

            SMB2CreateRequest smb2CreateRequest =
                    openFileRequest(treeConnect, path,
                            SMB2DirectoryAccessMask.DELETE.getValue(),
                            EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE,
                                    SMB2ShareAccess.FILE_SHARE_READ),
                            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY),
                            SMB2CreateDisposition.FILE_OPEN,
                            null
                    );

            deleteCommon(treeConnect, path, smb2CreateRequest);
        }
    }

    public static void mkdir(SMBTreeConnect treeConnect, String path)
            throws TransportException, SmbApiException {
        logger.info("mkdir {}", path);

        SMB2File fileHandle = openDirectory(treeConnect, path,
                EnumSet.of(SMB2DirectoryAccessMask.FILE_LIST_DIRECTORY, SMB2DirectoryAccessMask.FILE_ADD_SUBDIRECTORY),
                EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE, SMB2ShareAccess
                        .FILE_SHARE_READ),
                SMB2CreateDisposition.FILE_CREATE,
                EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));

        fileHandle.close();

    }

    public static boolean fileExists(SMBTreeConnect treeConnect, String path)
            throws SmbApiException, TransportException {
        return exists(treeConnect, path, EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));
    }

    public static boolean folderExists(SMBTreeConnect treeConnect, String path)
            throws SmbApiException, TransportException {
        return exists(treeConnect, path, EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));
    }

    /**
     * @return The SecurityDescriptor(MS-DTYP 2.4.6 SECURITY_DESCRIPTOR) for the Given Path
     * @throws SmbApiException
     * @throws TransportException
     */
    public static SecurityDescriptor getSecurityInfo(
            SMBTreeConnect treeConnect, String path, EnumSet<SecurityInformation> securityInfo)
            throws SmbApiException, TransportException {

        byte[] outputBuffer = queryInfoCommon(treeConnect, path,
                SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_SECURITY, securityInfo, null);
        SecurityDescriptor sd = new SecurityDescriptor();
        try {
            sd.read(new SMBBuffer(outputBuffer));
        } catch (Buffer.BufferException e) {
            throw new TransportException(e);
        }
        return sd;
    }

    /**
     * @return The FileInformation for the Given Path
     * @throws SmbApiException
     * @throws TransportException
     */
    public static FileInfo getFileInformation(
            SMBTreeConnect treeConnect, String path)
            throws SmbApiException, TransportException {

        byte[] outputBuffer = queryInfoCommon(treeConnect, path,
                SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_FILE, null,
                FileInformationClass.FileAllInformation);

        try {
            return FileInformationFactory.parseFileAllInformation(
                    new Buffer.PlainBuffer(outputBuffer, Endian.LE));
        } catch (Buffer.BufferException e) {
            throw new TransportException(e);
        }
    }

    private static byte[] queryInfoCommon(SMBTreeConnect treeConnect, String path,
                                          SMB2QueryInfoRequest.SMB2QueryInfoType infoType,
                                          EnumSet<SecurityInformation> securityInfo,
                                          FileInformationClass fileInformationClass)
            throws SmbApiException, TransportException {

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2File fileHandle = null;
        try {
            fileHandle = open(
                    treeConnect, path,
                    EnumWithValue.EnumUtils.toLong(EnumSet.of(SMB2DirectoryAccessMask.GENERIC_READ)),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                    EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE,
                            SMB2ShareAccess.FILE_SHARE_READ),
                    SMB2CreateDisposition.FILE_OPEN,
                    null);
            SMB2QueryInfoRequest qreq = new SMB2QueryInfoRequest(
                    connection.getNegotiatedDialect(), session.getSessionId(), treeConnect.getTreeId(),
                    fileHandle.getFileId(), infoType,
                    fileInformationClass, null, null, securityInfo);
            connection.send(qreq);
            SMB2QueryInfoResponse qresp = (SMB2QueryInfoResponse) connection.receive().get(0);
            if (qresp.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
                throw new SmbApiException(qresp.getHeader().getStatus(), qresp.getHeader().getStatusCode(),
                        "QUERY_INFO failed for " + path, null);
            }
            return qresp.getOutputBuffer();
        } finally {
            if (fileHandle != null) fileHandle.closeSilently();
        }
    }

    private static boolean exists(SMBTreeConnect treeConnect, String path, EnumSet<SMB2CreateOptions> createOptions)
            throws TransportException, SmbApiException {
        logger.info("folderExists {}", path);

        SMB2File fileHandle = null;
        try {
            fileHandle = openDirectory(treeConnect, path,
                    EnumSet.of(SMB2DirectoryAccessMask.FILE_READ_ATTRIBUTES),
                    EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE,
                            SMB2ShareAccess.FILE_SHARE_READ),
                    SMB2CreateDisposition.FILE_OPEN,
                    createOptions);
            return true;
        } catch (SmbApiException sae) {
            if (sae.getStatusCode() == SMB2StatusCode.STATUS_OBJECT_NAME_NOT_FOUND) {
                return false;
            } else {
                throw sae;
            }
        } finally {
            if (fileHandle != null) fileHandle.closeSilently();
        }
    }


    private static void deleteCommon(SMBTreeConnect treeConnect, String path, SMB2CreateRequest smb2CreateRequest)
            throws TransportException, SmbApiException {

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        // Use Compounding
        byte[] fileIdBytes = new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte)
                0xFF, (byte) 0xFF, (byte) 0xFF};
        SMB2FileId fileId = new SMB2FileId(fileIdBytes, fileIdBytes);
        byte[] dispoInfo = FileInformationFactory.getFileDispositionInfo(true);
        SMB2SetInfoRequest si_req = new SMB2SetInfoRequest(
                connection.getNegotiatedDialect(), session.getSessionId(), treeConnect.getTreeId(),
                SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_FILE, fileId, FileInformationClass
                .FileDispositionInformation,
                null, dispoInfo);
        SMB2Close closeReq = new SMB2Close(connection.getNegotiatedDialect(), fileId,
                session.getSessionId(), treeConnect.getTreeId());

        connection.sendRelatedRequests(true, smb2CreateRequest, si_req, closeReq);
        List<SMB2Packet> smb2Packets = connection.receive();
        //logger.debug("# of response packets " + smb2Packets.size());

        for (SMB2Packet packet : smb2Packets) {
            if (packet.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
                throw new SmbApiException(packet.getHeader().getStatus(), packet.getHeader().getStatusCode(),
                        packet.getHeader().getMessage() + " failed for path " + path, null);
            }
        }
    }


    public static SMB2File openFile(
            SMBTreeConnect treeConnect, String path, EnumSet<SMB2DirectoryAccessMask> accessMask,
            SMB2CreateDisposition createDisposition)
            throws TransportException, SmbApiException {
        logger.info("OpenFile {},{},{}", path, accessMask, createDisposition);

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        EnumSet<SMB2ShareAccess> shareAccess = EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ);
        EnumSet<SMB2CreateOptions> createOptions = EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE);
        SMB2CreateRequest cr = openFileRequest(treeConnect, path, EnumWithValue.EnumUtils.toLong(accessMask),
                EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ), null, createDisposition,
                EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));
        connection.send(cr);
        SMB2CreateResponse cresponse = (SMB2CreateResponse) connection.receive().get(0);
        if (cresponse.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(cresponse.getHeader().getStatus(), cresponse.getHeader().getStatusCode(),
                    "Create failed for " + path, null);
        }
        return new SMB2File(
                cresponse.getFileId(), treeConnect, path, EnumWithValue.EnumUtils.toLong(accessMask), shareAccess,
                createOptions, null, createDisposition);
    }


    public static SMB2File openDirectory(SMBTreeConnect treeConnect, String path,
                                         EnumSet<SMB2DirectoryAccessMask> accessMask,
                                         EnumSet<SMB2ShareAccess> shareAccess,
                                         SMB2CreateDisposition createDisposition,
                                         EnumSet<SMB2CreateOptions> createOptions)
            throws TransportException, SmbApiException {
        logger.info("OpenDirectory {},{},{},{},{}", path, accessMask, shareAccess, createDisposition, createOptions);

        return open(treeConnect, path,
                EnumWithValue.EnumUtils.toLong(accessMask),
                EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY),
                shareAccess,
                createDisposition,
                createOptions);
    }

    public static SMB2File open(
            SMBTreeConnect treeConnect, String path, long accessMask,
            EnumSet<FileAttributes> fileAttributes, EnumSet<SMB2ShareAccess> shareAccess,
            SMB2CreateDisposition createDisposition, EnumSet<SMB2CreateOptions> createOptions)
            throws TransportException, SmbApiException {
        logger.info("open {},{}", path);

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();
        SMB2CreateRequest cr = openFileRequest(
                treeConnect, path, accessMask, shareAccess, fileAttributes, createDisposition, createOptions);
        connection.send(cr);
        SMB2CreateResponse cresponse = (SMB2CreateResponse) connection.receive().get(0);
        // TODO handle status pending
        if (cresponse.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(cresponse.getHeader().getStatus(), cresponse.getHeader().getStatusCode(),
                    "Create failed for " + path, null);
        }

        return new SMB2File(
                cresponse.getFileId(), treeConnect, path, accessMask, shareAccess,
                createOptions, fileAttributes, createDisposition);
    }

    private static SMB2CreateRequest openFileRequest(
            SMBTreeConnect treeConnect, String path,
            long accessMask,
            EnumSet<SMB2ShareAccess> shareAccess,
            EnumSet<FileAttributes> fileAttributes,
            SMB2CreateDisposition createDisposition,
            EnumSet<SMB2CreateOptions> createOptions) {

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2CreateRequest cr = new SMB2CreateRequest(
                connection.getNegotiatedDialect(),
                session.getSessionId(), treeConnect.getTreeId(),
                accessMask,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions, path);
        cr.getHeader().setCreditRequest(256);
        cr.getHeader().setCreditCost(1);

        return cr;
    }

    public void close() throws TransportException, SmbApiException {
        Connection connection = treeConnect.getSession().getConnection();
        SMB2Close closeReq = new SMB2Close(
                connection.getNegotiatedDialect(), fileId,
                treeConnect.getSession().getSessionId(), treeConnect.getTreeId());
        connection.send(closeReq);
        SMB2Close closeResp = (SMB2Close) connection.receive().get(0);
        if (closeResp.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(closeResp.getHeader().getStatus(), closeResp.getHeader().getStatusCode(),
                    "Close failed for " + fileId, null);
        }
    }


    public void closeSilently() {
        try {
            close();
        } catch (Exception e) {
            logger.warn("File close failed for {},{},{}", fileName, treeConnect, fileId, e);
        }
    }

    @Override
    public String toString() {
        return "SMB2File{" +
                "fileId=" + fileId +
                ", fileName='" + fileName + '\'' +
                '}';
    }
}
