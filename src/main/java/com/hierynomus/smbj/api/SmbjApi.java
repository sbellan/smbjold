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
package com.hierynomus.smbj.api;

import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.msfscc.fileinformation.FileInfo;
import com.hierynomus.msfscc.fileinformation.FileInformationFactory;
import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.smbj.Config;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.smb2.SMB2CompletionFilter;
import com.hierynomus.smbj.smb2.SMB2CreateDisposition;
import com.hierynomus.smbj.smb2.SMB2CreateOptions;
import com.hierynomus.smbj.smb2.SMB2Dialect;
import com.hierynomus.smbj.smb2.SMB2DirectoryAccessMask;
import com.hierynomus.smbj.smb2.SMB2FileId;
import com.hierynomus.smbj.smb2.SMB2Packet;
import com.hierynomus.smbj.smb2.SMB2ShareAccess;
import com.hierynomus.smbj.smb2.SMB2StatusCode;
import com.hierynomus.smbj.smb2.messages.SMB2ChangeNotifyRequest;
import com.hierynomus.smbj.smb2.messages.SMB2ChangeNotifyResponse;
import com.hierynomus.smbj.smb2.messages.SMB2Close;
import com.hierynomus.smbj.smb2.messages.SMB2CreateRequest;
import com.hierynomus.smbj.smb2.messages.SMB2CreateResponse;
import com.hierynomus.smbj.smb2.messages.SMB2Logoff;
import com.hierynomus.smbj.smb2.messages.SMB2LogoffResponse;
import com.hierynomus.smbj.smb2.messages.SMB2QueryDirectoryRequest;
import com.hierynomus.smbj.smb2.messages.SMB2QueryDirectoryResponse;
import com.hierynomus.smbj.smb2.messages.SMB2QueryInfoRequest;
import com.hierynomus.smbj.smb2.messages.SMB2QueryInfoResponse;
import com.hierynomus.smbj.smb2.messages.SMB2ReadRequest;
import com.hierynomus.smbj.smb2.messages.SMB2ReadResponse;
import com.hierynomus.smbj.smb2.messages.SMB2SetInfoRequest;
import com.hierynomus.smbj.smb2.messages.SMB2SetInfoResponse;
import com.hierynomus.smbj.smb2.messages.SMB2TreeConnectRequest;
import com.hierynomus.smbj.smb2.messages.SMB2TreeConnectResponse;
import com.hierynomus.smbj.smb2.messages.SMB2TreeDisconnect;
import com.hierynomus.smbj.smb2.messages.SMB2TreeDisconnectResponse;
import com.hierynomus.smbj.smb2.messages.SMB2WriteRequest;
import com.hierynomus.smbj.smb2.messages.SMB2WriteResponse;
import com.hierynomus.smbj.transport.TransportException;
import com.hierynomus.utils.PathUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.EnumSet;
import java.util.List;

/**
 * High-level API for basic use cases
 * <p>
 * All of the API's assume that the connection, session id and tree is managed by caller.
 * <p>
 * Each API is provided in 2 modes, one where the client manages the SMBFileId and the other
 * where the API itself creates and closes the File.
 */
public class SmbjApi {

    private static final Logger logger = LoggerFactory.getLogger(SmbjApi.class);

    static SMB2Dialect DIALECT = SMB2Dialect.SMB_2_1;

    public enum FileOpenMode {
        READ,
        WRITE,
        DELETE
    }

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Connect to a specific share. This is a wrapper for connect/create session/tree connect
     *
     * @param host
     * @param user
     * @param password
     * @param domain
     * @param sharePath
     * @return
     * @throws IOException
     * @throws SmbApiException
     */
    public static ShareConnectionSync connect(
            Config smbConfig, String host, String user, String password, String domain, String sharePath)
            throws IOException, SmbApiException {
        logger.info("Connect {},{},{},{}", host, user, domain, sharePath);
        SMB2Dialect dialect = SMB2Dialect.SMB_2_1;
        SMBClient client = new SMBClient(smbConfig);
        //String workstation = "SMBJ-" + UUID.randomUUID().toString();
        Connection connection = client.connect(host);
        AuthenticationContext ac = new AuthenticationContext(
                user,
                password == null ? new char[0] : password.toCharArray(),
                domain);
        Session session = connection.authenticate(ac);

        sharePath = sharePath.replace("/", "\\");
        if (sharePath.charAt(0) != '\\') sharePath = "\\" + sharePath;
        long treeId = treeConnect(session, connection, String.format("\\\\%s%s", host, sharePath));

        logger.info("Successfully connected {},{}", session.getSessionId(), treeId);
        return new ShareConnectionSync(smbConfig, connection, session, treeId);
    }

    public static void disconnect(ShareConnectionSync scs) throws TransportException {
        logger.info("Disconnect {},{}", scs.getSession().getSessionId(), scs.getTreeId());
        SMB2TreeDisconnect td = new SMB2TreeDisconnect(SMB2Dialect.SMB_2_1);
        td.getHeader().setSessionId(scs.getSession().getSessionId());
        td.getHeader().setTreeId(scs.getTreeId());
        scs.getConnection().send(td);
        SMB2TreeDisconnectResponse disconnectResponse =
                (SMB2TreeDisconnectResponse) scs.getConnection().receive().get(0);
        if (disconnectResponse.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            logger.warn("Tree disconnect failed with {}", disconnectResponse.getHeader().getStatus());
        }
        // Logoff
        SMB2Logoff logOff = new SMB2Logoff(SMB2Dialect.SMB_2_1);
        logOff.getHeader().setSessionId(scs.getSession().getSessionId());
        scs.getConnection().send(logOff);
        SMB2LogoffResponse logOffResponse = (SMB2LogoffResponse) scs.getConnection().receive().get(0);
        if (logOffResponse.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            logger.warn("Logoff failed with {}", logOffResponse.getHeader().getStatus());
        }

    }

    /**
     * @param scs  Connection Info
     * @param path Path relative to the connect root.
     *             Leave null or empty to list the root directory
     * @return List of FileInfo
     * @throws SmbApiException
     * @throws TransportException
     */
    public static List<FileInfo> list(ShareConnectionSync scs, String path)
            throws SmbApiException, TransportException {
        logger.info("List {}", path);

        SMB2FileId fileId = openDirectory(scs, path,
                EnumSet.of(SMB2DirectoryAccessMask.FILE_LIST_DIRECTORY, SMB2DirectoryAccessMask.FILE_READ_ATTRIBUTES),
                EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE, SMB2ShareAccess
                        .FILE_SHARE_READ),
                SMB2CreateDisposition.FILE_OPEN,
                EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));

        try {
            return list(scs, fileId);
        } finally {
            if (fileId != null) {
                SMB2Close closeReq = new SMB2Close(DIALECT, fileId, scs.getSession().getSessionId(), scs.getTreeId());
                scs.getConnection().send(closeReq);
                SMB2Close closeResp = (SMB2Close) scs.getConnection().receive().get(0);
            }
        }
    }

    /**
     * List on a already open FileId
     */
    public static List<FileInfo> list(ShareConnectionSync scs, SMB2FileId fileId)
            throws TransportException, SmbApiException {
        logger.info("List {}", ByteArrayUtils.printHex(fileId.getPersistentHandle()));
        // Query Directory Request
        SMB2QueryDirectoryRequest qdr = new SMB2QueryDirectoryRequest(DIALECT,
                scs.getSession().getSessionId(), scs.getTreeId(),
                fileId, FileInformationClass.FileIdBothDirectoryInformation, // FileInformationClass
                // .FileDirectoryInformation,
                EnumSet.of(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.SMB2_REOPEN),
                0, null);
        scs.getConnection().send(qdr);
        SMB2QueryDirectoryResponse qdresp = (SMB2QueryDirectoryResponse) scs.getConnection().receive().get(0);
        if (qdresp.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(qdresp.getHeader().getStatus(), qdresp.getHeader().getStatusCode(),
                    "Query directory failed for " + fileId, null);
        }
        byte[] outputBuffer = qdresp.getOutputBuffer();

        try {
            return FileInformationFactory.parseFileInformationList(
                    outputBuffer, qdresp.getOutputBufferOffset(), qdresp.getOutBufferLength(), FileInformationClass.FileAllInformation);
        } catch (Buffer.BufferException e) {
            throw new TransportException(e);
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
    public static List<SMB2ChangeNotifyResponse.FileNotifyInfo> notify(ShareConnectionSync scs, SMB2FileId fileId)
            throws TransportException, SmbApiException {

        int bufferLength = 64 * 1024;

        SMB2ChangeNotifyRequest cnr = new SMB2ChangeNotifyRequest(
                SMB2Dialect.SMB_2_1,
                scs.getSession().getSessionId(), scs.getTreeId(),
                fileId,
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
        scs.getConnection().send(cnr);

        SMB2ChangeNotifyResponse cnresponse = (SMB2ChangeNotifyResponse) scs.getConnection().receive().get(0);
        // Wait till we get a permanent response
        while (cnresponse.getHeader().getStatus() == SMB2StatusCode.STATUS_PENDING
                && cnresponse.getHeader().getAsyncId() > 0) {
            cnresponse = (SMB2ChangeNotifyResponse) scs.getConnection().receive().get(0);
        }
        if (cnresponse.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(cnresponse.getHeader().getStatus(), cnresponse.getHeader().getStatusCode(),
                    "Notify failed for " + fileId, null);
        }

        return cnresponse.getFileNotifyInfoList();
    }

    /**
     * Write the given input stream to the given path
     *
     * @param scs
     * @param path
     * @param overWrite if true, overwrite if a file with same name exists.
     * @param srcStream
     * @throws SmbApiException
     * @throws IOException
     */
    public static void write(ShareConnectionSync scs, String path, boolean overWrite, InputStream srcStream)
            throws SmbApiException, IOException {
        logger.info("Write {},{}", path, overWrite);
        SMB2CreateDisposition createDisposition = SMB2CreateDisposition.FILE_OVERWRITE_IF;
        if (!overWrite) createDisposition = SMB2CreateDisposition.FILE_CREATE;
        SMB2FileId fileId = openFile(scs, path, FileOpenMode.WRITE, createDisposition);

        try {
            byte[] buf = new byte[8192];
            int numRead = -1;
            int offset = 0;
            while ((numRead = srcStream.read(buf)) != -1) {
                SMB2WriteRequest wreq = new SMB2WriteRequest(DIALECT, fileId,
                        scs.getSession().getSessionId(), scs.getTreeId(),
                        buf, numRead, offset, 0);
                scs.getConnection().send(wreq);
                SMB2WriteResponse wresp = (SMB2WriteResponse) scs.getConnection().receive().get(0);
                if (wresp.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
                    throw new SmbApiException(wresp.getHeader().getStatus(), wresp.getHeader().getStatusCode(),
                            "Write failed for " + path, null);
                }
                offset += numRead;
            }
        } finally {
            if (fileId != null) {
                close(scs, fileId);
            }
        }
    }

    /**
     * Read a file and write the data to the given output stream
     *
     * @param scs
     * @param path
     * @param destStream
     * @throws SmbApiException
     * @throws IOException
     */
    public static void read(ShareConnectionSync scs, String path, OutputStream destStream)
            throws SmbApiException, IOException {
        logger.info("Read {}", path);
        SMB2FileId fileId = openFile(scs, path, FileOpenMode.READ, SMB2CreateDisposition.FILE_OPEN);

        try {
            long offset = 0;
            SMB2ReadRequest rreq = new SMB2ReadRequest(DIALECT, fileId, scs.getSession().getSessionId(),
                    scs.getTreeId(), offset);

            scs.getConnection().send(rreq);
            SMB2ReadResponse rresp = (SMB2ReadResponse) scs.getConnection().receive().get(0);
            while (rresp.getHeader().getStatus() == SMB2StatusCode.STATUS_SUCCESS &&
                    rresp.getHeader().getStatus() != SMB2StatusCode.STATUS_END_OF_FILE) {
                destStream.write(rresp.getData());
                offset += rresp.getDataLength();
                rreq = new SMB2ReadRequest(DIALECT, fileId, scs.getSession().getSessionId(), scs.getTreeId(), offset);
                scs.getConnection().send(rreq);
                rresp = (SMB2ReadResponse) scs.getConnection().receive().get(0);
            }

            if (rresp.getHeader().getStatus() != SMB2StatusCode.STATUS_END_OF_FILE) {
                throw new SmbApiException(rresp.getHeader().getStatus(), rresp.getHeader().getStatusCode(),
                        "Read failed for " + path, null);
            }

        } finally {
            if (fileId != null) {
                close(scs, fileId);
            }
        }
    }

    public static SMB2FileId openFile(ShareConnectionSync scs, String path, FileOpenMode mode, SMB2CreateDisposition
            createDisposition)
            throws TransportException, SmbApiException {
        logger.info("OpenFile {},{},{}", path, mode, createDisposition);
        EnumSet<SMB2DirectoryAccessMask> accessMask =
                EnumSet.of(mapModeToAccessMask(mode));

        SMB2CreateRequest cr = openFileRequest(scs, path, mode, accessMask, null, createDisposition,
                EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));
        scs.getConnection().send(cr);
        SMB2CreateResponse cresponse = (SMB2CreateResponse) scs.getConnection().receive().get(0);
        if (cresponse.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(cresponse.getHeader().getStatus(), cresponse.getHeader().getStatusCode(),
                    "Create failed for " + path, null);
        }
        return cresponse.getFileId();
    }

    public static SMB2FileId openDirectory(ShareConnectionSync scs, String path,
                                           EnumSet<SMB2DirectoryAccessMask> accessMask,
                                           EnumSet<SMB2ShareAccess> shareAccess,
                                           SMB2CreateDisposition createDisposition,
                                           EnumSet<SMB2CreateOptions> createOptions)
            throws TransportException, SmbApiException {
        logger.info("OpenDirectory {},{},{},{},{}", path, accessMask, shareAccess, createDisposition, createOptions);

        return open(scs, path,
                EnumWithValue.EnumUtils.toLong(accessMask),
                EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY),
                shareAccess,
                createDisposition,
                createOptions);
    }

    public static SMB2FileId open(
            ShareConnectionSync scs, String path, long accessMask,
            EnumSet<FileAttributes> fileAttributes, EnumSet<SMB2ShareAccess> shareAcess,
            SMB2CreateDisposition createDisposition, EnumSet<SMB2CreateOptions> createOptions)
            throws TransportException, SmbApiException {
        logger.info("open {},{}", path);

        SMB2CreateRequest cr = new SMB2CreateRequest(
                DIALECT, scs.getConfig(),
                scs.getSession().getSessionId(), scs.getTreeId(),
                accessMask,
                fileAttributes,
                shareAcess,
                createDisposition,
                createOptions, path);
        scs.getConnection().send(cr);
        SMB2CreateResponse cresponse = (SMB2CreateResponse) scs.getConnection().receive().get(0);
        if (cresponse.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(cresponse.getHeader().getStatus(), cresponse.getHeader().getStatusCode(),
                    "Create failed for " + path, null);
        }

        return cresponse.getFileId();
    }

    public static void close(ShareConnectionSync scs, SMB2FileId fileId)
            throws TransportException, SmbApiException {
        logger.info("Close {}", fileId);
        SMB2Close closeReq = new SMB2Close(DIALECT, fileId, scs.getSession().getSessionId(), scs.getTreeId());
        scs.getConnection().send(closeReq);
        SMB2Close closeResp = (SMB2Close) scs.getConnection().receive().get(0);
        if (closeResp.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(closeResp.getHeader().getStatus(), closeResp.getHeader().getStatusCode(),
                    "Close failed for " + fileId, null);
        }
    }

    public static void rm(ShareConnectionSync scs, String path)
            throws TransportException, SmbApiException {
        logger.info("rm {}", path);
        EnumSet<SMB2DirectoryAccessMask> accessMask =
                EnumSet.of(mapModeToAccessMask(FileOpenMode.DELETE));
        SMB2CreateRequest smb2CreateRequest =
                openFileRequest(scs, path, FileOpenMode.DELETE, accessMask, null, SMB2CreateDisposition.FILE_OPEN,
                        EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));

        deleteCommon(scs, path, smb2CreateRequest);
    }

    public static void mkdir(ShareConnectionSync scs, String path)
            throws TransportException, SmbApiException {
        logger.info("mkdir {}", path);

        SMB2FileId fileId = openDirectory(scs, path,
                EnumSet.of(SMB2DirectoryAccessMask.FILE_LIST_DIRECTORY, SMB2DirectoryAccessMask.FILE_ADD_SUBDIRECTORY),
                EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE, SMB2ShareAccess
                        .FILE_SHARE_READ),
                SMB2CreateDisposition.FILE_CREATE,
                EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));

        close(scs, fileId);

    }

    public static boolean fileExists(ShareConnectionSync scs, String path)
            throws SmbApiException, TransportException {
        return exists(scs, path, EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));
    }

    public static boolean folderExists(ShareConnectionSync scs, String path)
            throws SmbApiException, TransportException {
        return exists(scs, path, EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));
    }

    /**
     * @return The SecurityDescriptor(MS-DTYP 2.4.6 SECURITY_DESCRIPTOR) for the Given Path
     * @throws SmbApiException
     * @throws TransportException
     */
    public static SecurityDescriptor getSecurityInfo(
            ShareConnectionSync scs, String path, EnumSet<SecurityInformation> securityInfo)
            throws SmbApiException, TransportException {

        byte[] outputBuffer = queryInfoCommon(scs, path,
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
            ShareConnectionSync scs, String path)
            throws SmbApiException, TransportException {

        byte[] outputBuffer = queryInfoCommon(scs, path,
                SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_FILE, null,
                FileInformationClass.FileAllInformation);

        try {
            return FileInformationFactory.parseFileAllInformation(
                    new Buffer.PlainBuffer(outputBuffer, Endian.LE));
        } catch (Buffer.BufferException e) {
            throw new TransportException(e);
        }
    }

    private static byte[] queryInfoCommon(ShareConnectionSync scs, String path,
                                          SMB2QueryInfoRequest.SMB2QueryInfoType infoType,
                                          EnumSet<SecurityInformation> securityInfo,
                                          FileInformationClass fileInformationClass
    )
            throws SmbApiException, TransportException {

        SMB2FileId fileId = null;
        try {
            fileId = open(
                    scs, path,
                    EnumWithValue.EnumUtils.toLong(EnumSet.of(SMB2DirectoryAccessMask.GENERIC_READ)),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                    EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE,
                            SMB2ShareAccess.FILE_SHARE_READ),
                    SMB2CreateDisposition.FILE_OPEN,
                    null);
            SMB2QueryInfoRequest qreq = new SMB2QueryInfoRequest(
                    DIALECT, scs.getSession().getSessionId(), scs.getTreeId(),
                    fileId, infoType,
                    fileInformationClass, null, null, securityInfo);
            scs.getConnection().send(qreq);
            SMB2QueryInfoResponse qresp = (SMB2QueryInfoResponse) scs.getConnection().receive().get(0);
            if (qresp.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
                throw new SmbApiException(qresp.getHeader().getStatus(), qresp.getHeader().getStatusCode(),
                        "QUERY_INFO failed for " + path, null);
            }
            return qresp.getOutputBuffer();
        } finally {
            if (fileId != null) close(scs, fileId);
        }
    }

    private static boolean exists(ShareConnectionSync scs, String path, EnumSet<SMB2CreateOptions> createOptions)
            throws TransportException, SmbApiException {
        logger.info("folderExists {}", path);

        SMB2FileId fileId = null;
        try {
            fileId = openDirectory(scs, path,
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
            if (fileId != null) close(scs, fileId);
        }
    }

    public static void rmdir(ShareConnectionSync scs, String path, boolean recursive)
            throws TransportException, SmbApiException {
        logger.info("rmdir {},{}", path, recursive);

        //TODO Even with DELETE_CHILD permission, receiving error, so doing the recursive way for now.
        //if (recursive) accessMask.add(SMB2DirectoryAccessMask.FILE_DELETE_CHILD);
        if (recursive) {
            List<FileInfo> list = list(scs, path);
            for (FileInfo fi : list) {
                if (!EnumWithValue.EnumUtils.isSet(fi.getFileAttributes(), FileAttributes.FILE_ATTRIBUTE_DIRECTORY)) {
                    rm(scs, PathUtils.get(path, fi.getFileName()));
                } else {
                    rmdir(scs, PathUtils.get(path, fi.getFileName()), recursive);
                }
            }
            rmdir(scs, path, false);
        } else {

            EnumSet<SMB2DirectoryAccessMask> accessMask =
                    EnumSet.of(mapModeToAccessMask(FileOpenMode.DELETE));

            SMB2CreateRequest smb2CreateRequest =
                    openFileRequest(scs, path, FileOpenMode.DELETE,
                            accessMask,
                            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY),
                            SMB2CreateDisposition.FILE_OPEN,
                            null
                    );

            deleteCommon(scs, path, smb2CreateRequest);
        }

    }

    public static void delete(ShareConnectionSync scs, SMB2FileId smb2FileId)
            throws TransportException, SmbApiException {
        byte[] dispoInfo = FileInformationFactory.getFileDispositionInfo(true);
        SMB2SetInfoRequest si_req = new SMB2SetInfoRequest(
                DIALECT, scs.getSession().getSessionId(), scs.getTreeId(),
                SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_FILE, smb2FileId, FileInformationClass
                .FileDispositionInformation,
                null, dispoInfo);
        scs.getConnection().send(si_req);

        SMB2SetInfoResponse receive = (SMB2SetInfoResponse) scs.getConnection().receive().get(0);
        if (receive.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(receive.getHeader().getStatus(), receive.getHeader().getStatusCode(),
                    "Tree connect request failed for " + smb2FileId, null);
        }
    }

    // Private

    private static void deleteCommon(ShareConnectionSync scs, String path, SMB2CreateRequest smb2CreateRequest)
            throws TransportException, SmbApiException {
        // Use Compounding
        byte[] fileIdBytes = new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte)
                0xFF, (byte) 0xFF, (byte) 0xFF};
        SMB2FileId fileId = new SMB2FileId(fileIdBytes, fileIdBytes);
        byte[] dispoInfo = FileInformationFactory.getFileDispositionInfo(true);
        SMB2SetInfoRequest si_req = new SMB2SetInfoRequest(
                DIALECT, scs.getSession().getSessionId(), scs.getTreeId(),
                SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_FILE, fileId, FileInformationClass
                .FileDispositionInformation,
                null, dispoInfo);
        SMB2Close closeReq = new SMB2Close(DIALECT, fileId, scs.getSession().getSessionId(), scs.getTreeId());

        scs.getConnection().sendRelatedRequests(true, smb2CreateRequest, si_req, closeReq);
        List<SMB2Packet> smb2Packets = scs.getConnection().receive();
        //logger.debug("# of response packets " + smb2Packets.size());

        for (SMB2Packet packet : smb2Packets) {
            if (packet.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
                throw new SmbApiException(packet.getHeader().getStatus(), packet.getHeader().getStatusCode(),
                        packet.getHeader().getMessage() + " failed for path " + path, null);
            }
        }
    }

    private static long treeConnect(Session session, Connection connection, String smbPath)
            throws TransportException, SmbApiException {
        SMB2TreeConnectRequest tr = new SMB2TreeConnectRequest(DIALECT, smbPath);
        tr.getHeader().setSessionId(session.getSessionId());
        tr.getHeader().setCreditRequest(256);
        connection.send(tr);

        SMB2TreeConnectResponse receive = (SMB2TreeConnectResponse) connection.receive().get(0);
        if (receive.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(receive.getHeader().getStatus(), receive.getHeader().getStatusCode(),
                    "Tree connect request failed for " + smbPath, null);
        }
        return receive.getHeader().getTreeId();
    }

    private static EnumSet<SMB2ShareAccess> mapModeToShareAccess(FileOpenMode mode) {
        EnumSet<SMB2ShareAccess> shareAccess = EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ);
        if (mode == FileOpenMode.WRITE) shareAccess = EnumSet.of(SMB2ShareAccess.FILE_SHARE_WRITE);
        if (mode == FileOpenMode.DELETE) shareAccess = EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE);
        return shareAccess;
    }

    private static SMB2DirectoryAccessMask mapModeToAccessMask(FileOpenMode mode) {
        SMB2DirectoryAccessMask accessMask = SMB2DirectoryAccessMask.GENERIC_READ;
        if (mode == FileOpenMode.WRITE) accessMask = SMB2DirectoryAccessMask.GENERIC_WRITE;
        if (mode == FileOpenMode.DELETE) accessMask = SMB2DirectoryAccessMask.DELETE;
        return accessMask;
    }

    private static SMB2CreateRequest openFileRequest(
            ShareConnectionSync scs, String path,
            FileOpenMode mode,
            EnumSet<SMB2DirectoryAccessMask> accessMask,
            EnumSet<FileAttributes> fileAttributes,
            SMB2CreateDisposition createDisposition,
            EnumSet<SMB2CreateOptions> createOptions) {
//        EnumSet<SMB2ShareAccess> shareAccess = mapModeToShareAccess(mode);
        EnumSet<SMB2ShareAccess> shareAccess = EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ);

        SMB2CreateRequest cr = new SMB2CreateRequest(
                DIALECT,
                scs.getConfig(),
                scs.getSession().getSessionId(), scs.getTreeId(),
                EnumWithValue.EnumUtils.toLong(accessMask),
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions, path);

        return cr;
    }
}
