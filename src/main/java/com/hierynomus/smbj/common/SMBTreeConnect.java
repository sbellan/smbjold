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
package com.hierynomus.smbj.common;

import com.hierynomus.smbj.api.SmbApiException;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.smb2.SMB2Dialect;
import com.hierynomus.smbj.smb2.SMB2StatusCode;
import com.hierynomus.smbj.smb2.messages.SMB2TreeDisconnect;
import com.hierynomus.smbj.smb2.messages.SMB2TreeDisconnectResponse;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * MS-SMB2 3.2.1.4 Per Tree Connect
 */
public class SMBTreeConnect {

    private static final Logger logger = LoggerFactory.getLogger(SMBTreeConnect.class);

    String shareName;
    long treeId;
    Session session;

    public SMBTreeConnect(String shareName, long treeId, Session session) {
        this.shareName = shareName;
        this.treeId = treeId;
        this.session = session;
    }

    public String getShareName() {
        return shareName;
    }

    public long getTreeId() {
        return treeId;
    }

    public Session getSession() {
        return session;
    }

    public void disconnect() throws TransportException, SmbApiException {
        SMB2TreeDisconnect td = new SMB2TreeDisconnect(session.getConnection().getNegotiatedDialect());
        td.getHeader().setSessionId(session.getSessionId());
        td.getHeader().setTreeId(treeId);
        session.getConnection().send(td);
        SMB2TreeDisconnectResponse disconnectResponse =
                (SMB2TreeDisconnectResponse) session.getConnection().receive().get(0);
        if (disconnectResponse.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(disconnectResponse.getHeader().getStatus(), disconnectResponse.getHeader().getStatusCode(),
                    "Tree disconnect failed for " + shareName + "/" + treeId, null);
        }
    }

    public void closeSilently() {
        try {
            disconnect();
        } catch (Exception ignore) {
            logger.warn("Exception while Tree disconnect", ignore);
        }

    }
}
