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
package com.hierynomus.smbj.session;

import com.hierynomus.smbj.api.SmbApiException;
import com.hierynomus.smbj.common.SMBTreeConnect;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.smb2.SMB2Dialect;
import com.hierynomus.smbj.smb2.SMB2StatusCode;
import com.hierynomus.smbj.smb2.messages.SMB2Logoff;
import com.hierynomus.smbj.smb2.messages.SMB2LogoffResponse;
import com.hierynomus.smbj.smb2.messages.SMB2TreeConnectRequest;
import com.hierynomus.smbj.smb2.messages.SMB2TreeConnectResponse;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * MS-SMB2.pdf 3.2.1.3 Per Session
 *
 * A Session
 */
public class Session {

    private static final Logger logger = LoggerFactory.getLogger(Session.class);

    Connection connection;
    long sessionId;

    public Session(Connection connection, long sessionId) {
        this.connection = connection;
        this.sessionId = sessionId;
    }

    public long getSessionId() {
        return sessionId;
    }

    public void setSessionId(long sessionId) {
        this.sessionId = sessionId;
    }

    public Connection getConnection() {
        return connection;
    }

    public SMBTreeConnect treeConnect(String host, String smbPath) throws TransportException, SmbApiException {
        String sharePath = "\\\\" + host + ((smbPath.charAt(0) == '\\') ? "" : '\\') + smbPath;
        SMB2TreeConnectRequest tr = new SMB2TreeConnectRequest(connection.getNegotiatedDialect(), sharePath);
        tr.getHeader().setSessionId(sessionId);
        tr.getHeader().setCreditRequest(1);
        connection.send(tr);

        SMB2TreeConnectResponse receive = (SMB2TreeConnectResponse) connection.receive().get(0);
        if (receive.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(receive.getHeader().getStatus(), receive.getHeader().getStatusCode(),
                    "Tree connect request failed for " + sharePath, null);
        }
        SMBTreeConnect stc = new SMBTreeConnect(smbPath, receive.getHeader().getTreeId(), this);
        return stc;
    }

    public void logoff() throws TransportException, SmbApiException {
        // Logoff
        SMB2Logoff logOff = new SMB2Logoff(getConnection().getNegotiatedDialect());
        logOff.getHeader().setSessionId(sessionId);
        getConnection().send(logOff);
        SMB2LogoffResponse logOffResponse = (SMB2LogoffResponse) getConnection().receive().get(0);
        if (logOffResponse.getHeader().getStatus() != SMB2StatusCode.STATUS_SUCCESS) {
            throw new SmbApiException(logOffResponse.getHeader().getStatus(), logOffResponse.getHeader().getStatusCode(),
                    "LogOff failed for " + sessionId, null);
        }

    }

    public void closeSilently() {
        try {
            logoff();
        } catch (Exception ignore) {
            logger.warn("Exception while logoff", ignore);
        }
    }
}
