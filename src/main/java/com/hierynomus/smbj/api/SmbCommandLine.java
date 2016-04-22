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

import com.hierynomus.msfscc.fileinformation.FileInfo;
import com.hierynomus.smbj.Config;
import com.hierynomus.smbj.DefaultConfig;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBTreeConnect;
import com.hierynomus.smbj.common.SmbHandler;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.smb2.SMB2CreateDisposition;
import com.hierynomus.smbj.smb2.SMB2CreateOptions;
import com.hierynomus.smbj.smb2.SMB2DirectoryAccessMask;
import com.hierynomus.smbj.smb2.SMB2File;
import com.hierynomus.smbj.smb2.SMB2ShareAccess;
import com.hierynomus.smbj.smb2.messages.SMB2ChangeNotifyResponse;
import com.hierynomus.smbj.transport.TransportException;
import com.hierynomus.utils.PathUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SmbCommandLine {

    private static final Logger logger = LoggerFactory.getLogger(SmbCommandLine.class);

    public static void main(String[] args) throws IOException, SmbApiException {
        SmbCommandLine scl = new SmbCommandLine();
        scl.doMain(args);
    }

    public static class ConnectInfo {
        public String host = null;
        public String domain = null;
        public String user = null;
        public String password = null;
        public String sharePath = null;
    }

    public static ConnectInfo getConnectInfo(String url) throws MalformedURLException, UnsupportedEncodingException {
        URL smbUrl = new URL(null, url, new SmbHandler());

        ConnectInfo ci = new ConnectInfo();
        ci.host = smbUrl.getHost();
        ci.sharePath = PathUtils.fix(smbUrl.getPath());

        Map<String, String> queryParams = splitQuery(smbUrl.getQuery());

        ci.domain = getArg("smbdomain", queryParams);
        ci.user = getArg("smbuser", queryParams);
        ci.password = getArg("smbpassword", queryParams);

        if (smbUrl.getUserInfo() != null) {
            String[] userInfoSplits = smbUrl.getUserInfo().split(":", 1);
            if (userInfoSplits.length >= 1) {
                if (ci.user == null) ci.user = userInfoSplits[0];
                if (userInfoSplits.length >= 2) {
                    if (ci.password == null) ci.password = userInfoSplits[1];
                }
            }
        }
        if (ci.domain == null) ci.domain = "?";

        return ci;
    }

    void doMain(String[] args) throws IOException, SmbApiException {

        SMBTreeConnect smbTreeConnect = null;
        try {
            ConnectInfo ci = getConnectInfo(args[0]);

            logger.info("%s-%s-%s-%s-%s\n", ci.host, ci.domain, ci.user, ci.password, ci.sharePath);

            SMBClient client = new SMBClient();
            Connection connection = client.connect(ci.host);
            AuthenticationContext ac = new AuthenticationContext(
                    ci.user,
                    ci.password == null ? new char[0] : ci.password.toCharArray(),
                    ci.domain);
            Session session = connection.authenticate(ac);
            smbTreeConnect = session.treeConnect(ci.host, ci.sharePath);

            String command = args[1].toLowerCase();
            String path = null;
            switch (command) {
                case "ls":
                case "list":
                    path = args.length > 2 ? args[2] : null;
                    doList(smbTreeConnect, path);
                    break;
                case "notify":
                    path = args.length > 2 ? args[2] : null;
                    doNotify(smbTreeConnect, path);
                    break;
                case "rm":
                    path = args[2];
                    doDelete(smbTreeConnect, path);
                    break;
                case "rmdir":
                    path = args[2];
                    boolean recursive = args.length > 3 ? Boolean.valueOf(args[3]) : false;
                    doDeleteDir(smbTreeConnect, path, recursive);
                    break;
                case "write":
                    String localfile = args[2];
                    String remotePath = args[3];
                    write(smbTreeConnect, localfile, remotePath);
                    break;
                case "read":
                    remotePath = args[2];
                    localfile = args[3];
                    read(smbTreeConnect, remotePath, localfile);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown command " + command);
            }
        } catch (Exception e) {
            System.err.println(e);
            System.err.println("Usage: SmbCommandLine <url> <command>");
            System.err.println("[] - Optional Args, <> - Mandatory Args ");
            System.err.println("commands: ");
            System.err.println("   list [remotepath]");
            System.err.println("   notify [remotepath]");
            System.err.println("   rm <remotepath>");
            System.err.println("   rmdir <remotepath> [recursive]");
            System.err.println("   write <localfile> <remotepath>");
            System.err.println("   write <remotepath> <localfile>");
        } finally {
            if (smbTreeConnect != null) {
                smbTreeConnect.closeSilently();
                smbTreeConnect.getSession().closeSilently();
            }
        }

    }

    private static String getArg(String name, Map<String, String> queryParams) {
        String val = queryParams.get(name.toUpperCase());
        if (val == null) {
            // Check in env
            val = System.getenv(name.toUpperCase());
            if (val == null) val = System.getenv(name);
        }
        return val;
    }

    public static Map<String, String> splitQuery(String query) throws UnsupportedEncodingException {
        if (query == null) return new HashMap<>();
        Map<String, String> query_pairs = new HashMap<String, String>();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8").toUpperCase(),
                    URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        return query_pairs;
    }

    public void doList(SMBTreeConnect treeConnect, String path) throws SmbApiException, TransportException {

        List<FileInfo> list = SMB2File.list(treeConnect, path);
        FileInfo.printList(list);
    }

    public void doNotify(final SMBTreeConnect treeConnect, String path) throws SmbApiException, TransportException {

        final SMB2File fileHandle =
                SMB2File.openDirectory(treeConnect, path,
                        EnumSet.of(SMB2DirectoryAccessMask.FILE_LIST_DIRECTORY, SMB2DirectoryAccessMask
                                .FILE_READ_ATTRIBUTES),
                        EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE,
                                SMB2ShareAccess.FILE_SHARE_READ),
                        SMB2CreateDisposition.FILE_OPEN,
                        EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));

        // TODO figure out the right way to close the handles on ^c
        final Thread currentThread = Thread.currentThread();
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                currentThread.interrupt();
                fileHandle.closeSilently();
                treeConnect.closeSilently();
                treeConnect.getSession().closeSilently();
            }
        });
        while (true) {
            List<SMB2ChangeNotifyResponse.FileNotifyInfo> notify = SMB2File.notify(treeConnect, fileHandle);
            System.out.println(notify.toString());
        }
    }

    public void doDelete(SMBTreeConnect treeConnect, String path) throws SmbApiException, TransportException {
        SMB2File.rm(treeConnect, path);
    }

    private void doDeleteDir(SMBTreeConnect treeConnect, String path, boolean recursive) throws SmbApiException,
            TransportException {
        SMB2File.rmdir(treeConnect, path, recursive);
    }


    public void write(SMBTreeConnect treeConnect, String localFile, String remotePath) throws Exception {
        try (InputStream is = new FileInputStream(localFile)) {
            SMB2File.write(treeConnect, remotePath, true, is);
        }
    }

    public void read(SMBTreeConnect treeConnect, String remotePath, String localFile) throws Exception {
        try (OutputStream os = new FileOutputStream(localFile)) {
            SMB2File.read(treeConnect, remotePath, os);
        }
    }
}
