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

import com.hierynomus.smbj.Config;
import com.hierynomus.smbj.DefaultConfig;
import com.hierynomus.smbj.common.SmbHandler;
import com.hierynomus.smbj.smb2.SMB2CreateDisposition;
import com.hierynomus.smbj.smb2.SMB2CreateOptions;
import com.hierynomus.smbj.smb2.SMB2DirectoryAccessMask;
import com.hierynomus.smbj.smb2.SMB2FileId;
import com.hierynomus.smbj.smb2.SMB2ShareAccess;
import com.hierynomus.smbj.smb2.messages.SMB2ChangeNotifyResponse;
import com.hierynomus.smbj.smb2.messages.SMB2QueryDirectoryResponse;
import com.hierynomus.smbj.transport.TransportException;

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
        public boolean useOffsetForEmptyNames = false;
    }

    public static ConnectInfo getConnectInfo(String url) throws MalformedURLException, UnsupportedEncodingException {
        URL smbUrl = new URL(null, url, new SmbHandler());

        ConnectInfo ci = new ConnectInfo();
        ci.host = smbUrl.getHost();
        ci.sharePath = smbUrl.getPath();

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

        ShareConnectionSync scs = null;
        try {
            ConnectInfo ci = getConnectInfo(args[0]);

            System.out.printf("%s-%s-%s-%s-%s\n", ci.host, ci.domain, ci.user, ci.password, ci.sharePath);
            scs = SmbjApi.connect(
                    getConfig(ci.useOffsetForEmptyNames), ci.host, ci.user, ci.password, ci.domain, ci.sharePath);

            String command = args[1].toLowerCase();
            String path = null;
            switch (command) {
                case "list":
                    path = args.length > 2 ? args[2] : null;
                    doList(scs, path);
                    break;
                case "notify":
                    path = args.length > 2 ? args[2] : null;
                    doNotify(scs, path);
                    break;
                case "rm":
                    path = args[2];
                    doDelete(scs, path);
                    break;
                case "rmdir":
                    path = args[2];
                    boolean recursive = args.length > 3 ? Boolean.valueOf(args[3]) : false;
                    doDeleteDir(scs, path, recursive);
                    break;
                case "write":
                    String localfile = args[2];
                    String remotePath = args[3];
                    write(scs, localfile, remotePath);
                    break;
                case "read":
                    remotePath = args[2];
                    localfile = args[3];
                    read(scs, remotePath, localfile);
                    break;
                default:
                    System.out.println("Dont know");
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
            if (scs != null) SmbjApi.disconnect(scs);
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

    public void doList(ShareConnectionSync scs, String path) throws SmbApiException, TransportException {

        List<SMB2QueryDirectoryResponse.FileInfo> list = SmbjApi.list(scs, path);
        SMB2QueryDirectoryResponse.FileInfoFormatter.print(list);
    }

    public void doNotify(final ShareConnectionSync scs, String path) throws SmbApiException, TransportException {

        final SMB2FileId smb2FileId =
                SmbjApi.openDirectory(scs, path,
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
                try {
                    SmbjApi.close(scs, smb2FileId);
                } catch (Exception ignore) {
                }
                try {
                    SmbjApi.disconnect(scs);
                } catch (Exception ignore) {
                }
            }
        });
        while (true) {
            List<SMB2ChangeNotifyResponse.FileNotifyInfo> notify = SmbjApi.notify(scs, smb2FileId);
            System.out.println(notify.toString());
        }
    }

    public void doDelete(ShareConnectionSync scs, String path) throws SmbApiException, TransportException {
        SmbjApi.rm(scs, path);
    }

    private void doDeleteDir(ShareConnectionSync scs, String path, boolean recursive) throws SmbApiException,
            TransportException {
        SmbjApi.rmdir(scs, path, recursive);
    }


    public void write(ShareConnectionSync scs, String localFile, String remotePath) throws Exception {
        try (InputStream is = new FileInputStream(localFile)) {
            SmbjApi.write(scs, remotePath, true, is);
        }
    }

    public void read(ShareConnectionSync scs, String remotePath, String localFile) throws Exception {
        try (OutputStream os = new FileOutputStream(localFile)) {
            SmbjApi.read(scs, remotePath, os);
        }
    }

    private Config getConfig(final boolean useOffsetForEmptyNames) {
        return new DefaultConfig() {
            @Override
            public boolean isUseOffsetForEmptyNames() {
                return useOffsetForEmptyNames;
            }
        };
    }

}
