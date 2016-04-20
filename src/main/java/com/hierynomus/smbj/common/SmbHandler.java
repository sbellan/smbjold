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

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

/**
 * Thanks to Jcifs for the SmbHandler
 */
public class SmbHandler extends URLStreamHandler {

    @Override
    protected URLConnection openConnection(URL u) throws IOException {
        throw new IOException("Not Supported ");
    }

    @Override
    protected void parseURL(URL u, String spec, int start, int limit) {
        String host = u.getHost();
        String path, ref;
        int port;

        if (spec.equals("smb://")) {
            spec = "smb:////";
            limit += 2;
        } else if (spec.startsWith("smb://") == false &&
                host != null && host.length() == 0) {
            spec = "//" + spec;
            limit += 2;
        }
        super.parseURL(u, spec, start, limit);
        path = u.getPath();
        ref = u.getRef();
        if (ref != null) {
            path += '#' + ref;
        }
        port = u.getPort();
        if (port == -1) {
            port = getDefaultPort();
        }
        setURL(u, "smb", u.getHost(), port,
                u.getAuthority(), u.getUserInfo(),
                path, u.getQuery(), null);
    }
}
