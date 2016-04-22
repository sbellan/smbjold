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

import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileInfo;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.smbj.Config;
import com.hierynomus.smbj.DefaultConfig;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.api.SmbApiException;
import com.hierynomus.smbj.api.SmbCommandLine;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBTreeConnect;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.smb2.SMB2File;
import com.hierynomus.smbj.smb2.SMB2StatusCode;
import com.hierynomus.smbj.transport.TransportException;
import com.hierynomus.utils.PathUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Integration test Pre-Req
 * <p>
 * Set the environment variable TEST_SMBJ_API_URL to an SMB URL,
 * smb://<host>/<sharepath>?[smbuser=user]&[smbpassword=pass]&[smbdomain=domain]
 * <p>
 * For eg.) smb://192.168.99.100/public?smbuser=u1&smbpassword=pass1&smbdomain=CORP
 */
public class TestSmbjApi {

    private static final Logger logger = LoggerFactory.getLogger(TestSmbjApi.class);

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    static SmbCommandLine.ConnectInfo ci;

    String TEST_PATH = PathUtils.fix("junit_testsmbjapi");

    @BeforeClass
    public static void setup() throws IOException {
        String url = System.getenv("TEST_SMBJ_API_URL");
        if (url == null) {
            url = "smb://localhost/share";
        }
        ci = SmbCommandLine.getConnectInfo(url);
        System.out.printf("%s-%s-%s-%s-%s\n", ci.host, ci.domain, ci.user, ci.password, ci.sharePath);
    }

    @Test
    public void testTemp() throws IOException, SmbApiException, URISyntaxException {
        logger.info("Connect {},{},{},{}", ci.host, ci.user, ci.domain, ci.sharePath);
        SMBClient client = new SMBClient();
        Connection connection = client.connect(ci.host);
        AuthenticationContext ac = new AuthenticationContext(
                ci.user,
                ci.password == null ? new char[0] : ci.password.toCharArray(),
                ci.domain);
        Session session = connection.authenticate(ac);
        SMBTreeConnect smbTreeConnect = null;
        try {

            smbTreeConnect = session.treeConnect(ci.host, ci.sharePath);
            FileInfo fileInformation = SMB2File.getFileInformation(smbTreeConnect, "1/cisco.dmg");
            System.out.println(fileInformation);

            SecurityDescriptor sd = SMB2File.getSecurityInfo(smbTreeConnect, "2", EnumSet.of(SecurityInformation
                            .OWNER_SECURITY_INFORMATION,
                    SecurityInformation.GROUP_SECURITY_INFORMATION,
                    SecurityInformation.DACL_SECURITY_INFORMATION));
            System.out.println(sd);

        } finally {
            if (smbTreeConnect != null) {
                smbTreeConnect.closeSilently();
            }
            session.closeSilently();
        }
    }

    @Test
    public void testFull() throws IOException, SmbApiException, URISyntaxException {

        logger.info("Connect {},{},{},{}", ci.host, ci.user, ci.domain, ci.sharePath);
        SMBClient client = new SMBClient();
        Connection connection = client.connect(ci.host);
        AuthenticationContext ac = new AuthenticationContext(
                ci.user,
                ci.password == null ? new char[0] : ci.password.toCharArray(),
                ci.domain);
        Session session = connection.authenticate(ac);
        SMBTreeConnect smbTreeConnect = null;
        try {
            // Remove the test directory and ignore not found
            smbTreeConnect = session.treeConnect(ci.host, ci.sharePath);
            try {
                SMB2File.rmdir(smbTreeConnect, TEST_PATH, true);
            } catch (SmbApiException sae) {
                if (sae.getStatusCode() != SMB2StatusCode.STATUS_OBJECT_NAME_NOT_FOUND) {
                    throw sae;
                }
            }

            // Create it again
            SMB2File.mkdir(smbTreeConnect, PathUtils.fix(TEST_PATH));
            SMB2File.mkdir(smbTreeConnect, PathUtils.fix(TEST_PATH + "/1"));
            SMB2File.mkdir(smbTreeConnect, PathUtils.fix(TEST_PATH + "/1/2"));
            SMB2File.mkdir(smbTreeConnect, PathUtils.fix(TEST_PATH + "/1/2/3"));
            SMB2File.mkdir(smbTreeConnect, PathUtils.fix(TEST_PATH + "/1/2/3/4"));
            SMB2File.mkdir(smbTreeConnect, PathUtils.fix(TEST_PATH + "/2"));
            SMB2File.mkdir(smbTreeConnect, PathUtils.fix(TEST_PATH + "/3"));
            SMB2File.mkdir(smbTreeConnect, PathUtils.fix(TEST_PATH + "/4"));
            SMB2File.mkdir(smbTreeConnect, PathUtils.fix(TEST_PATH + "/4/2"));
            SMB2File.mkdir(smbTreeConnect, PathUtils.fix(TEST_PATH + "/4/2/3"));
            SMB2File.mkdir(smbTreeConnect, PathUtils.fix(TEST_PATH + "/4/2/3/4"));

            assertTrue(SMB2File.folderExists(smbTreeConnect, PathUtils.fix(TEST_PATH)));
            assertTrue(SMB2File.folderExists(smbTreeConnect, PathUtils.fix(TEST_PATH + "/4/2/3/4")));
            try {
                SMB2File.fileExists(smbTreeConnect, PathUtils.fix(TEST_PATH));
                fail(TEST_PATH + " is not a file");
            } catch (SmbApiException sae) {
                if (sae.getStatusCode() != SMB2StatusCode.STATUS_FILE_IS_A_DIRECTORY) {
                    throw sae;
                }
            }

            FileInfo fileInformation = SMB2File.getFileInformation(smbTreeConnect, PathUtils.fix(TEST_PATH +
                    "/4/2"));
            assertTrue(EnumWithValue.EnumUtils.isSet(
                    fileInformation.getFileAttributes(), FileAttributes.FILE_ATTRIBUTE_DIRECTORY));

            assertFilesInPathEquals(smbTreeConnect, new String[]{"1", "2", "3", "4"}, PathUtils.fix(TEST_PATH));

            // Delete folder (Non recursive)
            SMB2File.rmdir(smbTreeConnect, PathUtils.fix(TEST_PATH + "/2"), false);
            assertFilesInPathEquals(smbTreeConnect, new String[]{"1", "3", "4"}, PathUtils.fix(TEST_PATH));

            // Delete folder (recursive)
            SMB2File.rmdir(smbTreeConnect, PathUtils.fix(TEST_PATH + "/4"), true);
            assertFilesInPathEquals(smbTreeConnect, new String[]{"1", "3"}, PathUtils.fix(TEST_PATH));

            // Upload 2 files
            String file1 = UUID.randomUUID().toString() + ".txt";
            String file2 = UUID.randomUUID().toString() + ".txt";
            String file3 = UUID.randomUUID().toString() + ".pdf";
            write(smbTreeConnect, PathUtils.fix(TEST_PATH + "/1/" + file1), "testfiles/medium.txt");
            write(smbTreeConnect, PathUtils.fix(TEST_PATH + "/1/2/3/" + file2), "testfiles/small.txt");
            write(smbTreeConnect, PathUtils.fix(TEST_PATH + "/1/2/3/" + file3), "testfiles/large.pdf");

            assertFilesInPathEquals(smbTreeConnect, new String[]{file2, file3, "4"}, PathUtils.fix(TEST_PATH +
                    "/1/2/3"));

            fileInformation = SMB2File.getFileInformation(smbTreeConnect, PathUtils.fix(TEST_PATH + "/1/2/3/" +
                    file3));
            assertTrue(!EnumWithValue.EnumUtils.isSet(
                    fileInformation.getFileAttributes(), FileAttributes.FILE_ATTRIBUTE_DIRECTORY));

            try {
                SMB2File.folderExists(smbTreeConnect, PathUtils.fix(TEST_PATH + "/1/2/3/" + file2));
                fail(TEST_PATH + " is not a folder");
            } catch (SmbApiException sae) {
                if (sae.getStatusCode() != SMB2StatusCode.STATUS_NOT_A_DIRECTORY) {
                    throw sae;
                }
            }


            //Delete
            SMB2File.rm(smbTreeConnect, PathUtils.fix(TEST_PATH + "/1/2/3/" + file2));
            assertFilesInPathEquals(smbTreeConnect, new String[]{"4", file3}, PathUtils.fix(TEST_PATH + "/1/2/3"));

            // Download and compare with originals
            File tmpFile1 = File.createTempFile("smbj", "junit");
            try (OutputStream os = new FileOutputStream(tmpFile1)) {
                SMB2File.read(smbTreeConnect, PathUtils.fix(TEST_PATH + "/1/" + file1), os);
            }
            assertFileContent("testfiles/medium.txt", tmpFile1.getAbsolutePath());

            SecurityDescriptor sd = SMB2File.getSecurityInfo(smbTreeConnect, PathUtils.fix(TEST_PATH + "/1/" +
                            file1),
                    EnumSet.of
                            (SecurityInformation
                                            .OWNER_SECURITY_INFORMATION,
                                    SecurityInformation.GROUP_SECURITY_INFORMATION,
                                    SecurityInformation.DACL_SECURITY_INFORMATION));
            assertTrue(sd.getControl().contains(SecurityDescriptor.Control.PS));
            assertTrue(sd.getControl().contains(SecurityDescriptor.Control.OD));
            assertNotNull(sd.getOwnerSid());
            assertNotNull(sd.getGroupSid());
            assertNotNull(sd.getDacl());
            assertNotNull(sd.getDacl().getAceCount() == sd.getDacl().getAces().length);

            System.out.println(sd);

            // Clean up
            SMB2File.rmdir(smbTreeConnect, PathUtils.fix(TEST_PATH), true);
            assertFalse(SMB2File.folderExists(smbTreeConnect, PathUtils.fix(TEST_PATH)));

            // Listing of the root directory.
            List<FileInfo> list = SMB2File.list(smbTreeConnect, null);
            assertTrue(list.size() > 0);
        } finally {
            smbTreeConnect.closeSilently();
            session.closeSilently();
        }
    }

    // Caution load whole files into memory
    private void assertFileContent(String localResource, String downloadedFile)
            throws URISyntaxException, IOException {
        byte[] expectedBytes = Files.readAllBytes(Paths.get(this.getClass().getResource(localResource).toURI()));
        byte[] bytes = Files.readAllBytes(Paths.get(downloadedFile));
        assertArrayEquals(expectedBytes, bytes);
    }

    private void assertFilesInPathEquals(SMBTreeConnect treeConnect, String[] expected, String path)
            throws SmbApiException, TransportException {
        List<FileInfo> list = SMB2File.list(treeConnect, path);
        String names[] = getNames(list);
        Arrays.sort(expected);
        Arrays.sort(names);
        assertArrayEquals(expected, names);
    }

    private String[] getNames(List<FileInfo> list) {
        String[] names = new String[list.size()];
        int idx = 0;
        for (FileInfo fi : list) {
            names[idx++] = fi.getFileName();
        }
        return names;
    }

    void write(SMBTreeConnect treeConnect, String remotePath, String localResource)
            throws IOException, SmbApiException {
        try (InputStream is = this.getClass().getResourceAsStream(localResource)) {
            SMB2File.write(treeConnect, remotePath, true, is);
        }
    }
}
