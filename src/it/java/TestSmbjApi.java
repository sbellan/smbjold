import com.hierynomus.smbj.Config;
import com.hierynomus.smbj.DefaultConfig;
import com.hierynomus.smbj.api.ShareConnectionSync;
import com.hierynomus.smbj.api.SmbApiException;
import com.hierynomus.smbj.api.SmbjApi;
import com.hierynomus.smbj.smb2.SMB2StatusCode;
import com.hierynomus.smbj.smb2.messages.SMB2QueryDirectoryResponse;
import com.hierynomus.smbj.transport.TransportException;
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
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Created by temp on 4/7/16.
 */
public class TestSmbjApi {

    private static final Logger logger = LoggerFactory.getLogger(TestSmbjApi.class);

    static String host = null;
    static String domain = null;
    static String user = null;
    static String password = null;
    static String sharePath = null;
    static boolean useOffsetForEmptyNames = false;

    String TEST_PATH = "junit_testsmbjapi";

    @BeforeClass
    public static void setup() throws IOException {
        String env = System.getenv("TEST_SMBJ_API_ENV");
        if (env == null) {
            env = "default";
        }
        Properties p = new Properties();
        String loadFileName = "/testfiles/connection_" + env + ".properties";

        logger.info("Trying to load {}", loadFileName);

        p.load(TestSmbjApi.class.getResourceAsStream(loadFileName));
        host = p.getProperty("host");
        domain = p.getProperty("domain");
        user = p.getProperty("user");
        password = p.getProperty("password");
        sharePath = p.getProperty("share_path");
        useOffsetForEmptyNames = Boolean.parseBoolean(p.getProperty("use_offset_for_empty_names", "false"));
    }

    @Test
    public void testFull() throws IOException, SmbApiException, URISyntaxException {
        ShareConnectionSync scs = SmbjApi.connect(getConfig(), host, user, password, domain, sharePath);

        try {
            // Remove the test directory and ignore not found
            try {
                SmbjApi.rmdir(scs, TEST_PATH, true);
            } catch (SmbApiException sae) {
                if (sae.getStatusCode() != SMB2StatusCode.STATUS_OBJECT_NAME_NOT_FOUND) {
                    throw sae;
                }
            }
            // Create it again
            SmbjApi.mkdir(scs, TEST_PATH);
            SmbjApi.mkdir(scs, TEST_PATH + "/1");
            SmbjApi.mkdir(scs, TEST_PATH + "/1/2");
            SmbjApi.mkdir(scs, TEST_PATH + "/1/2/3");
            SmbjApi.mkdir(scs, TEST_PATH + "/1/2/3/4");
            SmbjApi.mkdir(scs, TEST_PATH + "/2");
            SmbjApi.mkdir(scs, TEST_PATH + "/3");
            SmbjApi.mkdir(scs, TEST_PATH + "/4");
            SmbjApi.mkdir(scs, TEST_PATH + "/4/2");
            SmbjApi.mkdir(scs, TEST_PATH + "/4/2/3");
            SmbjApi.mkdir(scs, TEST_PATH + "/4/2/3/4");

            assertTrue(SmbjApi.folderExists(scs, TEST_PATH));
            assertTrue(SmbjApi.folderExists(scs, TEST_PATH + "/4/2/3/4"));
            try {
                SmbjApi.fileExists(scs, TEST_PATH);
                fail(TEST_PATH + " is not a file");
            } catch (SmbApiException sae) {
                if (sae.getStatusCode() != SMB2StatusCode.STATUS_FILE_IS_A_DIRECTORY) {
                    throw sae;
                }
            }

            assertFilesInPathEquals(scs, new String[]{"1", "2", "3", "4"}, TEST_PATH);

            // Delete folder (Non recursive)
            SmbjApi.rmdir(scs, TEST_PATH + "/2", false);
            assertFilesInPathEquals(scs, new String[]{"1", "3", "4"}, TEST_PATH);

            // Delete folder (recursive)
            SmbjApi.rmdir(scs, TEST_PATH + "/4", true);
            assertFilesInPathEquals(scs, new String[]{"1", "3"}, TEST_PATH);

            // Upload 2 files
            String file1 = UUID.randomUUID().toString() + ".txt";
            String file2 = UUID.randomUUID().toString() + ".txt";
            String file3 = UUID.randomUUID().toString() + ".pdf";
            write(scs, TEST_PATH + "/1/" + file1, "testfiles/medium.txt");
            write(scs, TEST_PATH + "/1/2/3/" + file2, "testfiles/small.txt");
            write(scs, TEST_PATH + "/1/2/3/" + file3, "testfiles/large.pdf");

            assertFilesInPathEquals(scs, new String[]{file2, file3, "4"}, TEST_PATH + "/1/2/3");

            try {
                SmbjApi.folderExists(scs, TEST_PATH + "/1/2/3/" + file2);
                fail(TEST_PATH + " is not a folder");
            } catch (SmbApiException sae) {
                if (sae.getStatusCode() != SMB2StatusCode.STATUS_NOT_A_DIRECTORY) {
                    throw sae;
                }
            }


            //Delete
            SmbjApi.rm(scs, TEST_PATH + "/1/2/3/" + file2);
            assertFilesInPathEquals(scs, new String[]{"4", file3}, TEST_PATH + "/1/2/3");

            // Download and compare with originals
            File tmpFile1 = File.createTempFile("smbj", "junit");
            try (OutputStream os = new FileOutputStream(tmpFile1)) {
                SmbjApi.read(scs, TEST_PATH + "/1/" + file1, os);
            }
            assertFileContent("testfiles/medium.txt", tmpFile1.getAbsolutePath());

            // Clean up
            SmbjApi.rmdir(scs, TEST_PATH, true);
            assertFalse(SmbjApi.folderExists(scs, TEST_PATH));

        } finally {
            SmbjApi.disconnect(scs);
        }
    }

    // Caution load whole files into memory
    private void assertFileContent(String localResource, String downloadedFile)
            throws URISyntaxException, IOException {
        byte[] expectedBytes = Files.readAllBytes(Paths.get(this.getClass().getResource(localResource).toURI()));
        byte[] bytes = Files.readAllBytes(Paths.get(downloadedFile));
        assertArrayEquals(expectedBytes, bytes);
    }

    private void assertFilesInPathEquals(ShareConnectionSync scs, String[] expected, String path)
            throws SmbApiException, TransportException {
        List<SMB2QueryDirectoryResponse.FileInfo> list = SmbjApi.list(scs, path);
        String names[] = getNames(list);
        Arrays.sort(expected);
        Arrays.sort(names);
        assertArrayEquals(expected, names);
    }

    private String[] getNames(List<SMB2QueryDirectoryResponse.FileInfo> list) {
        String[] names = new String[list.size()];
        int idx = 0;
        for (SMB2QueryDirectoryResponse.FileInfo fi : list) {
            names[idx++] = fi.getFileName();
        }
        return names;
    }

    void write(ShareConnectionSync scs, String remotePath, String localResource)
            throws IOException, SmbApiException {
        try (InputStream is = this.getClass().getResourceAsStream(localResource)) {
            SmbjApi.write(scs, remotePath, true, is);
        }
    }

    private Config getConfig() {
        return new DefaultConfig() {
            @Override
            public boolean isUseOffsetForEmptyNames() {
                return useOffsetForEmptyNames;
            }
        };
    }
}
