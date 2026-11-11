package org.meshpn.client;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import static org.junit.Assert.*;

public class DiagnosticFilesTest {
    @Rule public TemporaryFolder temp=new TemporaryFolder();
    private String read(File dir)throws Exception{return new String(Files.readAllBytes(new File(dir,DiagnosticFiles.NAME).toPath()),StandardCharsets.UTF_8);}
    @Test public void writesBothPrimaryAndRemovableStorageWithoutDuplicateCopies()throws Exception{
        File first=temp.newFolder("internal"),second=temp.newFolder("sd");
        DiagnosticFiles.Result r=DiagnosticFiles.save(new File[]{first,null,second,first},"Разрешение: нет\n");
        assertEquals(2,r.paths.size());assertEquals(0,r.failed);assertEquals("Разрешение: нет\n",read(first));assertEquals(read(first),read(second));
        assertEquals(1,first.listFiles().length);
    }
    @Test public void missingOrUnmountedStorageDoesNotBlockOtherVolume()throws Exception{
        File bad=new File(temp.newFile("not-a-directory"),"diagnostics"),good=temp.newFolder("sd");
        DiagnosticFiles.Result r=DiagnosticFiles.save(new File[]{bad,good},"report");
        assertEquals(1,r.failed);assertEquals(1,r.paths.size());assertEquals("report",read(good));
    }
    @Test public void nextReportReplacesPreviousFile()throws Exception{
        File dir=temp.newFolder();DiagnosticFiles.save(new File[]{dir},"old");
        assertEquals(1,DiagnosticFiles.save(new File[]{dir},"new").paths.size());assertEquals("new",read(dir));assertEquals(1,dir.listFiles().length);
    }
    @Test public void failedPublishLeavesExistingObjectAndNoTemporaryReport()throws Exception{
        File dir=temp.newFolder(),target=new File(dir,DiagnosticFiles.NAME);assertTrue(target.mkdir());
        DiagnosticFiles.Result r=DiagnosticFiles.save(new File[]{dir},"report");
        assertTrue(r.paths.isEmpty());assertEquals(1,r.failed);assertTrue(target.isDirectory());assertEquals(1,dir.listFiles().length);
    }
    @Test public void noStorageIsReportedWithoutFalseSuccess(){
        assertTrue(DiagnosticFiles.save(null,"report").paths.isEmpty());assertTrue(DiagnosticFiles.save(new File[]{null},"report").paths.isEmpty());
    }
}
