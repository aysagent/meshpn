package org.meshpn.client;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

final class DiagnosticFiles {
    static final AtomicBoolean saving=new AtomicBoolean();
    static final String NAME="clean-vpn-diagnostic.txt";
    static final class Result {final List<String> paths=new ArrayList<>();int failed;}
    static Result save(File[] directories,String report){
        Result result=new Result();Set<String> seen=new HashSet<>();
        byte[] bytes=report.getBytes(StandardCharsets.UTF_8);
        if(bytes.length>131072)throw new IllegalArgumentException("report_size");
        if(directories==null)return result;
        for(File dir:directories){
            if(dir==null)continue;
            File tmp=null;
            try{
                if(!seen.add(dir.getCanonicalPath()))continue;
                if(!dir.isDirectory()&&!dir.mkdirs())throw new IOException("directory_unavailable");
                File target=new File(dir,NAME);
                if(target.exists()&&!target.isFile())throw new IOException("report_target_not_file");
                tmp=File.createTempFile("vpn-report-",".tmp",dir);
                try(FileOutputStream out=new FileOutputStream(tmp)){out.write(bytes);out.getFD().sync();}
                if(!tmp.renameTo(target))throw new IOException("report_publish");
                result.paths.add(target.getAbsolutePath());
            }catch(IOException|SecurityException e){result.failed++;}
            finally{if(tmp!=null)try{tmp.delete();}catch(SecurityException ignored){}}
        }
        return result;
    }
}
