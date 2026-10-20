package com.fieldkit.analyzer;

import android.content.*;
import android.database.*;
import android.net.Uri;
import android.os.*;
import android.provider.OpenableColumns;
import java.io.*;

/** Read-only, individually granted access to generated reports. */
public final class ExportProvider extends ContentProvider {
    @Override public boolean onCreate(){return true;}
    private File file(Uri uri)throws FileNotFoundException {
        String name=uri.getLastPathSegment();if(name==null||!name.matches("[A-Za-z0-9._-]+"))throw new FileNotFoundException("Invalid export");
        File dir=new File(getContext().getCacheDir(),"exports"),file=new File(dir,name);
        try{if(!file.getCanonicalFile().getParentFile().equals(dir.getCanonicalFile())||!file.isFile())throw new FileNotFoundException();}catch(IOException e){throw new FileNotFoundException();}return file;
    }
    @Override public String getType(Uri uri){String n=uri.getLastPathSegment();return n!=null&&n.endsWith("json")?"application/json":n!=null&&n.endsWith("csv")?"text/csv":"text/plain";}
    @Override public ParcelFileDescriptor openFile(Uri uri,String mode)throws FileNotFoundException {if(!"r".equals(mode))throw new FileNotFoundException("Read only");return ParcelFileDescriptor.open(file(uri),ParcelFileDescriptor.MODE_READ_ONLY);}
    @Override public Cursor query(Uri uri,String[] projection,String selection,String[] args,String sort){
        try{File f=file(uri);String[] cols=projection==null?new String[]{OpenableColumns.DISPLAY_NAME,OpenableColumns.SIZE}:projection;MatrixCursor c=new MatrixCursor(cols);Object[] row=new Object[cols.length];for(int i=0;i<cols.length;i++)row[i]=OpenableColumns.DISPLAY_NAME.equals(cols[i])?f.getName():OpenableColumns.SIZE.equals(cols[i])?f.length():null;c.addRow(row);return c;}catch(FileNotFoundException e){return null;}}
    @Override public Uri insert(Uri u,ContentValues v){throw new UnsupportedOperationException();}
    @Override public int update(Uri u,ContentValues v,String s,String[] a){throw new UnsupportedOperationException();}
    @Override public int delete(Uri u,String s,String[] a){throw new UnsupportedOperationException();}
}
