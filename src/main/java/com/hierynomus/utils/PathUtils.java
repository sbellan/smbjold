package com.hierynomus.utils;

/**
 * Created by temp on 4/21/16.
 */
public class PathUtils {

    public static String fix(String s) {
        return s.replace('/', '\\');
    }

    public static String get(String first, String... more) {
        StringBuilder sb = new StringBuilder(first);
        for (int i = 0; i < more.length; i++) {
            sb.append('\\');
            sb.append(more[i]);
        }
        return sb.toString();
    }
}
