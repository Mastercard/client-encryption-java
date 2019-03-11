package com.mastercard.developer.utils;

public class StringUtils {

    private StringUtils() {
    }

    public static boolean isNullOrEmpty(String str) {
        return null == str || str.length() == 0;
    }
}