package com.imooc.security;

public class AccessContext {
    public static final ThreadLocal<String> token = new ThreadLocal<String>();

    public static String getToken(){
        return token.get();
    }

    public static void setToken(String tokenStr){
        token.set(tokenStr);
    }

    public static void clearAccessKey(){
        token.remove();
    }
}
