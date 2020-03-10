package com.dianju.signatureServer.webSignService;
import com.dianju.core.Util;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.UUID;
import javax.naming.Context;
import javax.naming.NameClassPair;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
public class LdapUtil {

    //private static final String LDAP_URL = "ldap://124.207.188.210:60805";//此项需要写到配置文件里，从配置文件里读取
    //正式环境的地址
    private static final String LDAP_URL1 = "ldap://10.112.5.138:389";//此项需要写到配置文件里，从配置文件里读取
    private static  String LDAP_URL =Util.getSystemDictionary("LDAP_URL");
    // LDAP驱动
    private static final String LDAP_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";

    private static final String crl_dn = "cn=crl,ou=CRL,o=CCTV,c=cn";

    /**** 测试 ****/
    /*public static void main(String[] args) {

	   //test();
        testNew();

    }*/

    public static void testNew(){
        String   crl_path = Util.getSystemDictionary("crl_path");
        LdapContext ctx = null;
        Control[] connCtls = null;
//       DirContext dc = null;
        Hashtable env = new Hashtable();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        //没有以下两行的话，是匿名登录
//       env.put(Context.SECURITY_PRINCIPAL, userCN);
//       env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_FACTORY);
        env.put(Context.PROVIDER_URL, LDAP_URL);
        try {
            // 连接LDAP进行认证
//    	   dc = new InitialDirContext(env);
            ctx = new InitialLdapContext(env, connCtls);
//           System.out.println("认证成功");
        } catch (javax.naming.AuthenticationException e) {
            e.printStackTrace();
            System.out.println("登录失败");
        } catch (NamingException err) {
            err.printStackTrace();
            System.out.println("-->>登录失败");
        } catch (Exception e) {
            System.out.println("登录出错：");
            e.printStackTrace();
        }
        int totalResults = 0;
        Map<String,String> map = new HashMap<String, String>();
        try {
            if(ctx != null){
                Attributes Attrs = ctx.getAttributes(crl_dn);
                System.out.println("Attrs:"+Attrs);
                if (Attrs != null) {
                    try {
                        for (NamingEnumeration ne = Attrs.getAll(); ne.hasMore();) {
                            Attribute Attr = (Attribute) ne.next();
                            System.out.println("AttributeID==="+ Attr.getID().toString());
                            if(Attr.getID().toString().equals("certificateRevocationList;binary")){
                                // 读取属性值
                                for (NamingEnumeration e = Attr.getAll(); e.hasMore(); totalResults++) {
//				                               String value = e.next().toString(); // 接受循环遍历读取的userPrincipalName用户属性
//				                               System.out.println("value:"+value);
                                    byte[] data =  (byte[])e.next();
                                    System.out.println(data);
                                    System.out.println(data.length);

                                    try {
                                        BufferedOutputStream bos = null;
                                        FileOutputStream fos = null;
                                        File file = null;
                                        file = new File(crl_path);
                                        fos = new FileOutputStream(file);
                                        bos = new BufferedOutputStream(fos);
                                        bos.write(data);
                                        bos.close();
                                        fos.close();
                                    } catch (FileNotFoundException e1) {
                                        // TODO Auto-generated catch block
                                        e1.printStackTrace();
                                    } catch (IOException e1) {
                                        // TODO Auto-generated catch block
                                        e1.printStackTrace();
                                    }

                                }
                            }else{
                                // 读取属性值
//				                           for (NamingEnumeration e = Attr.getAll(); e.hasMore(); totalResults++) {
//				                               String value = e.next().toString(); // 接受循环遍历读取的userPrincipalName用户属性
//				                               System.out.println("value:"+value);
//				                           }
                            }

                        }
                    } catch (NamingException e) {
                        System.err.println("Throw Exception : " + e);
                    }
                }

            }
        } catch (NamingException e) {
            e.printStackTrace();
            return;
        }

        try {
            if(ctx != null)
                ctx.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }


    public static void test(){
        LdapContext ctx = null;
        Control[] connCtls = null;
//       DirContext dc = null;
        Hashtable env = new Hashtable();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        //没有以下两行的话，是匿名登录
//       env.put(Context.SECURITY_PRINCIPAL, userCN);
//       env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_FACTORY);
        env.put(Context.PROVIDER_URL, LDAP_URL);
        try {
            // 连接LDAP进行认证
//    	   dc = new InitialDirContext(env);
            ctx = new InitialLdapContext(env, connCtls);
//           System.out.println("认证成功");
        } catch (javax.naming.AuthenticationException e) {
            e.printStackTrace();
            System.out.println("登录失败");
        } catch (NamingException err) {
            err.printStackTrace();
            System.out.println("-->>登录失败");
        } catch (Exception e) {
            System.out.println("登录出错：");
            e.printStackTrace();
        }
        int totalResults = 0;
        Map<String,String> map = new HashMap<String, String>();
        try {
            if(ctx != null){
                NamingEnumeration<NameClassPair> list = ctx.list("ou=CRL,o=CCTV,c=cn");
//				NamingEnumeration<NameClassPair> list = ctx.list("cn=crl,ou=CRL,o=CCTV,c=cn");
//				NamingEnumeration<NameClassPair> list = ctx.list("cn=crl0,ou=CRL,o=CCTV,c=cn");
                while(list.hasMore()){
                    NameClassPair ncp = list.next();
                    String cn = ncp.getName();
                    if(cn.indexOf("=") != -1){
                        int index = cn.indexOf("=");
                        cn = cn.substring(index + 1,cn.length());
                        System.out.println(cn);
                        System.out.println(ncp.getNameInNamespace());
                        map.put(cn, ncp.getNameInNamespace());

                        Attributes Attrs = ctx.getAttributes(ncp.getName()+ ",ou=CRL,o=CCTV,c=cn");
                        System.out.println("Attrs:"+Attrs);
                        if (Attrs != null) {
                            try {
                                for (NamingEnumeration ne = Attrs.getAll(); ne.hasMore();) {
                                    Attribute Attr = (Attribute) ne.next();
                                    System.out.println("AttributeID==="+ Attr.getID().toString());
                                    if(Attr.getID().toString().equals("certificateRevocationList;binary")){
                                        // 读取属性值
                                        for (NamingEnumeration e = Attr.getAll(); e.hasMore(); totalResults++) {
//				                               String value = e.next().toString(); // 接受循环遍历读取的userPrincipalName用户属性
//				                               System.out.println("value:"+value);
                                            byte[] data =  (byte[])e.next();
                                            System.out.println(data);
                                            System.out.println(data.length);

                                            try {
                                                BufferedOutputStream bos = null;
                                                FileOutputStream fos = null;
                                                File file = null;
                                                file = new File("D:/testcrl"+UUID.randomUUID()+".crl");
                                                fos = new FileOutputStream(file);
                                                bos = new BufferedOutputStream(fos);
                                                bos.write(data);
                                                bos.close();
                                                fos.close();
                                            } catch (FileNotFoundException e1) {
                                                // TODO Auto-generated catch block
                                                e1.printStackTrace();
                                            } catch (IOException e1) {
                                                // TODO Auto-generated catch block
                                                e1.printStackTrace();
                                            }

                                        }
                                    }else{
                                        // 读取属性值
                                        for (NamingEnumeration e = Attr.getAll(); e.hasMore(); totalResults++) {
                                            String value = e.next().toString(); // 接受循环遍历读取的userPrincipalName用户属性
                                            System.out.println("value:"+value);
                                        }
                                    }

                                }
                            } catch (NamingException e) {
                                System.err.println("Throw Exception : " + e);
                            }
                        }

                    }
                }
            }
        } catch (NamingException e) {
            e.printStackTrace();
            return;
        }

        try {
            if(ctx != null)
                ctx.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }

//		Iterator<Entry<String,String>> it = map.entrySet().iterator();
//		while(it.hasNext()){
//			Entry<String,String> entry = it.next();
//			System.out.println("Key:"+entry.getKey());
//			System.out.println("Value:"+entry.getValue());
//		}

    }


}
