package com.github.kaiwinter.shellysolis;

import com.alibaba.fastjson.JSON;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Response;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;

public class Authorization {

    private static final String KEY = "";
    private static final String KEY_SECRET = "";

    public static void main(String[] args) {
        try {
            Map<String,Object> map = new HashMap<>();
            String body = JSON.toJSONString(map);
            String ContentMd5 = getDigest(body);
            String Date = getGMTTime();
            String path = "/v1/api/inverterList";
            String param = "POST" + "\n" + ContentMd5 + "\n" + "application/json" + "\n" + Date + "\n" + path;
            String sign = HmacSHA1Encrypt(param, KEY_SECRET);
            String url = "https://www.soliscloud.com:13333" + path ;

            System.out.println("body: " + body);
            System.out.println("ContentMd5: " + ContentMd5);
            System.out.println("Date: " + Date);
            System.out.println("param: " + param);
            System.out.println("sign: " + sign);

            OkHttpClient client = new OkHttpClient();
            MediaType xmlType = MediaType.parse("application/json;charset=UTF-8");
            okhttp3.RequestBody requestBody = okhttp3.RequestBody.create(xmlType,body);
            okhttp3.Request request = new okhttp3.Request.Builder()
                    .url(url)
                    .addHeader("Content-type", "application/json;charset=UTF-8")
                    .addHeader("Authorization","API " + KEY + ":" + sign)
                    .addHeader("Content-MD5",ContentMd5)
                    .addHeader("Date",Date)
                    .post(requestBody)
                    .build();
            Response response = client.newCall(request).execute();
            String string = response.body().string();
            System.out.println(string);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String HmacSHA1Encrypt(String encryptText, String KeySecret) throws Exception
    {
        byte[] data=KeySecret.getBytes(StandardCharsets.UTF_8);
        SecretKey secretKey = new SecretKeySpec(data, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(secretKey);

        byte[] text = encryptText.getBytes(StandardCharsets.UTF_8);
        byte[] result = mac.doFinal(text);
        return Base64.encodeBase64String(result);
    }

    public static String getGMTTime(){

        Calendar cd = Calendar.getInstance();
        SimpleDateFormat sdf = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss 'GMT'", Locale.US);
        sdf.setTimeZone(TimeZone.getTimeZone("GMT"));
        String str = sdf.format(cd.getTime());
        return  str;
    }

    public static String getDigest(String test) {
        String result = "";
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(test.getBytes());
            byte[] b = md.digest();
            result = java.util.Base64.getEncoder().encodeToString(b);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return result;
    }
}
