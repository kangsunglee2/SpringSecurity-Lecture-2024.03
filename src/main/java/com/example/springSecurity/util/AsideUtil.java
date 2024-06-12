package com.example.springSecurity.util;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Service;

@Service
public class AsideUtil {

   public String getTodayQuote(String filename) {
      String result = null;
      try {
         BufferedReader br = new BufferedReader(new FileReader(filename), 1024);
         int index = (int) Math.floor(Math.random() * 100); // 0 ~ 99
         for (int i = 0; i <= index; i++) { // index = 10
            result = br.readLine();
         }
         br.close();
      } catch (Exception e) {
         e.printStackTrace();
      }
      return result;
   }
}
