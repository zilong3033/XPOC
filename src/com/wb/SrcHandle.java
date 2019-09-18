package com.wb;

import java.util.ArrayList;
import java.util.HashMap;
import javax.swing.*;
import java.net.URL;
import java.awt.*;

//扫描目标处理
public class SrcHandle {
   private String text;
   private JFrame jf;

   public SrcHandle(String text,JFrame jf){
       this.text=text;
       this.jf=jf;
   }

   //解析(IP:HOST)和(HTTP,HTTPS)资源
   public HashMap<String,ArrayList<String>> handle(){
       String[] hp;
       String[] iparrayj;
       String[] iparrayi;
       ArrayList<String> al=new ArrayList<>();
       HashMap<String,ArrayList<String>> hm=new HashMap<>();
       String host;

       //解析检查资源，按照IP归类
       try {
           text=text.replace(" ", "");
           text=text.replace("\n","");
           text=text.replace("\r", "");
           if(text.equals("")){
               throw new Exception("请输入目标！");
           }

           hp = text.split(";|,");
           System.out.println(hp);

           for(String j:hp) {
               if(j.equals("")){
                   continue;
               }

               if(j.startsWith("http")||j.startsWith("https")){
                   host=new URL(j).getHost();
                   al.add(j);
               }else {
                   iparrayj = j.split(":");
                   if (iparrayj.length < 2) {
                       throw new Exception("抛出异常，不符合IP:HOST和常规URL");
                   }
                   System.out.println(j);
                   for (String i : hp) {
                       iparrayi = i.split(":");
                       if(iparrayi[0].equals(iparrayj[0])){
                           al.add(i);
                       }
                   }
                   host=iparrayj[0];
               }

               //IP检查

               //port检查



               hm.put(host,(ArrayList<String>)al.clone());
               al.clear();
           }
       }catch (Exception e){
           e.printStackTrace();
           hm.put("error",al);   //此处al无意义，主要返回error标识。
           JOptionPane.showMessageDialog(
                   jf,
                   "资源解析有误，请检查吧！",
                   "错误提示",
                   JOptionPane.WARNING_MESSAGE
           );
       }
       return hm;
   }

   //nmap资源处理
   public HashMap<String,ArrayList<String>> handleNmap(){
       HashMap<String,ArrayList<String>> hm=new HashMap<>();
       //nmMap扫描结果处理




       return hm;
   }
}

