package com.wb;

import java.io.*;
import java.util.ArrayList;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.lang.reflect.Field;
import java.util.Date;
import java.util.HashMap;
import javax.swing.*;

public class ScanMain {

    //启动扫描模块
    public void start(JFrame jf,JTextArea log,HashMap<String,ArrayList<String>> ipMap,int ThreadNum,ArrayList<String> plugins)throws Exception {

        //将资源压入tasklist
        boolean status=tasklist(plugins,ipMap,ThreadNum,log);

        if(status) {
            log.append("扫描已完成！"+"\r\n");
        }else{
            log.append("扫描未知异常退出！"+"\r\n");
        }
    }

    //收集插件
    public ArrayList<String> getPlugin(JFrame jf) {
        ArrayList<String> plugins=new ArrayList<>();

        File file=new File("vuln");
        try {
            if (file.exists() & file.isDirectory()) {
                for (String vuln : file.list()) {
                    plugins.add(vuln);
                }
            }
        }catch (Exception e){
            JOptionPane.showMessageDialog(
                    jf,
                    e.toString(),
                    "错误提示",
                    JOptionPane.WARNING_MESSAGE
            );
        }
        return plugins;
    }

    //加载lib下的jar包
    public static ArrayList<String> getJar(){
        ArrayList<String> jars=new ArrayList<>();
        File file=new File("lib");
        try {
            if (file.exists() & file.isDirectory()) {
                for (String jar : file.list()) {
                    if(jar.endsWith(".jar")) {
                        jars.add(jar);
                    }
                }
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return jars;
    }

    //扫描引擎后续会完善代码提高效率
    public boolean pluginEngine(ArrayList<String> al,String iphost,JTextArea log)throws Exception{
        //加载外部lib文件下jar包和vuln下的POC
        ArrayList<URL> urllist=new ArrayList<>();

        File file=new File("vuln");
        System.out.println(file.getPath());
        URL url=file.toURI().toURL();
        urllist.add(url);

        ArrayList<String> jars=getJar();
        for(String jar:jars){
            urllist.add((new File("lib/"+jar)).toURI().toURL());
        }
        URL[] urls=urllist.toArray(new URL[urllist.size()]);

        ClassLoader loader=new URLClassLoader(urls);//创建类载入器
        for(String vuln:al) {
            System.out.println(vuln.split("\\.")[0]);
            Class<?> cls = loader.loadClass(vuln.split("\\.")[0]);
            Object obj=cls.newInstance();

            //获取POC的info
            HashMap<String,String> hm=new HashMap<>();   //存放属性对
            Field[] fields = cls.getDeclaredFields();
            for(Field field:fields){
                if(field.getGenericType().toString().equals("class java.lang.String")){
                    field.setAccessible(true);
                    hm.put(field.getName(),(String) field.get(obj));
                }else{
                    log.append(obj.getClass().getName()+"插件属性应该为String类型"+"\r\n");
                }
            }
            //log.append(hm.toString()+"\r\n");

            //调用check
            Method method=cls.getMethod("check",String.class);
            try {
                Object o = method.invoke(obj, iphost);
                String result = String.valueOf(o);
                if (!result.equals("NOT_FIND_BUG")) {
                    log.append(hm.get("name") + ":\t" + result +"\t"+iphost+"\r\n");
                }
            }catch (Exception e){
                e.printStackTrace();
                log.append("插件："+obj.getClass().getName()+"，扫描目标("+iphost+")发生异常，请检查，并重新扫描 ");
            }
        }
        boolean flag=true;    //程序状态反馈，true为正常执行，false为异常状态。
        return flag;
    }

    //插件检查，并log异常插件。
    public boolean checkPlugin(ArrayList<String> plugins,JTextArea log){
        boolean checkresult=true;
        try {
            ArrayList<URL> urllist=new ArrayList<>();

            File file=new File("vuln");
            System.out.println(file.getPath());
            URL url=file.toURI().toURL();
            urllist.add(url);

            ArrayList<String> jars=getJar();
            for(String jar:jars){
                urllist.add((new File("lib/"+jar)).toURI().toURL());
            }
            URL[] urls=urllist.toArray(new URL[urllist.size()]);

            ClassLoader loader=new URLClassLoader(urls);//创建类载入器
            for (String vuln : plugins) {
                Class<?> cls = loader.loadClass(vuln.split("\\.")[0]);
                Object obj=cls.newInstance();

                //获取POC的info
                HashMap<String,String> hm=new HashMap<>();   //存放属性对
                Field[] fields = cls.getDeclaredFields();
                for(Field field:fields){
                    if(field.getGenericType().toString().equals("class java.lang.String")){
                        field.setAccessible(true);
                        hm.put(field.getName(),(String) field.get(obj));
                    }else{
                        log.append(obj.getClass().getName()+":插件属性应该为String类型"+"\r\n");
                        checkresult=false;
                    }
                }
                if(!hm.containsKey("name")){
                    log.append(obj.getClass().getName()+": 插件没有name属性\r\n");
                    checkresult=false;
                }
                if(!hm.containsKey("descript")){
                    log.append(obj.getClass().getName()+": 插件没有descript属性\r\n");
                    checkresult=false;
                }
                if(!hm.containsKey("cve_number")){
                    log.append(obj.getClass().getName()+": 插件没有cve_number属性\r\n");
                    checkresult=false;
                }
                Method method=cls.getMethod("check",String.class);
            }
        }catch (Exception e){
            checkresult=false;
            log.append(e.toString()+"\r\n");
        }

        return checkresult;
    }


    //资源分配并调用扫描引擎
    private boolean tasklist(ArrayList<String> plugins,HashMap<String,ArrayList<String>> ipsources,int ThreadNum,JTextArea log){
        boolean flag=true;
        int targetnum=0;
        ArrayList<MyThread>  myThreadslist=new ArrayList<>();
        for(ArrayList i :ipsources.values()){
            targetnum+=i.size();
        }

        //分配资源到线程

        int counter=0;
        ArrayList<String> sourcelist=new ArrayList<>();

        if(targetnum/ThreadNum==0){
            for(String ip:ipsources.keySet()){
                for(String iphost:ipsources.get(ip)) {
                    sourcelist.add(iphost);
                    myThreadslist.add(new MyThread(plugins,(ArrayList<String>)sourcelist.clone(), log));
                    sourcelist.clear();
                }
            }
        }else{
            int num=targetnum/ThreadNum;
            for(String ip:ipsources.keySet()){
                for(String iphost:ipsources.get(ip)){
                    sourcelist.add(iphost);
                    counter++;
                    if(sourcelist.size()==num){
                        myThreadslist.add(new MyThread(plugins,(ArrayList<String>)sourcelist.clone(),log));
                        sourcelist.clear();
                    }else if((targetnum-counter==0)&(targetnum%ThreadNum!=0)){
                        myThreadslist.add(new MyThread(plugins,(ArrayList<String>)sourcelist.clone(),log));
                        sourcelist.clear();
                    }
                }
            }
        }

        log.append(new Date().toString()+"\r\n");
        for(MyThread j:myThreadslist){
            j.start();
        }
        for(MyThread i:myThreadslist){
            try {
                i.join();
            }catch (Exception e){
                log.append(e.toString());
            }
        }
        myThreadslist.clear();
        log.append(new Date().toString()+"\r\n");
        return flag;
    }
}

class MyThread extends Thread{
    private ArrayList<String> plugins;
    private ArrayList<String> sourcelist;
    private JTextArea log;
    private ScanMain scan=new ScanMain();

    public MyThread(ArrayList<String> plugins,ArrayList<String> sourcelist,JTextArea log){
        super();
        this.plugins=plugins;
        this.sourcelist=sourcelist;
        this.log=log;
    }

    @Override
    public void run() {
        for(String hostip:sourcelist){
            try {
                scan.pluginEngine(plugins, hostip, log);
            }catch (Exception e){
                log.append(e.toString());
            }
        }
    }
}
