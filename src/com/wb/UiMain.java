package com.wb;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;

public class UiMain extends JFrame {
    private int width = Toolkit.getDefaultToolkit().getScreenSize().width;
    private int height = Toolkit.getDefaultToolkit().getScreenSize().height;
    private int windowsWedth = 800;
    private int windowsHeight = 600;

    //初始化扫描模块
    private ScanMain scan = new ScanMain();

    boolean checkresult;  //插件检查，false为不通过

    public void CreateJFrame(String title){

        //初始化界面
        JFrame jf=new JFrame(title);
        jf.setBounds((width - windowsWedth) / 2, (height - windowsHeight) / 2, windowsWedth, windowsHeight);
        jf.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

        placeComponents(jf);
        jf.setVisible(true);
    }

    //画界面
    private void placeComponents(JFrame jf) {
        JPanel panel=new JPanel();
        jf.add(panel);


        panel.setLayout(null);

        JLabel label3=new JLabel("选择线程数：");
        label3.setBounds(60,25,80,25);
        JComboBox jComboBox1=new JComboBox();
        jComboBox1.addItem("5");
        jComboBox1.addItem("10");
        jComboBox1.addItem("15");
        jComboBox1.setBounds(150,25,80,25);
        panel.add(label3);
        panel.add(jComboBox1);

        //获取插件信息
        ArrayList<String> plugins = scan.getPlugin(jf);
        JLabel label1=new JLabel("插件数: "+plugins.size());
        label1.setBounds(350,25,80,25);
        panel.add(label1);

        JLabel label2=new JLabel("输入目标:");
        label2.setBounds(55,120,80,30);
        panel.add(label2);

        JTextArea text1=new JTextArea();
        JScrollPane js=new JScrollPane(text1);
        js.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        js.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        js.setBounds(25,180,725,350);
        text1.setLineWrap(true);
        panel.add(js);

        JTextArea text2=new JTextArea();
        JScrollPane js2=new JScrollPane(text2);
        js2.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        js2.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        js2.setBounds(120,85,480,85);
        panel.add(js2);

        JButton button1 = new JButton("插件检查");
        button1.setBounds(610, 25, 95, 25);
        panel.add(button1);

        JButton button2 = new JButton("开始扫描");
        button2.setBounds(610, 120, 95, 25);
        panel.add(button2);

        button1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                text1.setText("插件检查....\r\n");
                checkresult=scan.checkPlugin(plugins,text1);
                if(!checkresult){
                    button2.setEnabled(false);
                    JOptionPane.showMessageDialog(
                            jf,
                            "插件有误，请检查插件",
                            "错误提示",
                            JOptionPane.WARNING_MESSAGE
                    );
                }else{
                    button2.setEnabled(true);
                }
                text1.append("插件检查完成！");
            }
        });

        button2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    //资源解析
                    text1.setText("资源解析...\n");
                    SrcHandle srcHandle=new SrcHandle(text2.getText(),jf);
                    HashMap<String,ArrayList<String>> ipMap;
                    ipMap=srcHandle.handle();
                    text1.append(ipMap.toString()+"\r\n");

                    //获取线程数
                    int ThreadNum;
                    if(jComboBox1.getSelectedIndex()==0){
                        ThreadNum=5;
                    }else if(jComboBox1.getSelectedIndex()==1){
                        ThreadNum=10;
                    }else{
                        ThreadNum=15;
                    }
                     text1.append("线程数为: "+ThreadNum+"\r\n");

                    //开始扫描
                    if(!ipMap.containsKey("error")) {
                        text1.append("开始扫描："+"\r\n");
                        button2.setEnabled(false);
                        ThreadMain threadMain=new ThreadMain(jf, text1,button2,ipMap,ThreadNum,plugins);
                        threadMain.start();
                    }
                }catch (Exception e1){
                    JOptionPane.showMessageDialog(
                            jf,
                            e1.toString(),
                            "错误提示",
                            JOptionPane.WARNING_MESSAGE
                    );
                }
            }
        });

    }

    public static void main(String[] args){
        new UiMain().CreateJFrame("漏洞扫描工具 V1.0 ( by zil0ng) ");
    }
}

class ThreadMain extends Thread{
    private JFrame jf;
    private JTextArea log;
    private HashMap<String,ArrayList<String>> ipMap;
    private int ThreadNum;
    private ArrayList<String> plugins;
    private JButton button2;
    ScanMain scan=new ScanMain();

    public ThreadMain(JFrame jf,JTextArea log,JButton button2,HashMap<String,ArrayList<String>> ipMap,int ThreadNum,ArrayList<String> plugins){
        super();
        this.ipMap=ipMap;
        this.jf=jf;
        this.log=log;
        this.plugins=plugins;
        this.ThreadNum=ThreadNum;
        this.button2=button2;
    }

    @Override
    public void run() {
        try {
            scan.start(jf, log, ipMap, ThreadNum, plugins);
            button2.setEnabled(true);
        }catch (Exception e){
            JOptionPane.showMessageDialog(
                    jf,
                    e.toString(),
                    "错误提示",
                    JOptionPane.WARNING_MESSAGE
            );
        }
    }

}