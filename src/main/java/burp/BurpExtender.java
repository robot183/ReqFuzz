package burp;


import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.PrintWriter;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import java.util.List;

import javax.swing.*;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.util.regex.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;



public  class BurpExtender extends AbstractTableModel  implements IBurpExtender, IHttpListener, IScannerCheck, IMessageEditorController, ITab  {

    public IBurpExtenderCallbacks callbacks;

    public IExtensionHelpers helpers;

    public    List<IParameter>  parameters ;

    public  JTextField textField_payload ;
    public JSplitPane RootPane ; //创建主面板
    //声明一个，用于输出的对象
    public PrintWriter  stdout ;


    List<String>  poc= new ArrayList<>();

    private IMessageEditor requestViewer;

    private IMessageEditor responseViewer;

    private IHttpRequestResponse currentlyDisplayedItem;


    public final List<LogEntry> log = new ArrayList<LogEntry>();

    public Table logTable;
    public  String  paths ;
    public JTextArea textArea;

    public  byte[] newrequest;
    public  URL urls;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks =  callbacks ;
        this.helpers=callbacks.getHelpers();
        this.stdout=   new PrintWriter(callbacks.getStdout(),true);
        callbacks.registerHttpListener(this);
        callbacks.registerScannerCheck(this);
        callbacks.setExtensionName("ReqFuzz");
        callbacks.printOutput("Author:Mind\n微信公众号: Mind安全点滴\n");
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                RootPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                JSplitPane  jSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                JSplitPane  jSplitPane2= new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                logTable = new Table(BurpExtender.this);


                JButton Button2 = new JButton("清除记录");
                textField_payload  = new JTextField("输入你想探测的域名");//regex文本


                        textArea = new JTextArea(paths);
                textArea.setEditable(false);
                textArea.setLineWrap(true);
                textArea.setWrapStyleWord(true);


                JPanel panel= new JPanel();
                panel.setLayout(new GridLayout(18, 1));

                panel.add(Button2);
                panel.add(textField_payload);
                panel.add(textArea);

                jSplitPane2.setLeftComponent(panel);

                JScrollPane scrollPane = new JScrollPane(logTable);//先创建对象在放进去
                jSplitPane.setLeftComponent(scrollPane);



                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());

                jSplitPane.setRightComponent(tabs);

                //整体分布
                RootPane.setLeftComponent(jSplitPane);
                RootPane.setRightComponent(jSplitPane2);
                RootPane.setDividerLocation(1000);

                BurpExtender.this.callbacks.customizeUiComponent(RootPane);
                BurpExtender.this.callbacks.customizeUiComponent(logTable);
                BurpExtender.this.callbacks.customizeUiComponent(scrollPane);
                BurpExtender.this.callbacks.customizeUiComponent(panel);
                BurpExtender.this.callbacks.customizeUiComponent(tabs);

                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);


                Button2.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        log.clear();
                        paths = null;
                        BurpExtender.this.fireTableDataChanged();

                    }
                });


            }
        });




    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {



        if( toolFlag == 64 || toolFlag == 4){


            byte[] reqbody;
//            if (messageIsRequest) {
//                stdout.println("是一个请求");
//            } else {
//            }
                reqbody =messageInfo.getRequest();
                IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
                List<String> headers = analyzeRequest.getHeaders();


                poc.add("s");
                poc.add("'");
                String host = textField_payload.getText();

            for (int i = 0; i < headers.size(); i++) {
                if (headers.get(i).contains(host)) {
                    stdout.println(host);
                    IHttpService httpService = messageInfo.getHttpService();
                    parameters = this.helpers.analyzeRequest(messageInfo).getParameters();
                    IParameter para;
                    stdout.println(headers.get(i));
                    URL url = analyzeRequest.getUrl();
                    String path = url.getPath();
                    stdout.println(path);

                    String newPath =path+"\"" ; // 修改路径
                    String newUrl = url.getProtocol() + "://" + url.getHost() + newPath;
                    try {
                       urls = new URL(newUrl);
                    } catch (MalformedURLException e) {
                        throw new RuntimeException(e);
                    }
//                    newrequest = helpers.buildHttpMessage(analyzeRequest.getHeaders(), newUrl.getBytes());

                    newrequest = helpers.buildHttpRequest(urls);


                    BurpExtender.this.Request(poc, httpService, newrequest);
                    stdout.println("发包");
                    break;
                }

            }




        }

    }

    public  void Request(List<String> Poc,IHttpService httpService, byte[] request){





//            IParameter newParameter = this.helpers.buildParameter(name, poc.get(i), para.getType());
//            byte[] newrequest = this.helpers.updateParameter(request, newParameter);

            IHttpRequestResponse newIHttpRequestResponse = this.callbacks.makeHttpRequest(httpService, newrequest);
            stdout.println("进入request");
            byte[] newresponse = newIHttpRequestResponse.getResponse();
            IResponseInfo response = this.helpers.analyzeResponse(newresponse);
//                     List<String> responseheader = response.getHeaders();
            String statusCode = String.valueOf(response.getStatusCode());
            int Code = Integer.valueOf(statusCode).intValue();
            if(Code==200 || Code==403 || Code==404 || Code==400) {

                LogEntry logEntry = new LogEntry(helpers.analyzeRequest(newIHttpRequestResponse).getUrl().toString(), statusCode, "", newIHttpRequestResponse);

                //刷新第一个列表框
                log.add(logEntry);
                stdout.println("添加");
                BurpExtender.this.fireTableDataChanged();// size的值，不固定时，通过刷新列表框，展示实时数据

                stdout.println(statusCode);
                stdout.println(log.size());
            }


    }

//展示 数据包详情

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    @Override
    public String getTabCaption() {
        return  "ReqFuzz" ;
    }

    @Override
    public Component getUiComponent() {
        return RootPane;
    }

    @Override
    public int getRowCount() {
        return log.size();
    }

    @Override
    public int getColumnCount() {
        return 4;
    }

    @Override
    public String getColumnName(int column) {
        switch (column){
            case 0:
                return "URL";
            case 1:
                return "Status";
            case 2:
                return "result";
            default:
                return "";
        }
    }


    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return true;
    }


    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.url;
            case 1:
                return logEntry.status;
            case 2:
                return logEntry.res;
            default:
                return "";
        }
    }



    // 用于描述一条请求记录的数据结构
    private static class LogEntry{
        final String url;
        final String status;
        final String res;
        final IHttpRequestResponse requestResponse;

        LogEntry(String url, String status, String res, IHttpRequestResponse requestResponse) {
            this.url = url;
            this.status = status;
            this.res = res;
            this.requestResponse = requestResponse;
        }
    }
    // 自定义table的changeSelection方法，将request\response展示在正确的窗口中
    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }


        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    public static void updateTextAreaWithPaths(JTextArea textArea, String paths) {
        // 创建一个StringBuilder来构建文本内容
        StringBuilder sb = new StringBuilder();

        sb.append(paths).append("\n"); // 每个路径后添加换行符


        // 使用setText方法更新JTextArea的内容
        textArea.setText(sb.toString());
    }



}


