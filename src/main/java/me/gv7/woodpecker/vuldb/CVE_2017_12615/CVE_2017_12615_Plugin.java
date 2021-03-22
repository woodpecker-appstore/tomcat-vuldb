package me.gv7.woodpecker.vuldb.CVE_2017_12615;

import me.gv7.woodpecker.plugin.IExploit;
import me.gv7.woodpecker.plugin.IPluginHelper;
import me.gv7.woodpecker.plugin.IVulPlugin;
import me.gv7.woodpecker.plugin.IVulPluginCallbacks;
import me.gv7.woodpecker.vuldb.CVE_2017_12615.exploit.CVE_2020_12615_UploadExploit;
import me.gv7.woodpecker.vuldb.CVE_2017_12615.poc.CVE_2017_12615_Poc;

import java.util.ArrayList;
import java.util.List;

public class CVE_2017_12615_Plugin implements IVulPlugin {
    public static IVulPluginCallbacks callbacks;
    public static IPluginHelper pluginHelper;

    public void VulPluginMain(IVulPluginCallbacks callbacks) {
        CVE_2017_12615_Plugin.callbacks = callbacks;
        CVE_2017_12615_Plugin.pluginHelper = callbacks.getPluginHelper();
        // 设置插件信息
        callbacks.setVulPluginName("Tomcat CVE-2017-12615 plugin");
        callbacks.setVulPluginVersion("0.1.1");
        callbacks.setVulPluginAuthor("c0ny1");
        // 设置漏洞信息
        callbacks.setVulName("Tomcat put write file");
        callbacks.setVulId("CVE-2017-12615");
        callbacks.setVulCVSS(8.1);
        callbacks.setVulAuthor("iswin");
        callbacks.setVulSeverity("high");
        callbacks.setVulScope("Apache Tomcat 7.0.0 to 7.0.79");
        callbacks.setVulDescription("当在Windows上运行Apache Tomcat 7.0.0到7.0.79启用HTTP put时(例如，通过设置readonly初始化参数默认为false)，可以通过一个特别设计的请求上传一个JSP文件到服务器。然后这个JSP就可以被请求，它包含的任何代码都将由服务器执行。");
        callbacks.setVulCategory("RCE");
        callbacks.setVulDisclosureTime("2020-10");
        callbacks.setVulProduct("Tomcat");

        callbacks.registerPoc(new CVE_2017_12615_Poc());
        List<IExploit> exploitList = new ArrayList<IExploit>();
        exploitList.add(new CVE_2020_12615_UploadExploit());
        callbacks.registerExploit(exploitList);
    }
}
