package me.gv7.woodpecker.vuldb.CVE_2020_1938;

import me.gv7.woodpecker.plugin.IExploit;
import me.gv7.woodpecker.plugin.IPluginHelper;
import me.gv7.woodpecker.plugin.IVulPlugin;
import me.gv7.woodpecker.plugin.IVulPluginCallbacks;
import me.gv7.woodpecker.vuldb.CVE_2020_1938.exploit.CVE_2020_1938_CustomExploit;
import me.gv7.woodpecker.vuldb.CVE_2020_1938.exploit.CVE_2020_1938_ExeCodeExploit;
import me.gv7.woodpecker.vuldb.CVE_2020_1938.poc.CVE_2020_1938_Poc;

import java.util.ArrayList;
import java.util.List;

public class CVE_2020_1938_Plugin implements IVulPlugin {
    public static IVulPluginCallbacks callbacks;
    public static IPluginHelper pluginHelper;

    public void VulPluginMain(IVulPluginCallbacks callbacks) {
        CVE_2020_1938_Plugin.callbacks = callbacks;
        CVE_2020_1938_Plugin.pluginHelper = callbacks.getPluginHelper();
        // 设置插件信息
        callbacks.setVulPluginName("Tomcat CVE-2020-1938 plugin");
        callbacks.setVulPluginVersion("0.1.0");
        callbacks.setVulPluginAuthor("c0ny1");
        // 设置漏洞信息
        callbacks.setVulName("Tomcat AJP LFI");
        callbacks.setVulId("CVE-2020-1938");
        callbacks.setVulCVSS(8.1);
        callbacks.setVulAuthor("iswin");
        callbacks.setVulSeverity("high");
        callbacks.setVulScope("Apache Tomcat 6\n" +
                "Apache Tomcat 7 < 7.0.100\n" +
                "Apache Tomcat 8 < 8.5.51\n" +
                "Apache Tomcat 9 < 9.0.31");
        callbacks.setVulDescription("");
        callbacks.setVulCategory("LFI");
        callbacks.setVulDisclosureTime("2020-10");
        callbacks.setVulProduct("Tomcat");

        callbacks.registerPoc(new CVE_2020_1938_Poc());
        List<IExploit> exploitList = new ArrayList<IExploit>();
        exploitList.add(new CVE_2020_1938_CustomExploit());
        exploitList.add(new CVE_2020_1938_ExeCodeExploit());
        callbacks.registerExploit(exploitList);
    }
}
