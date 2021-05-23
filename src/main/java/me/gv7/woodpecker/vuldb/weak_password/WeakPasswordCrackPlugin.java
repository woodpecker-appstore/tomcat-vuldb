package me.gv7.woodpecker.vuldb.weak_password;

import me.gv7.woodpecker.plugin.IExploit;
import me.gv7.woodpecker.plugin.IPluginHelper;
import me.gv7.woodpecker.plugin.IVulPlugin;
import me.gv7.woodpecker.plugin.IVulPluginCallbacks;
import me.gv7.woodpecker.vuldb.weak_password.exploit.WeakPasswordCrack;
import me.gv7.woodpecker.vuldb.weak_password.poc.WeakPasswordCrackPoc;

import java.util.ArrayList;
import java.util.List;

public class WeakPasswordCrackPlugin implements IVulPlugin {
    public static IVulPluginCallbacks callbacks;
    public static IPluginHelper pluginHelper;

    public void VulPluginMain(IVulPluginCallbacks callbacks) {
        WeakPasswordCrackPlugin.callbacks = callbacks;
        WeakPasswordCrackPlugin.pluginHelper = callbacks.getPluginHelper();
        // 设置插件信息
        callbacks.setVulPluginName("Tomcat weak password crack plugin");
        callbacks.setVulPluginVersion("0.2.0");
        callbacks.setVulPluginAuthor("woodpecker-org");
        // 设置漏洞信息
        callbacks.setVulName("Tomcat weark password");
        callbacks.setVulCVSS(9.8);
        callbacks.setVulSeverity("high");
        callbacks.setVulDescription("如果管理员配置的是弱口令，那么可以通过爆破方式拿到账号密码，进而登录Tomcat后台部署war，获取权限。");
        callbacks.setVulCategory("weark password");
        callbacks.setVulProduct("Tomcat");
        callbacks.setVulDisclosureTime("2020-11-11");

        callbacks.registerPoc(new WeakPasswordCrackPoc());
        List<IExploit> exploitList = new ArrayList<>();
        exploitList.add(new WeakPasswordCrack());
        callbacks.registerExploit(exploitList);
    }
}
