package me.gv7.woodpecker.vuldb.weak_password;

import me.gv7.woodpecker.plugin.IExtenderCallbacks;
import me.gv7.woodpecker.plugin.IPlugin;
import me.gv7.woodpecker.plugin.IPluginHelper;
import me.gv7.woodpecker.vuldb.weak_password.poc.WeakPasswordCrackPoc;

public class WeakPasswordCrackPlugin implements IPlugin {
    public static IExtenderCallbacks callbacks;
    public static IPluginHelper pluginHelper;

    public void PluginMain(IExtenderCallbacks callbacks) {
        WeakPasswordCrackPlugin.callbacks = callbacks;
        WeakPasswordCrackPlugin.pluginHelper = callbacks.getPluginHelper();
        // 设置插件信息
        callbacks.setPluginName("Tomcat weak password crack plugin");
        callbacks.setPluginVersion("0.1.0");
        callbacks.setPluginAutor("c0ny1");
        // 设置漏洞信息
        callbacks.setVulName("Tomcat weark password");
        callbacks.setVulCVSS(9.8);
        callbacks.setVulSeverity("high");
        callbacks.setVulDescription("如果管理员配置的是弱口令，那么可以通过爆破方式拿到账号密码，进而登录Tomcat后台部署war，获取权限。");
        callbacks.setVulCategory("weark password");
        callbacks.setVulProduct("Tomcat");

        callbacks.registerPoc(new WeakPasswordCrackPoc());
    }
}
