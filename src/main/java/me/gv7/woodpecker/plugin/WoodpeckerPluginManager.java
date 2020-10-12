package me.gv7.woodpecker.plugin;

import me.gv7.woodpecker.vuldb.CVE_2017_12615.CVE_2017_12615_Plugin;
import me.gv7.woodpecker.vuldb.weak_password.WeakPasswordCrackPlugin;

public class WoodpeckerPluginManager implements IPluginManager {
    public void registerPluginManagerCallbacks(IPluginManagerCallbacks pluginManagerCallbacks) {
        pluginManagerCallbacks.registerPlugin(new WeakPasswordCrackPlugin());
        pluginManagerCallbacks.registerPlugin(new CVE_2017_12615_Plugin());
    }
}
