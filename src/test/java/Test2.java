
import me.gv7.woodpecker.requests.Requests;

import java.util.HashMap;
import java.util.Map;

public class Test2 {

    public static void main(String[] args) {
        String vulURL = "http://china-fisc.org:80/fqz//mnt/nassa/shouye/homeimage/201021/2010211211005920.txt";
        Map<String,String> headerMap = new HashMap<String,String>();
        headerMap.put("Cache-Control","max-age=0");
        headerMap.put("Upgrade-Insecure-Requests","1");
        headerMap.put("User-Agent","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.80 Safari/537.36");
        headerMap.put("Accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
        headerMap.put("Accept-Encoding","gzip, deflate");
        headerMap.put("Accept-Language","zh-CN,zh;q=0.9,en;q=0.8");
        headerMap.put("Connection","close");
        headerMap.put("Content-Type","application/x-www-form-urlencoded");
        headerMap.put("Content-Length","0");
        String reqBody = "adsd=\"wwewe\"";
        Requests.post(vulURL).body(reqBody).headers(headerMap).send();
    }
}
