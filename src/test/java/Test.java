import net.dongliu.requests.Requests;

public class Test {
    public static void main(String[] args) {
        String url = "http://47.115.79.250:8500/"+"actuator/env";
        String response = Requests.get(url).verify(false).send().readToText();
        System.out.println(response);
    }
}
