package example;

import java.net.InetAddress;

final class HiddenApi {
    Object hook() throws Exception {
        return InetAddress.class.getDeclaredField("impl");
    }
}
