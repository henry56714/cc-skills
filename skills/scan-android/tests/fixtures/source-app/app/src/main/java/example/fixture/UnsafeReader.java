package example.fixture;

import java.io.FileInputStream;
import java.io.IOException;

final class UnsafeReader {
    int firstByte(String path) throws IOException {
        FileInputStream stream = new FileInputStream(path);
        return stream.read();
    }
}
