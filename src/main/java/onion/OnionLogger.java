package onion;

import java.util.logging.Level;
import java.util.logging.Logger;

public class OnionLogger {

    static public void setup() {

        // get the global logger to configure it
        Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

        logger.setLevel(Level.ALL);
    }
}