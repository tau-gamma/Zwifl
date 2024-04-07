package onion.api;


import java.io.IOException;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.StreamHandler;

import org.apache.commons.cli.CommandLine;

import onion.OnionLogger;
import util.Program;
import util.config.CliParser;

public class Main extends Program {

    private String configFilePath;
    
    private static final Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

    Main() {
        super("api.onion", "Onion API by Daniel Bertagnolli and Alex Micheli");
        SimpleFormatter fmt = new SimpleFormatter();
        StreamHandler sh = new StreamHandler(System.out, fmt);
        OnionLogger.setup();
    }

    @Override
    protected void parseCommandLine(CommandLine cli, CliParser parser) {
    	configFilePath = parser.getConfigFilename("onion.conf");
    }

    @Override
    protected void run() {
    	OnionAPInterface server = null;
		try {
			server = new OnionAPInterface(configFilePath);
		} catch (Exception e1) {
			logger.warning("Something went wrong. Please check that all arguments are correct: " + e1.getMessage());
			System.exit(1);
		}
		try {
			server.start();
		} catch (Exception e) {
			logger.warning("Something went wrong. Shutting down Onion API: " + e.getMessage());
			System.exit(1);
		}
    }

    @Override
    protected void cleanup() {
    }
    
    public static void main(String args[]) throws IOException {
        new Main().start(args);
    }

}
