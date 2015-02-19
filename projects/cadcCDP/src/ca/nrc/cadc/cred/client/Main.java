
package ca.nrc.cadc.cred.client;

import java.net.URI;
import java.net.URL;
import java.security.PrivilegedAction;
import java.security.cert.X509Certificate;

import javax.security.auth.Subject;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import ca.nrc.cadc.auth.CertCmdArgUtil;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.ArgumentMap;
import ca.nrc.cadc.util.Log4jInit;

public class Main implements PrivilegedAction<Boolean>
{
    private static Logger logger = Logger.getLogger(Main.class);

    public static final String ARG_HELP = "help";
    public static final String ARG_VERBOSE = "verbose";
    public static final String ARG_DEBUG = "debug";
    public static final String ARG_H = "h";
    public static final String ARG_V = "v";
    public static final String ARG_D = "d";
    public static final String ARG_VIEW_CMD = "view";
    public static final String ARG_DELEGATE_CMD = "delegate";
    public static final String ARG_VALID_DAYS = "daysvalid";

    // authenticated subject
    private static Subject subject;

    private String baseURL;
    private RegistryClient registryClient = new RegistryClient();
    private CredPublicClient client;

    private int daysValid;

    private static final int INIT_STATUS = 1; // exit code for
    // initialisation failure
    private static final int NET_STATUS = 2; // exit code for

    // client-server failures

    // Operations on Cred client
    public enum Operation {
        DELEGATE, VIEW
    };

    private Operation operation; // current operation on Cred client

    public static final String SERVICE_ID = "ivo://cadc.nrc.ca/cred";

    /**
     * Main class for accessing CDP
     * 
     * @param args
     */
    public static void main(String[] args)
    {
        ArgumentMap argMap = new ArgumentMap(args);

        if (argMap.isSet(ARG_HELP) || argMap.isSet(ARG_H))
        {
            usage();
            System.exit(0);
        }

        // Set debug mode
        if (argMap.isSet(ARG_DEBUG) || argMap.isSet(ARG_D))
        {
            Log4jInit.setLevel("ca.nrc.cadc.cred.client", Level.DEBUG);
        }
        else if (argMap.isSet(ARG_VERBOSE) || argMap.isSet(ARG_V))
        {
            Log4jInit.setLevel("ca.nrc.cadc.cred.client", Level.INFO);
        }
        else
            Log4jInit.setLevel("ca", Level.WARN);

        Main command = new Main();
        
        try
        {
            command.validateCommand(argMap);
        }
        catch (IllegalArgumentException ex)
        {
            msg("illegal argument(s): " + ex.getMessage());
            msg("");
            usage();
            System.exit(INIT_STATUS);
        }

        try
        {
            command.init(argMap);
            Subject.doAs(subject, command);
        }
        catch (Throwable t)
        {
            logger.error("unexpected failure", t);
            System.exit(NET_STATUS);
        }
        System.exit(0);

    }

    /**
     * Runs the task in Subject's context. Needed by the PrivilegedAction
     * interface
     * 
     * @return true if successfull, false otherwise
     */
    public Boolean run()
    {
        logger.info("run - START");
        if (this.operation.equals(Operation.DELEGATE))
        {
            doDelegate();
        }
        if (this.operation.equals(Operation.VIEW))
        {
            doView();
        }
        logger.info("run - DONE");
        return new Boolean(true);
    }

    /**
     * Executes delegate command
     */
    private void doDelegate()
    {
        try
        {
            client.delegate(null, daysValid);
            msg("Certificate updated");
        }
        catch (Exception e)
        {
e.printStackTrace();
            logger.error("failed to delegate");
            logger.error("reason: " + e.getMessage());
            System.exit(NET_STATUS);
        }

    }

    /**
     * Executes view command
     */
    private void doView()
    {
        try
        {
            X509Certificate[] certs = client.getCertificate(null);
            certs[0].checkValidity();
            msg("Found valid certificate");
            msg("Certificate Subject DN: "
                    + certs[0].getSubjectX500Principal().getName());
            msg("Certificate Expiry Date: " + certs[0].getNotAfter());
            msg("Certificate Details: " + certs[0].toString());
        }
        catch (Exception e)
        {
            logger.error("failed to delegate");
            logger.error("reason: " + e.getMessage());
            System.exit(NET_STATUS);
        }

    }

    /**
     * Validates the command line operations
     * 
     * @param argMap
     */
    private void validateCommand(ArgumentMap argMap)
            throws IllegalArgumentException
    {
        int numOp = 0;
        if (argMap.isSet(ARG_VIEW_CMD))
        {
            operation = Operation.VIEW;
            numOp++;
        }
        if (argMap.isSet(ARG_DELEGATE_CMD))
        {
            operation = Operation.DELEGATE;
            numOp++;
            String validDaysStr = argMap.getValue(ARG_VALID_DAYS);
            if (validDaysStr != null)
            {
                boolean valid = true;
                try
                {
                    daysValid = Integer.parseInt(validDaysStr);
                    if (daysValid < 1)
                    {
                        valid = false;
                    }
                }
                catch (NumberFormatException ex)
                {
                    valid = false;
                }
                if (valid == false)
                {
                    logger.error(ARG_VALID_DAYS
                            + " must be a positive integer value");
                    usage();
                    System.exit(INIT_STATUS);
                }
            }
            else
            {
                logger.error(ARG_VALID_DAYS
                        + " argument missing");
                usage();
                System.exit(INIT_STATUS);
            }
        }
        if (numOp != 1)
        {
            logger.error("Must specify one operation");
            usage();
            System.exit(INIT_STATUS);
        }

        return;
    }

    /**
     * Initializes of the base URL for the service
     * 
     * @param argMap
     */
    private void init(ArgumentMap argMap)
    {
        try
        {
            subject = CertCmdArgUtil.initSubject(argMap);
        }
        catch (Exception ex)
        {
            logger.error("failed to initialise SSL from certificates: "
                    + ex.getMessage());
            if (logger.getLevel() == Level.DEBUG)
            {
                ex.printStackTrace();
            }
            if (ex instanceof IllegalArgumentException)
            {
                usage();
            }
            System.exit(INIT_STATUS);
        }

        try
        {
            URL baseURL = registryClient.getServiceURL(
                    new URI(SERVICE_ID), "https");
            if (baseURL == null)
            {
                logger.error("failed to find service URL for "
                        + SERVICE_ID);
                System.exit(INIT_STATUS);
            }
            this.baseURL = baseURL.toString();
            this.client = new CredPublicClient(new URL(this.baseURL));
        }
        catch (Exception e)
        {
            logger.error("failed to find service URL for " + SERVICE_ID);
            logger.error("reason: " + e.getMessage());
            System.exit(INIT_STATUS);
        }

        logger.info("server uri: " + SERVICE_ID);
        logger.info("base url: " + this.baseURL);
    }

    /**
     * Formats the usage message.
     */
    public static void usage()
    {
        String[] um = {
                "Usage: java -jar cadcCDP.jar --view|(--delegate --daysvalid=<days>) [-v|--verbose|-d|--debug]",
                CertCmdArgUtil.getCertArgUsage(),
                "                                                                                                  ",
                "Help:                                                                                             ",
                "java -jar cadcCDP.jar <-h | --help>                                                        ",
                "                                                                                                  " };

        for (String line : um)
            msg(line);

    }

    // encapsulate all messages to console here
    private static void msg(String s)
    {
        System.out.println(s);
    }

}
