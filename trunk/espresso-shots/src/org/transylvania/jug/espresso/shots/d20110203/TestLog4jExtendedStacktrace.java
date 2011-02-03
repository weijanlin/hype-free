package org.transylvania.jug.espresso.shots.d20110203;

import org.junit.*;
import static org.junit.Assert.*;
import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.regex.*;

import org.apache.log4j.*;
import org.apache.log4j.spi.Filter;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.ThrowableInformation;

public class TestLog4jExtendedStacktrace {
    private StringWriter logOutput;
    private Logger logger;
    
    @Test
    public void testSimpleException() {
        logger.info("test");
        assertTrue(logOutput.toString().contains("test"));
    }
    
    @Test
    public void testAugmentedStackTrace() {
        try {
            new Caller().call();
        }
        catch (Exception ex) {
            logger.error("An exception has occurred!", ex);
        }
        
        assertTrue(logOutput.toString().contains("java.lang.IllegalArgumentException: Test exception"));
        assertTrue(logOutput.toString().contains("\tat org.transylvania.jug.espresso.shots.d20110203.TestLog4jExtendedStacktrace$Callee.called"));
        assertTrue(logOutput.toString().contains("\tat org.transylvania.jug.espresso.shots.d20110203.TestLog4jExtendedStacktrace$Caller.call"));
        
        assertTrue(logOutput.toString().contains("org.transylvania.jug.espresso.shots.d20110203.TestLog4jExtendedStacktrace$Callee: " + Callee.VCS_VERSION));
        assertTrue(logOutput.toString().contains("org.transylvania.jug.espresso.shots.d20110203.TestLog4jExtendedStacktrace$Caller: " + Caller.VCS_VERSION));
    }

    private static void addAugmentationFilter() {
        Logger root = Logger.getRootLogger();
        @SuppressWarnings("unchecked")
        Enumeration<Appender> appenders =  root.getAllAppenders();
        while (appenders.hasMoreElements()) {
            appenders.nextElement().addFilter(new VersionAugmenterFilter());
        }
    }
    
    @Before
    public void SetUp() {
        logOutput = new StringWriter();
        
        Logger root = Logger.getRootLogger();
        root.removeAllAppenders();
        root.setLevel(Level.INFO);
        root.addAppender(new WriterAppender(new PatternLayout("%d{ABSOLUTE} %-5p [%t] [%c{1}] %m%n"), logOutput));
        addAugmentationFilter();

        logger = root.getLoggerRepository().getLogger(TestLog4jExtendedStacktrace.class.getCanonicalName());
    }
    
    static class VersionAugmenterFilter extends Filter {
        private static final Field throwableInfo = getThrowableInfoField();
        
        public int decide(LoggingEvent event) {
            if (null == event.getThrowableInformation()) { return Filter.NEUTRAL; }
            try {
                throwableInfo.set(event, new VersionAugmentorThrowableInformation( event.getThrowableInformation().getThrowable() ));
            }
            catch (Exception e) { }
            return Filter.NEUTRAL;
        }

        private static Field getThrowableInfoField() {
            try {
                Field result = LoggingEvent.class.getDeclaredField("throwableInfo");
                result.setAccessible(true);
                return result;
            }
            catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }
    }
    
    static class VersionAugmentorThrowableInformation extends ThrowableInformation {
        private static final long serialVersionUID = -4572801007059393120L;
        private final static Pattern stackLine = Pattern.compile("\\tat (.*?)\\.[^\\.]+\\(");

        public VersionAugmentorThrowableInformation(Throwable throwable) {
            super(throwable);
        }
        
        public VersionAugmentorThrowableInformation(Throwable throwable, Category category) {
            super(throwable, category);
        }
        
        @Override
        public String[] getThrowableStrRep() {
            ArrayList<String> result = new ArrayList<String>();
            SortedSet<String> augmentations = new TreeSet<String>();
            
            for (String line: super.getThrowableStrRep()) {
                result.add(line);
                Matcher m = stackLine.matcher(line);
                if (!m.find()) { continue; }
                
                String className = m.group(1);
                try {
                    Class<?> clazz = Class.forName(className);
                    Field field = clazz.getDeclaredField("VCS_VERSION");
                    augmentations.add(className + ": " + field.get(null));
                }
                catch (Exception e) { }
            }
            
            if (!augmentations.isEmpty()) {
                result.add("");
                result.addAll(augmentations);
            }
            
            return result.toArray(new String[result.size()]);
        }
        
    }
    
    static class Caller {
        public final static String VCS_VERSION = "$Revision$";
        
        private final Callee callee = new Callee();
        
        void call() {
            callee.called();
        }
    }
    
    static class Callee {
        public final static String VCS_VERSION = "$Revision$";
        
        void called() {
            throw new IllegalArgumentException("Test exception");
        }
    }
}
