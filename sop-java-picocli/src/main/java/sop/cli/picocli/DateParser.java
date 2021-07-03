package sop.cli.picocli;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class DateParser {

    private static final TimeZone tz = TimeZone.getTimeZone("UTC");
    private static final DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'");

    private static final Date beginningOfTime = new Date(0);
    private static final Date endOfTime = new Date(8640000000000000L);

    static {
        df.setTimeZone(tz);
    }

    public static Date parseNotAfter(String notAfter) {
        try {
            return notAfter.equals("now") ? new Date() : notAfter.equals("-") ? endOfTime : df.parse(notAfter);
        } catch (ParseException e) {
            System.err.println("Invalid date string supplied as value of --not-after.");
            e.printStackTrace();
            System.exit(1);
            return null;
        }
    }

    public static Date parseNotBefore(String notBefore) {
        try {
            return notBefore.equals("now") ? new Date() : notBefore.equals("-") ? beginningOfTime : df.parse(notBefore);
        } catch (ParseException e) {
            System.err.println("Invalid date string supplied as value of --not-before.");
            e.printStackTrace();
            System.exit(1);
            return null;
        }
    }
}
