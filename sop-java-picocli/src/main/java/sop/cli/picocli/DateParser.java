/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
            Print.errln("Invalid date string supplied as value of --not-after.");
            Print.trace(e);
            System.exit(1);
            return null;
        }
    }

    public static Date parseNotBefore(String notBefore) {
        try {
            return notBefore.equals("now") ? new Date() : notBefore.equals("-") ? beginningOfTime : df.parse(notBefore);
        } catch (ParseException e) {
            Print.errln("Invalid date string supplied as value of --not-before.");
            Print.trace(e);
            System.exit(1);
            return null;
        }
    }
}
