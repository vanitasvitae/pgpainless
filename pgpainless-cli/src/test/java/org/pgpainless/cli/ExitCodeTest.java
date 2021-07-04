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
package org.pgpainless.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class ExitCodeTest {

    @Test
    public void testUnknownCommand_69() {
        assertEquals(69, PGPainlessCLI.execute("generate-kex"));
    }

    @Test
    public void testCommandWithUnknownOption_37() {
        assertEquals(37, PGPainlessCLI.execute("generate-key", "-k", "\"k is unknown\""));
    }

    @Test
    public void successfulVersion_0 () {
        assertEquals(0, PGPainlessCLI.execute("version"));
    }
}
