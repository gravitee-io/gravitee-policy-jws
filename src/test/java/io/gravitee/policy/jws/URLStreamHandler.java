/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
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
package io.gravitee.policy.jws;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;

/** A {@link java.net.URLStreamHandler} that handles resources on the classpath. */
public class URLStreamHandler extends java.net.URLStreamHandler {

    /** The classloader to find resources from. */
    private final ClassLoader classLoader;

    public URLStreamHandler() {
        this.classLoader = getClass().getClassLoader();
    }

    @Override
    protected URLConnection openConnection(URL u) throws IOException {
        final URL resourceUrl = classLoader.getResource(u.getPath());
        return resourceUrl.openConnection();
    }
}
