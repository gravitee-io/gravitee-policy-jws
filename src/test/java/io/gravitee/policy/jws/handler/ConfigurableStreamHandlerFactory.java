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
package io.gravitee.policy.jws.handler;

import java.net.URL;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;
import java.util.HashMap;
import java.util.Map;

public class ConfigurableStreamHandlerFactory implements URLStreamHandlerFactory {

    private static ConfigurableStreamHandlerFactory instance;
    private final Map<String, URLStreamHandler> protocolHandlers;
    private boolean factorySet = false;

    private ConfigurableStreamHandlerFactory() {
        protocolHandlers = new HashMap<>();
    }

    public static synchronized ConfigurableStreamHandlerFactory getInstance(String protocol, URLStreamHandler urlHandler) {
        if (instance == null) {
            instance = new ConfigurableStreamHandlerFactory();
            instance.addHandler(protocol, urlHandler);
        }
        return instance;
    }

    private void addHandler(String protocol, URLStreamHandler urlHandler) {
        protocolHandlers.put(protocol, urlHandler);
    }

    public URLStreamHandler createURLStreamHandler(String protocol) {
        return protocolHandlers.get(protocol);
    }

    public void setURLStreamHandlerFactory() {
        // Prevent the URLStreamHandlerFactory from being set more than once and causing factory already defined exception
        if (factorySet) {
            return;
        }
        URL.setURLStreamHandlerFactory(this);
        factorySet = true;
    }
}
