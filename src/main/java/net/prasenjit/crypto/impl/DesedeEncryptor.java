/*
 *    Copyright 2017 Prasenjit Purohit
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.prasenjit.crypto.impl;

import javax.crypto.SecretKey;

/**
 * Created by prase on 11-06-2017.
 *
 * @author prasenjit
 * @version $Id: $Id
 */
public class DesedeEncryptor extends AbstractSymmetricEncryptor {
    /**
     * <p>Constructor for DesedeEncryptor.</p>
     *
     * @param key a {@link javax.crypto.SecretKey} object.
     */
    public DesedeEncryptor(SecretKey key) {
        super(key, "DESede/CBC/PKCS5Padding");
    }
}
