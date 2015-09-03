/**
 * Copyright 2015 DuraSpace, Inc.
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
package org.fcrepo.integration.auth.webac;

import static org.slf4j.LoggerFactory.getLogger;

import java.util.List;

import org.fcrepo.auth.roles.common.integration.RolesFadTestObjectBean;

import org.junit.Test;
import org.slf4j.Logger;

/**
 * @author whikloj
 */
public class BasicRolesAdminWebACIT extends WebACAbstractRolesIT {

    private static Logger LOGGER = getLogger(BasicRolesAdminWebACIT.class);

    /**
     * This test is good for running individually to find bootstrap problems with the delegate. All it does is build the
     * Fedora XACML environment.
     */
    @Test
    public void test() {
        LOGGER.debug("Spring startup was successfull.");
    }

    @Override
    protected List<RolesFadTestObjectBean> getTestObjs() {
        return test_objs;
    }

}
