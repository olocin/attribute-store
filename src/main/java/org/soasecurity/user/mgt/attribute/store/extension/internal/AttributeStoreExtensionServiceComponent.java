/*
 * Copyright (c)  WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.soasecurity.user.mgt.attribute.store.extension.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.soasecurity.user.mgt.attribute.store.extension.AttributeStoreExtension;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * 
 * @scr.component name="org.soasecurity.user.mgt.attribute.store.extension.internal.AttributeStoreExtensionServiceComponent"
 * immediate="true"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */

public class AttributeStoreExtensionServiceComponent {

    private static Log log = LogFactory.getLog(AttributeStoreExtensionServiceComponent.class);

	@SuppressWarnings({ "rawtypes", "unused" })
	private ServiceRegistration serviceRegistration = null;

    private static RealmService realmService;

    /**
     * activate
     * @param context
     */
    protected void activate(ComponentContext context) {

        AttributeStoreExtension listener = new AttributeStoreExtension();
        serviceRegistration =
                context.getBundleContext().registerService(UserOperationEventListener.class.getName(),
                        listener, null);

        log.info("My Custom bundle is activated");
    }

    /**
     * deactivate
     * @param context
     */
    protected void deactivate(ComponentContext context) {
        log.info("My Custom bundle is de-activated");
    }

    /**
     * sets realm service
     * @param realmService <code>RealmService</code>
     */
    protected void setRealmService(RealmService realmService) {

        log.info("DefaultUserRealm set in Custom Extension bundle");
        AttributeStoreExtensionServiceComponent.realmService = realmService;
    }

    /**
     * un-sets realm service
     * @param realmService  <code>RealmService</code>
     */
    protected void unsetRealmService(RealmService realmService) {

        log.info("DefaultUserRealm unset in Custom Extension bundle");
        AttributeStoreExtensionServiceComponent.realmService = null;
    }

    /**
     *
     * @return
     */
    public static RealmService getRealmService() {
        return realmService;
    }
}
