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


package org.soasecurity.user.mgt.attribute.store.extension;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.soasecurity.user.mgt.attribute.store.extension.internal.AttributeStoreExtensionServiceComponent;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserOperationEventListener;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Arrays;
import java.util.Map;

/**
 *
 */
public class AttributeStoreExtension extends AbstractUserOperationEventListener {

    private static Log log = LogFactory.getLog(AttributeStoreExtension.class);

    /**
     * If there is user store domain name with following post prefix, It would be identified as attribute store
     */
    private static final String ATTRIBUTE_STORE_POST_PREFIX = "-ATTRIBUTE-STORE";

    @Override
    public int getExecutionOrderId() {
        return 986732;
    }

    @Override
    public boolean doPostGetUserClaimValues(String userName, String[] claims, String profileName,
                                Map<String, String> claimMap, UserStoreManager storeManager) throws UserStoreException {

        // just log for testing
        log.debug("doPostGetUserClaimValues method is called after retrieving claim using underline user store");

        String userDomainName =  UserCoreUtil.getDomainName(storeManager.getRealmConfiguration());
        if(userDomainName.endsWith(ATTRIBUTE_STORE_POST_PREFIX)){
        	// the user store is an attribute user store, exit
        	return true;
        }
        String attributeStoreDomain =  userDomainName + ATTRIBUTE_STORE_POST_PREFIX;
        
        log.debug(String.format("doPostGetUserClaimValues method...getting claims [%s] for user [%s] and profile name [%s] in attribute user store [%s]", Arrays.toString(claims), userName, profileName, attributeStoreDomain));
        
        // get user store manager for related attribute user store
        UserStoreManager userStoreManager = AttributeStoreExtensionServiceComponent.getRealmService().getBootstrapRealm().getUserStoreManager().getSecondaryUserStoreManager(attributeStoreDomain);
        
        if(userStoreManager != null) {
        	if(userStoreManager.isExistingUser(userName)) {
        		log.debug("doPostGetUserClaimValues method...adding claims");
	            Map<String, String> newClaimMap = userStoreManager.getUserClaimValues(userName, claims, profileName);
	            if(newClaimMap != null) {
	            	claimMap.putAll(newClaimMap);
	            } else {
	            	log.debug(String.format("doPostGetUserClaimValues method...claims map is null for user [%s] in attribute user store [%s]", userName, attributeStoreDomain));
				}
        	} else {
        		log.debug(String.format("doPostGetUserClaimValues method...user [%s] does not exist in attribute user store [%s]", userName, attributeStoreDomain));
        	}
        } else {
        	log.debug(String.format("doPostGetUserClaimValues method...attribute user store [%s] is null", attributeStoreDomain));
        }
        return true;
    }
}
