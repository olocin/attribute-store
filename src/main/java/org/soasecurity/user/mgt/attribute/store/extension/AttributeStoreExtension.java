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
import org.wso2.carbon.user.api.RealmConfiguration;
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
    public boolean doPreAuthenticate(String userName, Object credential,
                                     UserStoreManager userStoreManager) throws UserStoreException {

        // just log for testing
        log.info("doPreAuthenticate method is called before authenticating with user store");

        // check for attribute user store domains.
        String currentDomainName = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        
        log.info("doPreAuthenticate method...attribute user store domain: " + currentDomainName + ", username: " + userName);

        if(currentDomainName.endsWith(ATTRIBUTE_STORE_POST_PREFIX)){
        	log.warn("doPreAuthenticate method...this is Attribute User Store Domain, can not authenticate users");
            throw new UserStoreException("This is Attribute User Store Domain, Can not authenticate users");
        }

        return true;
    }

    @Override
    public boolean doPostGetUserClaimValues(String userName, String[] claims, String profileName,
                                Map<String, String> claimMap, UserStoreManager storeManager) throws UserStoreException {

        // just log for testing
        log.info("doPostGetUserClaimValues method is called after retrieving claim using underline user store");

        RealmConfiguration rc  = storeManager.getRealmConfiguration();
        
//        log.info("**************************************************");
//        log.info("realm user store class: " + rc.getUserStoreClass());
//        log.info("realm class name: " + rc.getRealmClassName());
//        log.info("user store property domain: " + rc.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME));
//        log.info(storeManager.toString());
//        log.info("**************************************************");
        
        String userDomainName =  UserCoreUtil.getDomainName(rc);
        String attributeStoreDomain =  userDomainName + ATTRIBUTE_STORE_POST_PREFIX;
        
        log.info("doPostGetUserClaimValues method...attribute user store: " + attributeStoreDomain + ", username: " + userName);
        log.info(String.format("doPostGetUserClaimValues method...claims (%s) for user [%s] and profile name [%s]", Arrays.toString(claims), userName, profileName));
        
        UserStoreManager userStoreManager = storeManager.getSecondaryUserStoreManager(attributeStoreDomain);
        
        
        if(userStoreManager != null) {

            Map<String, String> newClaimMap = userStoreManager.getUserClaimValues(userName, claims, profileName);
            
            log.info("doPostGetUserClaimValues method...adding claims");

            claimMap.putAll(newClaimMap);
        } else {
        	log.warn("doPostGetUserClaimValues method...attribute user store is null");
        }

        return true;
    }

}
