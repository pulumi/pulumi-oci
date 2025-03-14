// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppArgs Empty = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppArgs();

    /**
     * (Updatable) The multicloud platform service URL which the application will invoke for runtime operations such as AWSCredentials api invocation
     * 
     * **Added In:** 2301202328
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="multicloudPlatformUrl")
    private @Nullable Output<String> multicloudPlatformUrl;

    /**
     * @return (Updatable) The multicloud platform service URL which the application will invoke for runtime operations such as AWSCredentials api invocation
     * 
     * **Added In:** 2301202328
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> multicloudPlatformUrl() {
        return Optional.ofNullable(this.multicloudPlatformUrl);
    }

    /**
     * (Updatable) Specifies the service type for which the application is configured for multicloud integration. For applicable external service types, app will invoke multicloud service for runtime operations
     * 
     * **Added In:** 2301202328
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="multicloudServiceType", required=true)
    private Output<String> multicloudServiceType;

    /**
     * @return (Updatable) Specifies the service type for which the application is configured for multicloud integration. For applicable external service types, app will invoke multicloud service for runtime operations
     * 
     * **Added In:** 2301202328
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<String> multicloudServiceType() {
        return this.multicloudServiceType;
    }

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppArgs() {}

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppArgs(DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppArgs $) {
        this.multicloudPlatformUrl = $.multicloudPlatformUrl;
        this.multicloudServiceType = $.multicloudServiceType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppArgs $;

        public Builder() {
            $ = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppArgs();
        }

        public Builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppArgs defaults) {
            $ = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param multicloudPlatformUrl (Updatable) The multicloud platform service URL which the application will invoke for runtime operations such as AWSCredentials api invocation
         * 
         * **Added In:** 2301202328
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: request
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder multicloudPlatformUrl(@Nullable Output<String> multicloudPlatformUrl) {
            $.multicloudPlatformUrl = multicloudPlatformUrl;
            return this;
        }

        /**
         * @param multicloudPlatformUrl (Updatable) The multicloud platform service URL which the application will invoke for runtime operations such as AWSCredentials api invocation
         * 
         * **Added In:** 2301202328
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: request
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder multicloudPlatformUrl(String multicloudPlatformUrl) {
            return multicloudPlatformUrl(Output.of(multicloudPlatformUrl));
        }

        /**
         * @param multicloudServiceType (Updatable) Specifies the service type for which the application is configured for multicloud integration. For applicable external service types, app will invoke multicloud service for runtime operations
         * 
         * **Added In:** 2301202328
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: immutable
         * * required: true
         * * returned: request
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder multicloudServiceType(Output<String> multicloudServiceType) {
            $.multicloudServiceType = multicloudServiceType;
            return this;
        }

        /**
         * @param multicloudServiceType (Updatable) Specifies the service type for which the application is configured for multicloud integration. For applicable external service types, app will invoke multicloud service for runtime operations
         * 
         * **Added In:** 2301202328
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: immutable
         * * required: true
         * * returned: request
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder multicloudServiceType(String multicloudServiceType) {
            return multicloudServiceType(Output.of(multicloudServiceType));
        }

        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppArgs build() {
            if ($.multicloudServiceType == null) {
                throw new MissingRequiredPropertyException("DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppArgs", "multicloudServiceType");
            }
            return $;
        }
    }

}
