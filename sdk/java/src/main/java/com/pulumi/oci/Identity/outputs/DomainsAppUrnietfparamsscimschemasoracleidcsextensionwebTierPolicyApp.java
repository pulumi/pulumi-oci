// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsAppUrnietfparamsscimschemasoracleidcsextensionwebTierPolicyApp {
    /**
     * @return (Updatable) If this Attribute is true, resource ref id and resource ref name attributes will we included in wtp json response.
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    private @Nullable Boolean resourceRef;
    /**
     * @return (Updatable) Webtier policy AZ Control
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String webTierPolicyAzControl;
    /**
     * @return (Updatable) Store the web tier policy for an application as a string in Javascript Object Notification (JSON) format.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String webTierPolicyJson;

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionwebTierPolicyApp() {}
    /**
     * @return (Updatable) If this Attribute is true, resource ref id and resource ref name attributes will we included in wtp json response.
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Optional<Boolean> resourceRef() {
        return Optional.ofNullable(this.resourceRef);
    }
    /**
     * @return (Updatable) Webtier policy AZ Control
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> webTierPolicyAzControl() {
        return Optional.ofNullable(this.webTierPolicyAzControl);
    }
    /**
     * @return (Updatable) Store the web tier policy for an application as a string in Javascript Object Notification (JSON) format.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> webTierPolicyJson() {
        return Optional.ofNullable(this.webTierPolicyJson);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionwebTierPolicyApp defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean resourceRef;
        private @Nullable String webTierPolicyAzControl;
        private @Nullable String webTierPolicyJson;
        public Builder() {}
        public Builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionwebTierPolicyApp defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.resourceRef = defaults.resourceRef;
    	      this.webTierPolicyAzControl = defaults.webTierPolicyAzControl;
    	      this.webTierPolicyJson = defaults.webTierPolicyJson;
        }

        @CustomType.Setter
        public Builder resourceRef(@Nullable Boolean resourceRef) {
            this.resourceRef = resourceRef;
            return this;
        }
        @CustomType.Setter
        public Builder webTierPolicyAzControl(@Nullable String webTierPolicyAzControl) {
            this.webTierPolicyAzControl = webTierPolicyAzControl;
            return this;
        }
        @CustomType.Setter
        public Builder webTierPolicyJson(@Nullable String webTierPolicyJson) {
            this.webTierPolicyJson = webTierPolicyJson;
            return this;
        }
        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionwebTierPolicyApp build() {
            final var o = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionwebTierPolicyApp();
            o.resourceRef = resourceRef;
            o.webTierPolicyAzControl = webTierPolicyAzControl;
            o.webTierPolicyJson = webTierPolicyJson;
            return o;
        }
    }
}