// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsDynamicResourceGroupGrant {
    /**
     * @return (Updatable) App identifier
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsAddedSinceVersion: 3
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String appId;
    /**
     * @return (Updatable) Each value of grantMechanism indicates how (or by what component) some App (or App-Entitlement) was granted. A customer or the UI should use only grantMechanism values that start with &#39;ADMINISTRATOR&#39;:
     * * &#39;ADMINISTRATOR_TO_USER&#39; is for a direct grant to a specific User.
     * * &#39;ADMINISTRATOR_TO_GROUP&#39; is for a grant to a specific Group, which results in indirect grants to Users who are members of that Group.
     * * &#39;ADMINISTRATOR_TO_APP&#39; is for a grant to a specific App.  The grantee (client) App gains access to the granted (server) App.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsAddedSinceVersion: 3
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String grantMechanism;
    /**
     * @return (Updatable) Grant URI
     * 
     * **SCIM++ Properties:**
     * * idcsAddedSinceVersion: 3
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    private @Nullable String ref;
    /**
     * @return (Updatable) Grant identifier
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsAddedSinceVersion: 3
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String value;

    private DomainsDynamicResourceGroupGrant() {}
    /**
     * @return (Updatable) App identifier
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsAddedSinceVersion: 3
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> appId() {
        return Optional.ofNullable(this.appId);
    }
    /**
     * @return (Updatable) Each value of grantMechanism indicates how (or by what component) some App (or App-Entitlement) was granted. A customer or the UI should use only grantMechanism values that start with &#39;ADMINISTRATOR&#39;:
     * * &#39;ADMINISTRATOR_TO_USER&#39; is for a direct grant to a specific User.
     * * &#39;ADMINISTRATOR_TO_GROUP&#39; is for a grant to a specific Group, which results in indirect grants to Users who are members of that Group.
     * * &#39;ADMINISTRATOR_TO_APP&#39; is for a grant to a specific App.  The grantee (client) App gains access to the granted (server) App.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsAddedSinceVersion: 3
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> grantMechanism() {
        return Optional.ofNullable(this.grantMechanism);
    }
    /**
     * @return (Updatable) Grant URI
     * 
     * **SCIM++ Properties:**
     * * idcsAddedSinceVersion: 3
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    public Optional<String> ref() {
        return Optional.ofNullable(this.ref);
    }
    /**
     * @return (Updatable) Grant identifier
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsAddedSinceVersion: 3
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> value() {
        return Optional.ofNullable(this.value);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsDynamicResourceGroupGrant defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String appId;
        private @Nullable String grantMechanism;
        private @Nullable String ref;
        private @Nullable String value;
        public Builder() {}
        public Builder(DomainsDynamicResourceGroupGrant defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.appId = defaults.appId;
    	      this.grantMechanism = defaults.grantMechanism;
    	      this.ref = defaults.ref;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder appId(@Nullable String appId) {

            this.appId = appId;
            return this;
        }
        @CustomType.Setter
        public Builder grantMechanism(@Nullable String grantMechanism) {

            this.grantMechanism = grantMechanism;
            return this;
        }
        @CustomType.Setter
        public Builder ref(@Nullable String ref) {

            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder value(@Nullable String value) {

            this.value = value;
            return this;
        }
        public DomainsDynamicResourceGroupGrant build() {
            final var _resultValue = new DomainsDynamicResourceGroupGrant();
            _resultValue.appId = appId;
            _resultValue.grantMechanism = grantMechanism;
            _resultValue.ref = ref;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
