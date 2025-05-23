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
public final class DomainsCloudGateMappingUpstreamServerGroup {
    /**
     * @return (Updatable) The URI to the upstream block entry
     * 
     * **Added In:** 20.1.3
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
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
     * @return (Updatable) SSL flag for the Upstream Block
     * 
     * **Added In:** 20.1.3
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    private @Nullable Boolean ssl;
    /**
     * @return (Updatable) The id of the upstream block entry.
     * 
     * **Added In:** 20.1.3
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private @Nullable String value;

    private DomainsCloudGateMappingUpstreamServerGroup() {}
    /**
     * @return (Updatable) The URI to the upstream block entry
     * 
     * **Added In:** 20.1.3
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
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
     * @return (Updatable) SSL flag for the Upstream Block
     * 
     * **Added In:** 20.1.3
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Optional<Boolean> ssl() {
        return Optional.ofNullable(this.ssl);
    }
    /**
     * @return (Updatable) The id of the upstream block entry.
     * 
     * **Added In:** 20.1.3
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<String> value() {
        return Optional.ofNullable(this.value);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsCloudGateMappingUpstreamServerGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String ref;
        private @Nullable Boolean ssl;
        private @Nullable String value;
        public Builder() {}
        public Builder(DomainsCloudGateMappingUpstreamServerGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ref = defaults.ref;
    	      this.ssl = defaults.ssl;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder ref(@Nullable String ref) {

            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder ssl(@Nullable Boolean ssl) {

            this.ssl = ssl;
            return this;
        }
        @CustomType.Setter
        public Builder value(@Nullable String value) {

            this.value = value;
            return this;
        }
        public DomainsCloudGateMappingUpstreamServerGroup build() {
            final var _resultValue = new DomainsCloudGateMappingUpstreamServerGroup();
            _resultValue.ref = ref;
            _resultValue.ssl = ssl;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
