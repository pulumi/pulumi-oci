// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsCloudGateMappingUpstreamServerGroupArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsCloudGateMappingUpstreamServerGroupArgs Empty = new DomainsCloudGateMappingUpstreamServerGroupArgs();

    /**
     * (Updatable) The URI to the upstream block entry
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
    @Import(name="ref")
    private @Nullable Output<String> ref;

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
    public Optional<Output<String>> ref() {
        return Optional.ofNullable(this.ref);
    }

    /**
     * (Updatable) SSL flag for the Upstream Block
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
    @Import(name="ssl")
    private @Nullable Output<Boolean> ssl;

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
    public Optional<Output<Boolean>> ssl() {
        return Optional.ofNullable(this.ssl);
    }

    /**
     * (Updatable) The id of the upstream block entry.
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
    @Import(name="value")
    private @Nullable Output<String> value;

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
    public Optional<Output<String>> value() {
        return Optional.ofNullable(this.value);
    }

    private DomainsCloudGateMappingUpstreamServerGroupArgs() {}

    private DomainsCloudGateMappingUpstreamServerGroupArgs(DomainsCloudGateMappingUpstreamServerGroupArgs $) {
        this.ref = $.ref;
        this.ssl = $.ssl;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsCloudGateMappingUpstreamServerGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsCloudGateMappingUpstreamServerGroupArgs $;

        public Builder() {
            $ = new DomainsCloudGateMappingUpstreamServerGroupArgs();
        }

        public Builder(DomainsCloudGateMappingUpstreamServerGroupArgs defaults) {
            $ = new DomainsCloudGateMappingUpstreamServerGroupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param ref (Updatable) The URI to the upstream block entry
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
         * @return builder
         * 
         */
        public Builder ref(@Nullable Output<String> ref) {
            $.ref = ref;
            return this;
        }

        /**
         * @param ref (Updatable) The URI to the upstream block entry
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
         * @return builder
         * 
         */
        public Builder ref(String ref) {
            return ref(Output.of(ref));
        }

        /**
         * @param ssl (Updatable) SSL flag for the Upstream Block
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
         * @return builder
         * 
         */
        public Builder ssl(@Nullable Output<Boolean> ssl) {
            $.ssl = ssl;
            return this;
        }

        /**
         * @param ssl (Updatable) SSL flag for the Upstream Block
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
         * @return builder
         * 
         */
        public Builder ssl(Boolean ssl) {
            return ssl(Output.of(ssl));
        }

        /**
         * @param value (Updatable) The id of the upstream block entry.
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
         * @return builder
         * 
         */
        public Builder value(@Nullable Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) The id of the upstream block entry.
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
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public DomainsCloudGateMappingUpstreamServerGroupArgs build() {
            return $;
        }
    }

}
