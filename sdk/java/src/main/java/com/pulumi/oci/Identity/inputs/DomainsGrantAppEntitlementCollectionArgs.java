// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsGrantAppEntitlementCollectionArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsGrantAppEntitlementCollectionArgs Empty = new DomainsGrantAppEntitlementCollectionArgs();

    /**
     * (Updatable) The URI of the SCIM resource that represents the User or App who modified this Resource
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
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
     * @return (Updatable) The URI of the SCIM resource that represents the User or App who modified this Resource
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
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
     * Value of the tag.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="value", required=true)
    private Output<String> value;

    /**
     * @return Value of the tag.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<String> value() {
        return this.value;
    }

    private DomainsGrantAppEntitlementCollectionArgs() {}

    private DomainsGrantAppEntitlementCollectionArgs(DomainsGrantAppEntitlementCollectionArgs $) {
        this.ref = $.ref;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsGrantAppEntitlementCollectionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsGrantAppEntitlementCollectionArgs $;

        public Builder() {
            $ = new DomainsGrantAppEntitlementCollectionArgs();
        }

        public Builder(DomainsGrantAppEntitlementCollectionArgs defaults) {
            $ = new DomainsGrantAppEntitlementCollectionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param ref (Updatable) The URI of the SCIM resource that represents the User or App who modified this Resource
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
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
         * @param ref (Updatable) The URI of the SCIM resource that represents the User or App who modified this Resource
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
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
         * @param value Value of the tag.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder value(Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value Value of the tag.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public DomainsGrantAppEntitlementCollectionArgs build() {
            $.value = Objects.requireNonNull($.value, "expected parameter 'value' to be non-null");
            return $;
        }
    }

}