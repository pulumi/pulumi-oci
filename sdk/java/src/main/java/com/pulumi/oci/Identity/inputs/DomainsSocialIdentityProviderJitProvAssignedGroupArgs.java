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


public final class DomainsSocialIdentityProviderJitProvAssignedGroupArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsSocialIdentityProviderJitProvAssignedGroupArgs Empty = new DomainsSocialIdentityProviderJitProvAssignedGroupArgs();

    /**
     * (Updatable) A human readable name, primarily used for display purposes. READ-ONLY.
     * 
     * **Added In:** 2309290043
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="display")
    private @Nullable Output<String> display;

    /**
     * @return (Updatable) A human readable name, primarily used for display purposes. READ-ONLY.
     * 
     * **Added In:** 2309290043
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> display() {
        return Optional.ofNullable(this.display);
    }

    @Import(name="ref")
    private @Nullable Output<String> ref;

    public Optional<Output<String>> ref() {
        return Optional.ofNullable(this.ref);
    }

    /**
     * (Updatable) Group identifier
     * 
     * **Added In:** 2309290043
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
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
     * @return (Updatable) Group identifier
     * 
     * **Added In:** 2309290043
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
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

    private DomainsSocialIdentityProviderJitProvAssignedGroupArgs() {}

    private DomainsSocialIdentityProviderJitProvAssignedGroupArgs(DomainsSocialIdentityProviderJitProvAssignedGroupArgs $) {
        this.display = $.display;
        this.ref = $.ref;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsSocialIdentityProviderJitProvAssignedGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsSocialIdentityProviderJitProvAssignedGroupArgs $;

        public Builder() {
            $ = new DomainsSocialIdentityProviderJitProvAssignedGroupArgs();
        }

        public Builder(DomainsSocialIdentityProviderJitProvAssignedGroupArgs defaults) {
            $ = new DomainsSocialIdentityProviderJitProvAssignedGroupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param display (Updatable) A human readable name, primarily used for display purposes. READ-ONLY.
         * 
         * **Added In:** 2309290043
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: request
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder display(@Nullable Output<String> display) {
            $.display = display;
            return this;
        }

        /**
         * @param display (Updatable) A human readable name, primarily used for display purposes. READ-ONLY.
         * 
         * **Added In:** 2309290043
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: request
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder display(String display) {
            return display(Output.of(display));
        }

        public Builder ref(@Nullable Output<String> ref) {
            $.ref = ref;
            return this;
        }

        public Builder ref(String ref) {
            return ref(Output.of(ref));
        }

        /**
         * @param value (Updatable) Group identifier
         * 
         * **Added In:** 2309290043
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
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
         * @param value (Updatable) Group identifier
         * 
         * **Added In:** 2309290043
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
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

        public DomainsSocialIdentityProviderJitProvAssignedGroupArgs build() {
            if ($.value == null) {
                throw new MissingRequiredPropertyException("DomainsSocialIdentityProviderJitProvAssignedGroupArgs", "value");
            }
            return $;
        }
    }

}
