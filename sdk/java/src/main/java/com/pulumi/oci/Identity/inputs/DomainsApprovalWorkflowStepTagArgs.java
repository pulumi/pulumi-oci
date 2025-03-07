// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class DomainsApprovalWorkflowStepTagArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsApprovalWorkflowStepTagArgs Empty = new DomainsApprovalWorkflowStepTagArgs();

    /**
     * Key or name of the tag.
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
    @Import(name="key", required=true)
    private Output<String> key;

    /**
     * @return Key or name of the tag.
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
    public Output<String> key() {
        return this.key;
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

    private DomainsApprovalWorkflowStepTagArgs() {}

    private DomainsApprovalWorkflowStepTagArgs(DomainsApprovalWorkflowStepTagArgs $) {
        this.key = $.key;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsApprovalWorkflowStepTagArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsApprovalWorkflowStepTagArgs $;

        public Builder() {
            $ = new DomainsApprovalWorkflowStepTagArgs();
        }

        public Builder(DomainsApprovalWorkflowStepTagArgs defaults) {
            $ = new DomainsApprovalWorkflowStepTagArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param key Key or name of the tag.
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
        public Builder key(Output<String> key) {
            $.key = key;
            return this;
        }

        /**
         * @param key Key or name of the tag.
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
        public Builder key(String key) {
            return key(Output.of(key));
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

        public DomainsApprovalWorkflowStepTagArgs build() {
            if ($.key == null) {
                throw new MissingRequiredPropertyException("DomainsApprovalWorkflowStepTagArgs", "key");
            }
            if ($.value == null) {
                throw new MissingRequiredPropertyException("DomainsApprovalWorkflowStepTagArgs", "value");
            }
            return $;
        }
    }

}
