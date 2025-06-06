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


public final class DomainsApprovalWorkflowAssignmentIdcsLastModifiedByArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsApprovalWorkflowAssignmentIdcsLastModifiedByArgs Empty = new DomainsApprovalWorkflowAssignmentIdcsLastModifiedByArgs();

    /**
     * The displayName of the User or App who modified this Resource
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="display")
    private @Nullable Output<String> display;

    /**
     * @return The displayName of the User or App who modified this Resource
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> display() {
        return Optional.ofNullable(this.display);
    }

    /**
     * The OCID of the SCIM resource that represents the User or App who modified this Resource
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="ocid")
    private @Nullable Output<String> ocid;

    /**
     * @return The OCID of the SCIM resource that represents the User or App who modified this Resource
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> ocid() {
        return Optional.ofNullable(this.ocid);
    }

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
     * The type of resource, User or App, that modified this Resource
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return The type of resource, User or App, that modified this Resource
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    /**
     * The ID of the SCIM resource that represents the User or App who modified this Resource
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="value", required=true)
    private Output<String> value;

    /**
     * @return The ID of the SCIM resource that represents the User or App who modified this Resource
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<String> value() {
        return this.value;
    }

    private DomainsApprovalWorkflowAssignmentIdcsLastModifiedByArgs() {}

    private DomainsApprovalWorkflowAssignmentIdcsLastModifiedByArgs(DomainsApprovalWorkflowAssignmentIdcsLastModifiedByArgs $) {
        this.display = $.display;
        this.ocid = $.ocid;
        this.ref = $.ref;
        this.type = $.type;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsApprovalWorkflowAssignmentIdcsLastModifiedByArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsApprovalWorkflowAssignmentIdcsLastModifiedByArgs $;

        public Builder() {
            $ = new DomainsApprovalWorkflowAssignmentIdcsLastModifiedByArgs();
        }

        public Builder(DomainsApprovalWorkflowAssignmentIdcsLastModifiedByArgs defaults) {
            $ = new DomainsApprovalWorkflowAssignmentIdcsLastModifiedByArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param display The displayName of the User or App who modified this Resource
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
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
         * @param display The displayName of the User or App who modified this Resource
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder display(String display) {
            return display(Output.of(display));
        }

        /**
         * @param ocid The OCID of the SCIM resource that represents the User or App who modified this Resource
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readOnly
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder ocid(@Nullable Output<String> ocid) {
            $.ocid = ocid;
            return this;
        }

        /**
         * @param ocid The OCID of the SCIM resource that represents the User or App who modified this Resource
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readOnly
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder ocid(String ocid) {
            return ocid(Output.of(ocid));
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
         * @param type The type of resource, User or App, that modified this Resource
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type The type of resource, User or App, that modified this Resource
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param value The ID of the SCIM resource that represents the User or App who modified this Resource
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readOnly
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
         * @param value The ID of the SCIM resource that represents the User or App who modified this Resource
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readOnly
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

        public DomainsApprovalWorkflowAssignmentIdcsLastModifiedByArgs build() {
            if ($.value == null) {
                throw new MissingRequiredPropertyException("DomainsApprovalWorkflowAssignmentIdcsLastModifiedByArgs", "value");
            }
            return $;
        }
    }

}
