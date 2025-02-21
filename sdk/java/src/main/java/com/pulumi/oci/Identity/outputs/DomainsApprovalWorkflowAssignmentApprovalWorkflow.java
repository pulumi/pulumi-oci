// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsApprovalWorkflowAssignmentApprovalWorkflow {
    /**
     * @return (Updatable) Display name of the approval workflow
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String display;
    /**
     * @return Unique Oracle Cloud Infrastructure Identifier of the approval workflow
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
     */
    private @Nullable String ocid;
    /**
     * @return (Updatable) URI of the approval workflow
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: reference
     * * uniqueness: none
     * 
     */
    private @Nullable String ref;
    /**
     * @return Indicates type of the entity that is associated with this assignment (for ARM validation)
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * idcsDefaultValue: ApprovalWorkflow
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    private String type;
    /**
     * @return Identifier of the approval workflow
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    private String value;

    private DomainsApprovalWorkflowAssignmentApprovalWorkflow() {}
    /**
     * @return (Updatable) Display name of the approval workflow
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> display() {
        return Optional.ofNullable(this.display);
    }
    /**
     * @return Unique Oracle Cloud Infrastructure Identifier of the approval workflow
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
     */
    public Optional<String> ocid() {
        return Optional.ofNullable(this.ocid);
    }
    /**
     * @return (Updatable) URI of the approval workflow
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: reference
     * * uniqueness: none
     * 
     */
    public Optional<String> ref() {
        return Optional.ofNullable(this.ref);
    }
    /**
     * @return Indicates type of the entity that is associated with this assignment (for ARM validation)
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * idcsDefaultValue: ApprovalWorkflow
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return Identifier of the approval workflow
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsApprovalWorkflowAssignmentApprovalWorkflow defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String display;
        private @Nullable String ocid;
        private @Nullable String ref;
        private String type;
        private String value;
        public Builder() {}
        public Builder(DomainsApprovalWorkflowAssignmentApprovalWorkflow defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.display = defaults.display;
    	      this.ocid = defaults.ocid;
    	      this.ref = defaults.ref;
    	      this.type = defaults.type;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder display(@Nullable String display) {

            this.display = display;
            return this;
        }
        @CustomType.Setter
        public Builder ocid(@Nullable String ocid) {

            this.ocid = ocid;
            return this;
        }
        @CustomType.Setter
        public Builder ref(@Nullable String ref) {

            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("DomainsApprovalWorkflowAssignmentApprovalWorkflow", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("DomainsApprovalWorkflowAssignmentApprovalWorkflow", "value");
            }
            this.value = value;
            return this;
        }
        public DomainsApprovalWorkflowAssignmentApprovalWorkflow build() {
            final var _resultValue = new DomainsApprovalWorkflowAssignmentApprovalWorkflow();
            _resultValue.display = display;
            _resultValue.ocid = ocid;
            _resultValue.ref = ref;
            _resultValue.type = type;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
