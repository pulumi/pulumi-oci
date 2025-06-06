// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsApprovalWorkflowAssignmentIdcsLastModifiedBy {
    /**
     * @return The displayName of the User or App who modified this Resource
     * 
     */
    private String display;
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    private String ocid;
    /**
     * @return The URI of the SCIM resource that represents the User or App who modified this Resource
     * 
     */
    private String ref;
    /**
     * @return The type of resource, User or App, that modified this Resource
     * 
     */
    private String type;
    /**
     * @return Value of the tag.
     * 
     */
    private String value;

    private GetDomainsApprovalWorkflowAssignmentIdcsLastModifiedBy() {}
    /**
     * @return The displayName of the User or App who modified this Resource
     * 
     */
    public String display() {
        return this.display;
    }
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    public String ocid() {
        return this.ocid;
    }
    /**
     * @return The URI of the SCIM resource that represents the User or App who modified this Resource
     * 
     */
    public String ref() {
        return this.ref;
    }
    /**
     * @return The type of resource, User or App, that modified this Resource
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return Value of the tag.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsApprovalWorkflowAssignmentIdcsLastModifiedBy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String display;
        private String ocid;
        private String ref;
        private String type;
        private String value;
        public Builder() {}
        public Builder(GetDomainsApprovalWorkflowAssignmentIdcsLastModifiedBy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.display = defaults.display;
    	      this.ocid = defaults.ocid;
    	      this.ref = defaults.ref;
    	      this.type = defaults.type;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder display(String display) {
            if (display == null) {
              throw new MissingRequiredPropertyException("GetDomainsApprovalWorkflowAssignmentIdcsLastModifiedBy", "display");
            }
            this.display = display;
            return this;
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            if (ocid == null) {
              throw new MissingRequiredPropertyException("GetDomainsApprovalWorkflowAssignmentIdcsLastModifiedBy", "ocid");
            }
            this.ocid = ocid;
            return this;
        }
        @CustomType.Setter
        public Builder ref(String ref) {
            if (ref == null) {
              throw new MissingRequiredPropertyException("GetDomainsApprovalWorkflowAssignmentIdcsLastModifiedBy", "ref");
            }
            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetDomainsApprovalWorkflowAssignmentIdcsLastModifiedBy", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetDomainsApprovalWorkflowAssignmentIdcsLastModifiedBy", "value");
            }
            this.value = value;
            return this;
        }
        public GetDomainsApprovalWorkflowAssignmentIdcsLastModifiedBy build() {
            final var _resultValue = new GetDomainsApprovalWorkflowAssignmentIdcsLastModifiedBy();
            _resultValue.display = display;
            _resultValue.ocid = ocid;
            _resultValue.ref = ref;
            _resultValue.type = type;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
