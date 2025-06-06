// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsOciConsoleSignOnPolicyConsentModifiedResource {
    /**
     * @return Policy Resource Ocid
     * 
     */
    private String ocid;
    /**
     * @return The Modified Resource type - Policy, Rule, ConditionGroup, or Condition. A label that indicates the resource type.
     * 
     */
    private String type;
    /**
     * @return Value of the tag.
     * 
     */
    private String value;

    private GetDomainsOciConsoleSignOnPolicyConsentModifiedResource() {}
    /**
     * @return Policy Resource Ocid
     * 
     */
    public String ocid() {
        return this.ocid;
    }
    /**
     * @return The Modified Resource type - Policy, Rule, ConditionGroup, or Condition. A label that indicates the resource type.
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

    public static Builder builder(GetDomainsOciConsoleSignOnPolicyConsentModifiedResource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String ocid;
        private String type;
        private String value;
        public Builder() {}
        public Builder(GetDomainsOciConsoleSignOnPolicyConsentModifiedResource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ocid = defaults.ocid;
    	      this.type = defaults.type;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder ocid(String ocid) {
            if (ocid == null) {
              throw new MissingRequiredPropertyException("GetDomainsOciConsoleSignOnPolicyConsentModifiedResource", "ocid");
            }
            this.ocid = ocid;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetDomainsOciConsoleSignOnPolicyConsentModifiedResource", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetDomainsOciConsoleSignOnPolicyConsentModifiedResource", "value");
            }
            this.value = value;
            return this;
        }
        public GetDomainsOciConsoleSignOnPolicyConsentModifiedResource build() {
            final var _resultValue = new GetDomainsOciConsoleSignOnPolicyConsentModifiedResource();
            _resultValue.ocid = ocid;
            _resultValue.type = type;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
