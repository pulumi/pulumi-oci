// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsOciConsoleSignOnPolicyConsentsResourcePolicyResource {
    /**
     * @return Policy Resource Ocid
     * 
     */
    private String ocid;
    /**
     * @return Value of the tag.
     * 
     */
    private String value;

    private GetDomainsOciConsoleSignOnPolicyConsentsResourcePolicyResource() {}
    /**
     * @return Policy Resource Ocid
     * 
     */
    public String ocid() {
        return this.ocid;
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

    public static Builder builder(GetDomainsOciConsoleSignOnPolicyConsentsResourcePolicyResource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String ocid;
        private String value;
        public Builder() {}
        public Builder(GetDomainsOciConsoleSignOnPolicyConsentsResourcePolicyResource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ocid = defaults.ocid;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder ocid(String ocid) {
            if (ocid == null) {
              throw new MissingRequiredPropertyException("GetDomainsOciConsoleSignOnPolicyConsentsResourcePolicyResource", "ocid");
            }
            this.ocid = ocid;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetDomainsOciConsoleSignOnPolicyConsentsResourcePolicyResource", "value");
            }
            this.value = value;
            return this;
        }
        public GetDomainsOciConsoleSignOnPolicyConsentsResourcePolicyResource build() {
            final var _resultValue = new GetDomainsOciConsoleSignOnPolicyConsentsResourcePolicyResource();
            _resultValue.ocid = ocid;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
