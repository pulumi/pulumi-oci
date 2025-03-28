// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsPoliciesPolicyPolicyType {
    /**
     * @return Rule URI
     * 
     */
    private String ref;
    /**
     * @return Value of the tag.
     * 
     */
    private String value;

    private GetDomainsPoliciesPolicyPolicyType() {}
    /**
     * @return Rule URI
     * 
     */
    public String ref() {
        return this.ref;
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

    public static Builder builder(GetDomainsPoliciesPolicyPolicyType defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String ref;
        private String value;
        public Builder() {}
        public Builder(GetDomainsPoliciesPolicyPolicyType defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ref = defaults.ref;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder ref(String ref) {
            if (ref == null) {
              throw new MissingRequiredPropertyException("GetDomainsPoliciesPolicyPolicyType", "ref");
            }
            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetDomainsPoliciesPolicyPolicyType", "value");
            }
            this.value = value;
            return this;
        }
        public GetDomainsPoliciesPolicyPolicyType build() {
            final var _resultValue = new GetDomainsPoliciesPolicyPolicyType();
            _resultValue.ref = ref;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
