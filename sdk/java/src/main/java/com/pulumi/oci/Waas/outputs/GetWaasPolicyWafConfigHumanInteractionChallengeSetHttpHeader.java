// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetWaasPolicyWafConfigHumanInteractionChallengeSetHttpHeader {
    /**
     * @return The unique name of the whitelist.
     * 
     */
    private String name;
    /**
     * @return The value of the header.
     * 
     */
    private String value;

    private GetWaasPolicyWafConfigHumanInteractionChallengeSetHttpHeader() {}
    /**
     * @return The unique name of the whitelist.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The value of the header.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWaasPolicyWafConfigHumanInteractionChallengeSetHttpHeader defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private String value;
        public Builder() {}
        public Builder(GetWaasPolicyWafConfigHumanInteractionChallengeSetHttpHeader defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetWaasPolicyWafConfigHumanInteractionChallengeSetHttpHeader", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetWaasPolicyWafConfigHumanInteractionChallengeSetHttpHeader", "value");
            }
            this.value = value;
            return this;
        }
        public GetWaasPolicyWafConfigHumanInteractionChallengeSetHttpHeader build() {
            final var _resultValue = new GetWaasPolicyWafConfigHumanInteractionChallengeSetHttpHeader();
            _resultValue.name = name;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
