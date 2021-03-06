// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetWebAppFirewallPolicyActionBody {
    /**
     * @return Static response body text.
     * 
     */
    private final String text;
    /**
     * @return Type of WebAppFirewallPolicyRule.
     * 
     */
    private final String type;

    @CustomType.Constructor
    private GetWebAppFirewallPolicyActionBody(
        @CustomType.Parameter("text") String text,
        @CustomType.Parameter("type") String type) {
        this.text = text;
        this.type = type;
    }

    /**
     * @return Static response body text.
     * 
     */
    public String text() {
        return this.text;
    }
    /**
     * @return Type of WebAppFirewallPolicyRule.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWebAppFirewallPolicyActionBody defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String text;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(GetWebAppFirewallPolicyActionBody defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.text = defaults.text;
    	      this.type = defaults.type;
        }

        public Builder text(String text) {
            this.text = Objects.requireNonNull(text);
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public GetWebAppFirewallPolicyActionBody build() {
            return new GetWebAppFirewallPolicyActionBody(text, type);
        }
    }
}
