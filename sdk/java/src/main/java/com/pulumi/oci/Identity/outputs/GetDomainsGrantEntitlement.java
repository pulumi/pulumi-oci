// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsGrantEntitlement {
    /**
     * @return The name of the attribute whose value (specified by attributeValue) confers privilege within the service-instance (specified by app).
     * 
     */
    private String attributeName;
    /**
     * @return The value of the attribute (specified by attributeName) that confers privilege within the service-instance (specified by app).  If attributeName is &#39;appRoles&#39;, then attributeValue is the ID of the AppRole.
     * 
     */
    private String attributeValue;

    private GetDomainsGrantEntitlement() {}
    /**
     * @return The name of the attribute whose value (specified by attributeValue) confers privilege within the service-instance (specified by app).
     * 
     */
    public String attributeName() {
        return this.attributeName;
    }
    /**
     * @return The value of the attribute (specified by attributeName) that confers privilege within the service-instance (specified by app).  If attributeName is &#39;appRoles&#39;, then attributeValue is the ID of the AppRole.
     * 
     */
    public String attributeValue() {
        return this.attributeValue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsGrantEntitlement defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String attributeName;
        private String attributeValue;
        public Builder() {}
        public Builder(GetDomainsGrantEntitlement defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attributeName = defaults.attributeName;
    	      this.attributeValue = defaults.attributeValue;
        }

        @CustomType.Setter
        public Builder attributeName(String attributeName) {
            this.attributeName = Objects.requireNonNull(attributeName);
            return this;
        }
        @CustomType.Setter
        public Builder attributeValue(String attributeValue) {
            this.attributeValue = Objects.requireNonNull(attributeValue);
            return this;
        }
        public GetDomainsGrantEntitlement build() {
            final var o = new GetDomainsGrantEntitlement();
            o.attributeName = attributeName;
            o.attributeValue = attributeValue;
            return o;
        }
    }
}