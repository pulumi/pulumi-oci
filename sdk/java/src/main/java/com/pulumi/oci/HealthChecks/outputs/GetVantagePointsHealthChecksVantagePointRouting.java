// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.HealthChecks.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetVantagePointsHealthChecksVantagePointRouting {
    /**
     * @return The registry label for `asn`, usually the name of the organization that owns the ASN. May be omitted or null.
     * 
     */
    private String asLabel;
    /**
     * @return The Autonomous System Number (ASN) identifying the organization responsible for routing packets to `prefix`.
     * 
     */
    private Integer asn;
    /**
     * @return An IP prefix (CIDR syntax) that is less specific than `address`, through which `address` is routed.
     * 
     */
    private String prefix;
    /**
     * @return An integer between 0 and 100 used to select between multiple origin ASNs when routing to `prefix`. Most prefixes have exactly one origin ASN, in which case `weight` will be 100.
     * 
     */
    private Integer weight;

    private GetVantagePointsHealthChecksVantagePointRouting() {}
    /**
     * @return The registry label for `asn`, usually the name of the organization that owns the ASN. May be omitted or null.
     * 
     */
    public String asLabel() {
        return this.asLabel;
    }
    /**
     * @return The Autonomous System Number (ASN) identifying the organization responsible for routing packets to `prefix`.
     * 
     */
    public Integer asn() {
        return this.asn;
    }
    /**
     * @return An IP prefix (CIDR syntax) that is less specific than `address`, through which `address` is routed.
     * 
     */
    public String prefix() {
        return this.prefix;
    }
    /**
     * @return An integer between 0 and 100 used to select between multiple origin ASNs when routing to `prefix`. Most prefixes have exactly one origin ASN, in which case `weight` will be 100.
     * 
     */
    public Integer weight() {
        return this.weight;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVantagePointsHealthChecksVantagePointRouting defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String asLabel;
        private Integer asn;
        private String prefix;
        private Integer weight;
        public Builder() {}
        public Builder(GetVantagePointsHealthChecksVantagePointRouting defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.asLabel = defaults.asLabel;
    	      this.asn = defaults.asn;
    	      this.prefix = defaults.prefix;
    	      this.weight = defaults.weight;
        }

        @CustomType.Setter
        public Builder asLabel(String asLabel) {
            this.asLabel = Objects.requireNonNull(asLabel);
            return this;
        }
        @CustomType.Setter
        public Builder asn(Integer asn) {
            this.asn = Objects.requireNonNull(asn);
            return this;
        }
        @CustomType.Setter
        public Builder prefix(String prefix) {
            this.prefix = Objects.requireNonNull(prefix);
            return this;
        }
        @CustomType.Setter
        public Builder weight(Integer weight) {
            this.weight = Objects.requireNonNull(weight);
            return this;
        }
        public GetVantagePointsHealthChecksVantagePointRouting build() {
            final var o = new GetVantagePointsHealthChecksVantagePointRouting();
            o.asLabel = asLabel;
            o.asn = asn;
            o.prefix = prefix;
            o.weight = weight;
            return o;
        }
    }
}