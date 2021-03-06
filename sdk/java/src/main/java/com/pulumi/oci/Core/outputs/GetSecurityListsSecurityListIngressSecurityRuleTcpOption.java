// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetSecurityListsSecurityListIngressSecurityRuleTcpOptionSourcePortRange;
import java.lang.Integer;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSecurityListsSecurityListIngressSecurityRuleTcpOption {
    /**
     * @return The maximum port number. Must not be lower than the minimum port number. To specify a single port number, set both the min and max to the same value.
     * 
     */
    private final Integer max;
    /**
     * @return The minimum port number. Must not be greater than the maximum port number.
     * 
     */
    private final Integer min;
    private final List<GetSecurityListsSecurityListIngressSecurityRuleTcpOptionSourcePortRange> sourcePortRanges;

    @CustomType.Constructor
    private GetSecurityListsSecurityListIngressSecurityRuleTcpOption(
        @CustomType.Parameter("max") Integer max,
        @CustomType.Parameter("min") Integer min,
        @CustomType.Parameter("sourcePortRanges") List<GetSecurityListsSecurityListIngressSecurityRuleTcpOptionSourcePortRange> sourcePortRanges) {
        this.max = max;
        this.min = min;
        this.sourcePortRanges = sourcePortRanges;
    }

    /**
     * @return The maximum port number. Must not be lower than the minimum port number. To specify a single port number, set both the min and max to the same value.
     * 
     */
    public Integer max() {
        return this.max;
    }
    /**
     * @return The minimum port number. Must not be greater than the maximum port number.
     * 
     */
    public Integer min() {
        return this.min;
    }
    public List<GetSecurityListsSecurityListIngressSecurityRuleTcpOptionSourcePortRange> sourcePortRanges() {
        return this.sourcePortRanges;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSecurityListsSecurityListIngressSecurityRuleTcpOption defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Integer max;
        private Integer min;
        private List<GetSecurityListsSecurityListIngressSecurityRuleTcpOptionSourcePortRange> sourcePortRanges;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSecurityListsSecurityListIngressSecurityRuleTcpOption defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.max = defaults.max;
    	      this.min = defaults.min;
    	      this.sourcePortRanges = defaults.sourcePortRanges;
        }

        public Builder max(Integer max) {
            this.max = Objects.requireNonNull(max);
            return this;
        }
        public Builder min(Integer min) {
            this.min = Objects.requireNonNull(min);
            return this;
        }
        public Builder sourcePortRanges(List<GetSecurityListsSecurityListIngressSecurityRuleTcpOptionSourcePortRange> sourcePortRanges) {
            this.sourcePortRanges = Objects.requireNonNull(sourcePortRanges);
            return this;
        }
        public Builder sourcePortRanges(GetSecurityListsSecurityListIngressSecurityRuleTcpOptionSourcePortRange... sourcePortRanges) {
            return sourcePortRanges(List.of(sourcePortRanges));
        }        public GetSecurityListsSecurityListIngressSecurityRuleTcpOption build() {
            return new GetSecurityListsSecurityListIngressSecurityRuleTcpOption(max, min, sourcePortRanges);
        }
    }
}
