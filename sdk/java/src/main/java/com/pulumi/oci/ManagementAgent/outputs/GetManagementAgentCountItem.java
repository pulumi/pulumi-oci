// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ManagementAgent.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ManagementAgent.outputs.GetManagementAgentCountItemDimension;
import java.lang.Integer;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagementAgentCountItem {
    /**
     * @return The number of Management Agents in this group
     * 
     */
    private Integer count;
    /**
     * @return The Aggregation of Management Agent Dimensions
     * 
     */
    private List<GetManagementAgentCountItemDimension> dimensions;

    private GetManagementAgentCountItem() {}
    /**
     * @return The number of Management Agents in this group
     * 
     */
    public Integer count() {
        return this.count;
    }
    /**
     * @return The Aggregation of Management Agent Dimensions
     * 
     */
    public List<GetManagementAgentCountItemDimension> dimensions() {
        return this.dimensions;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagementAgentCountItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer count;
        private List<GetManagementAgentCountItemDimension> dimensions;
        public Builder() {}
        public Builder(GetManagementAgentCountItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.count = defaults.count;
    	      this.dimensions = defaults.dimensions;
        }

        @CustomType.Setter
        public Builder count(Integer count) {
            this.count = Objects.requireNonNull(count);
            return this;
        }
        @CustomType.Setter
        public Builder dimensions(List<GetManagementAgentCountItemDimension> dimensions) {
            this.dimensions = Objects.requireNonNull(dimensions);
            return this;
        }
        public Builder dimensions(GetManagementAgentCountItemDimension... dimensions) {
            return dimensions(List.of(dimensions));
        }
        public GetManagementAgentCountItem build() {
            final var o = new GetManagementAgentCountItem();
            o.count = count;
            o.dimensions = dimensions;
            return o;
        }
    }
}