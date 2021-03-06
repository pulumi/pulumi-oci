// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waas.outputs.GetEdgeSubnetsEdgeSubnet;
import com.pulumi.oci.Waas.outputs.GetEdgeSubnetsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetEdgeSubnetsResult {
    /**
     * @return The list of edge_subnets.
     * 
     */
    private final List<GetEdgeSubnetsEdgeSubnet> edgeSubnets;
    private final @Nullable List<GetEdgeSubnetsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;

    @CustomType.Constructor
    private GetEdgeSubnetsResult(
        @CustomType.Parameter("edgeSubnets") List<GetEdgeSubnetsEdgeSubnet> edgeSubnets,
        @CustomType.Parameter("filters") @Nullable List<GetEdgeSubnetsFilter> filters,
        @CustomType.Parameter("id") String id) {
        this.edgeSubnets = edgeSubnets;
        this.filters = filters;
        this.id = id;
    }

    /**
     * @return The list of edge_subnets.
     * 
     */
    public List<GetEdgeSubnetsEdgeSubnet> edgeSubnets() {
        return this.edgeSubnets;
    }
    public List<GetEdgeSubnetsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetEdgeSubnetsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetEdgeSubnetsEdgeSubnet> edgeSubnets;
        private @Nullable List<GetEdgeSubnetsFilter> filters;
        private String id;

        public Builder() {
    	      // Empty
        }

        public Builder(GetEdgeSubnetsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.edgeSubnets = defaults.edgeSubnets;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        public Builder edgeSubnets(List<GetEdgeSubnetsEdgeSubnet> edgeSubnets) {
            this.edgeSubnets = Objects.requireNonNull(edgeSubnets);
            return this;
        }
        public Builder edgeSubnets(GetEdgeSubnetsEdgeSubnet... edgeSubnets) {
            return edgeSubnets(List.of(edgeSubnets));
        }
        public Builder filters(@Nullable List<GetEdgeSubnetsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetEdgeSubnetsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }        public GetEdgeSubnetsResult build() {
            return new GetEdgeSubnetsResult(edgeSubnets, filters, id);
        }
    }
}
