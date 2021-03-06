// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetIpsecConnectionTunnelRoutesFilter;
import com.pulumi.oci.Core.outputs.GetIpsecConnectionTunnelRoutesTunnelRoute;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetIpsecConnectionTunnelRoutesResult {
    /**
     * @return The source of the route advertisement.
     * 
     */
    private final @Nullable String advertiser;
    private final @Nullable List<GetIpsecConnectionTunnelRoutesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final String ipsecId;
    private final String tunnelId;
    /**
     * @return The list of tunnel_routes.
     * 
     */
    private final List<GetIpsecConnectionTunnelRoutesTunnelRoute> tunnelRoutes;

    @CustomType.Constructor
    private GetIpsecConnectionTunnelRoutesResult(
        @CustomType.Parameter("advertiser") @Nullable String advertiser,
        @CustomType.Parameter("filters") @Nullable List<GetIpsecConnectionTunnelRoutesFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("ipsecId") String ipsecId,
        @CustomType.Parameter("tunnelId") String tunnelId,
        @CustomType.Parameter("tunnelRoutes") List<GetIpsecConnectionTunnelRoutesTunnelRoute> tunnelRoutes) {
        this.advertiser = advertiser;
        this.filters = filters;
        this.id = id;
        this.ipsecId = ipsecId;
        this.tunnelId = tunnelId;
        this.tunnelRoutes = tunnelRoutes;
    }

    /**
     * @return The source of the route advertisement.
     * 
     */
    public Optional<String> advertiser() {
        return Optional.ofNullable(this.advertiser);
    }
    public List<GetIpsecConnectionTunnelRoutesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String ipsecId() {
        return this.ipsecId;
    }
    public String tunnelId() {
        return this.tunnelId;
    }
    /**
     * @return The list of tunnel_routes.
     * 
     */
    public List<GetIpsecConnectionTunnelRoutesTunnelRoute> tunnelRoutes() {
        return this.tunnelRoutes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIpsecConnectionTunnelRoutesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String advertiser;
        private @Nullable List<GetIpsecConnectionTunnelRoutesFilter> filters;
        private String id;
        private String ipsecId;
        private String tunnelId;
        private List<GetIpsecConnectionTunnelRoutesTunnelRoute> tunnelRoutes;

        public Builder() {
    	      // Empty
        }

        public Builder(GetIpsecConnectionTunnelRoutesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.advertiser = defaults.advertiser;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.ipsecId = defaults.ipsecId;
    	      this.tunnelId = defaults.tunnelId;
    	      this.tunnelRoutes = defaults.tunnelRoutes;
        }

        public Builder advertiser(@Nullable String advertiser) {
            this.advertiser = advertiser;
            return this;
        }
        public Builder filters(@Nullable List<GetIpsecConnectionTunnelRoutesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetIpsecConnectionTunnelRoutesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder ipsecId(String ipsecId) {
            this.ipsecId = Objects.requireNonNull(ipsecId);
            return this;
        }
        public Builder tunnelId(String tunnelId) {
            this.tunnelId = Objects.requireNonNull(tunnelId);
            return this;
        }
        public Builder tunnelRoutes(List<GetIpsecConnectionTunnelRoutesTunnelRoute> tunnelRoutes) {
            this.tunnelRoutes = Objects.requireNonNull(tunnelRoutes);
            return this;
        }
        public Builder tunnelRoutes(GetIpsecConnectionTunnelRoutesTunnelRoute... tunnelRoutes) {
            return tunnelRoutes(List.of(tunnelRoutes));
        }        public GetIpsecConnectionTunnelRoutesResult build() {
            return new GetIpsecConnectionTunnelRoutesResult(advertiser, filters, id, ipsecId, tunnelId, tunnelRoutes);
        }
    }
}
