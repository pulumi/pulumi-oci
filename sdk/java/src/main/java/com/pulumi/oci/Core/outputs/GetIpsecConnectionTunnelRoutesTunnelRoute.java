// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetIpsecConnectionTunnelRoutesTunnelRoute {
    /**
     * @return Specifies the advertiser of the routes. If set to `ORACLE`, this returns only the routes advertised by Oracle. When set to `CUSTOMER`, this returns only the routes advertised by the CPE.
     * 
     */
    private String advertiser;
    /**
     * @return The age of the route.
     * 
     */
    private String age;
    /**
     * @return A list of ASNs in AS_Path.
     * 
     */
    private List<Integer> asPaths;
    /**
     * @return Indicates this is the best route.
     * 
     */
    private Boolean isBestPath;
    /**
     * @return The BGP network layer reachability information.
     * 
     */
    private String prefix;

    private GetIpsecConnectionTunnelRoutesTunnelRoute() {}
    /**
     * @return Specifies the advertiser of the routes. If set to `ORACLE`, this returns only the routes advertised by Oracle. When set to `CUSTOMER`, this returns only the routes advertised by the CPE.
     * 
     */
    public String advertiser() {
        return this.advertiser;
    }
    /**
     * @return The age of the route.
     * 
     */
    public String age() {
        return this.age;
    }
    /**
     * @return A list of ASNs in AS_Path.
     * 
     */
    public List<Integer> asPaths() {
        return this.asPaths;
    }
    /**
     * @return Indicates this is the best route.
     * 
     */
    public Boolean isBestPath() {
        return this.isBestPath;
    }
    /**
     * @return The BGP network layer reachability information.
     * 
     */
    public String prefix() {
        return this.prefix;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIpsecConnectionTunnelRoutesTunnelRoute defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String advertiser;
        private String age;
        private List<Integer> asPaths;
        private Boolean isBestPath;
        private String prefix;
        public Builder() {}
        public Builder(GetIpsecConnectionTunnelRoutesTunnelRoute defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.advertiser = defaults.advertiser;
    	      this.age = defaults.age;
    	      this.asPaths = defaults.asPaths;
    	      this.isBestPath = defaults.isBestPath;
    	      this.prefix = defaults.prefix;
        }

        @CustomType.Setter
        public Builder advertiser(String advertiser) {
            this.advertiser = Objects.requireNonNull(advertiser);
            return this;
        }
        @CustomType.Setter
        public Builder age(String age) {
            this.age = Objects.requireNonNull(age);
            return this;
        }
        @CustomType.Setter
        public Builder asPaths(List<Integer> asPaths) {
            this.asPaths = Objects.requireNonNull(asPaths);
            return this;
        }
        public Builder asPaths(Integer... asPaths) {
            return asPaths(List.of(asPaths));
        }
        @CustomType.Setter
        public Builder isBestPath(Boolean isBestPath) {
            this.isBestPath = Objects.requireNonNull(isBestPath);
            return this;
        }
        @CustomType.Setter
        public Builder prefix(String prefix) {
            this.prefix = Objects.requireNonNull(prefix);
            return this;
        }
        public GetIpsecConnectionTunnelRoutesTunnelRoute build() {
            final var o = new GetIpsecConnectionTunnelRoutesTunnelRoute();
            o.advertiser = advertiser;
            o.age = age;
            o.asPaths = asPaths;
            o.isBestPath = isBestPath;
            o.prefix = prefix;
            return o;
        }
    }
}