// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetPathRouteSetsPathRouteSetPathRoutePathMatchType {
    /**
     * @return Specifies how the load balancing service compares a [PathRoute](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/requests/PathRoute) object&#39;s `path` string against the incoming URI.
     * *  **EXACT_MATCH** - Looks for a `path` string that exactly matches the incoming URI path.
     * *  **FORCE_LONGEST_PREFIX_MATCH** - Looks for the `path` string with the best, longest match of the beginning portion of the incoming URI path.
     * *  **PREFIX_MATCH** - Looks for a `path` string that matches the beginning portion of the incoming URI path.
     * *  **SUFFIX_MATCH** - Looks for a `path` string that matches the ending portion of the incoming URI path.
     * 
     */
    private String matchType;

    private GetPathRouteSetsPathRouteSetPathRoutePathMatchType() {}
    /**
     * @return Specifies how the load balancing service compares a [PathRoute](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/requests/PathRoute) object&#39;s `path` string against the incoming URI.
     * *  **EXACT_MATCH** - Looks for a `path` string that exactly matches the incoming URI path.
     * *  **FORCE_LONGEST_PREFIX_MATCH** - Looks for the `path` string with the best, longest match of the beginning portion of the incoming URI path.
     * *  **PREFIX_MATCH** - Looks for a `path` string that matches the beginning portion of the incoming URI path.
     * *  **SUFFIX_MATCH** - Looks for a `path` string that matches the ending portion of the incoming URI path.
     * 
     */
    public String matchType() {
        return this.matchType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPathRouteSetsPathRouteSetPathRoutePathMatchType defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String matchType;
        public Builder() {}
        public Builder(GetPathRouteSetsPathRouteSetPathRoutePathMatchType defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.matchType = defaults.matchType;
        }

        @CustomType.Setter
        public Builder matchType(String matchType) {
            if (matchType == null) {
              throw new MissingRequiredPropertyException("GetPathRouteSetsPathRouteSetPathRoutePathMatchType", "matchType");
            }
            this.matchType = matchType;
            return this;
        }
        public GetPathRouteSetsPathRouteSetPathRoutePathMatchType build() {
            final var _resultValue = new GetPathRouteSetsPathRouteSetPathRoutePathMatchType();
            _resultValue.matchType = matchType;
            return _resultValue;
        }
    }
}
