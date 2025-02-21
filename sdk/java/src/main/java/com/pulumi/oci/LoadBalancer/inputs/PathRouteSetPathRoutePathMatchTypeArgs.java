// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class PathRouteSetPathRoutePathMatchTypeArgs extends com.pulumi.resources.ResourceArgs {

    public static final PathRouteSetPathRoutePathMatchTypeArgs Empty = new PathRouteSetPathRoutePathMatchTypeArgs();

    /**
     * (Updatable) Specifies how the load balancing service compares a [PathRoute](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/requests/PathRoute) object&#39;s `path` string against the incoming URI.
     * *  **EXACT_MATCH** - Looks for a `path` string that exactly matches the incoming URI path.
     * *  **FORCE_LONGEST_PREFIX_MATCH** - Looks for the `path` string with the best, longest match of the beginning portion of the incoming URI path.
     * *  **PREFIX_MATCH** - Looks for a `path` string that matches the beginning portion of the incoming URI path.
     * *  **SUFFIX_MATCH** - Looks for a `path` string that matches the ending portion of the incoming URI path.
     * 
     * For a full description of how the system handles `matchType` in a path route set containing multiple rules, see [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="matchType", required=true)
    private Output<String> matchType;

    /**
     * @return (Updatable) Specifies how the load balancing service compares a [PathRoute](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/requests/PathRoute) object&#39;s `path` string against the incoming URI.
     * *  **EXACT_MATCH** - Looks for a `path` string that exactly matches the incoming URI path.
     * *  **FORCE_LONGEST_PREFIX_MATCH** - Looks for the `path` string with the best, longest match of the beginning portion of the incoming URI path.
     * *  **PREFIX_MATCH** - Looks for a `path` string that matches the beginning portion of the incoming URI path.
     * *  **SUFFIX_MATCH** - Looks for a `path` string that matches the ending portion of the incoming URI path.
     * 
     * For a full description of how the system handles `matchType` in a path route set containing multiple rules, see [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> matchType() {
        return this.matchType;
    }

    private PathRouteSetPathRoutePathMatchTypeArgs() {}

    private PathRouteSetPathRoutePathMatchTypeArgs(PathRouteSetPathRoutePathMatchTypeArgs $) {
        this.matchType = $.matchType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PathRouteSetPathRoutePathMatchTypeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PathRouteSetPathRoutePathMatchTypeArgs $;

        public Builder() {
            $ = new PathRouteSetPathRoutePathMatchTypeArgs();
        }

        public Builder(PathRouteSetPathRoutePathMatchTypeArgs defaults) {
            $ = new PathRouteSetPathRoutePathMatchTypeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param matchType (Updatable) Specifies how the load balancing service compares a [PathRoute](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/requests/PathRoute) object&#39;s `path` string against the incoming URI.
         * *  **EXACT_MATCH** - Looks for a `path` string that exactly matches the incoming URI path.
         * *  **FORCE_LONGEST_PREFIX_MATCH** - Looks for the `path` string with the best, longest match of the beginning portion of the incoming URI path.
         * *  **PREFIX_MATCH** - Looks for a `path` string that matches the beginning portion of the incoming URI path.
         * *  **SUFFIX_MATCH** - Looks for a `path` string that matches the ending portion of the incoming URI path.
         * 
         * For a full description of how the system handles `matchType` in a path route set containing multiple rules, see [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm).
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder matchType(Output<String> matchType) {
            $.matchType = matchType;
            return this;
        }

        /**
         * @param matchType (Updatable) Specifies how the load balancing service compares a [PathRoute](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/requests/PathRoute) object&#39;s `path` string against the incoming URI.
         * *  **EXACT_MATCH** - Looks for a `path` string that exactly matches the incoming URI path.
         * *  **FORCE_LONGEST_PREFIX_MATCH** - Looks for the `path` string with the best, longest match of the beginning portion of the incoming URI path.
         * *  **PREFIX_MATCH** - Looks for a `path` string that matches the beginning portion of the incoming URI path.
         * *  **SUFFIX_MATCH** - Looks for a `path` string that matches the ending portion of the incoming URI path.
         * 
         * For a full description of how the system handles `matchType` in a path route set containing multiple rules, see [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm).
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder matchType(String matchType) {
            return matchType(Output.of(matchType));
        }

        public PathRouteSetPathRoutePathMatchTypeArgs build() {
            if ($.matchType == null) {
                throw new MissingRequiredPropertyException("PathRouteSetPathRoutePathMatchTypeArgs", "matchType");
            }
            return $;
        }
    }

}
