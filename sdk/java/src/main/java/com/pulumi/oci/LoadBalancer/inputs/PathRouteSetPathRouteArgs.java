// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.LoadBalancer.inputs.PathRouteSetPathRoutePathMatchTypeArgs;
import java.lang.String;
import java.util.Objects;


public final class PathRouteSetPathRouteArgs extends com.pulumi.resources.ResourceArgs {

    public static final PathRouteSetPathRouteArgs Empty = new PathRouteSetPathRouteArgs();

    /**
     * (Updatable) The name of the target backend set for requests where the incoming URI matches the specified path.  Example: `example_backend_set`
     * 
     */
    @Import(name="backendSetName", required=true)
    private Output<String> backendSetName;

    /**
     * @return (Updatable) The name of the target backend set for requests where the incoming URI matches the specified path.  Example: `example_backend_set`
     * 
     */
    public Output<String> backendSetName() {
        return this.backendSetName;
    }

    /**
     * (Updatable) The path string to match against the incoming URI path.
     * *  Path strings are case-insensitive.
     * *  Asterisk (*) wildcards are not supported.
     * *  Regular expressions are not supported.
     * 
     */
    @Import(name="path", required=true)
    private Output<String> path;

    /**
     * @return (Updatable) The path string to match against the incoming URI path.
     * *  Path strings are case-insensitive.
     * *  Asterisk (*) wildcards are not supported.
     * *  Regular expressions are not supported.
     * 
     */
    public Output<String> path() {
        return this.path;
    }

    /**
     * (Updatable) The type of matching to apply to incoming URIs.
     * 
     */
    @Import(name="pathMatchType", required=true)
    private Output<PathRouteSetPathRoutePathMatchTypeArgs> pathMatchType;

    /**
     * @return (Updatable) The type of matching to apply to incoming URIs.
     * 
     */
    public Output<PathRouteSetPathRoutePathMatchTypeArgs> pathMatchType() {
        return this.pathMatchType;
    }

    private PathRouteSetPathRouteArgs() {}

    private PathRouteSetPathRouteArgs(PathRouteSetPathRouteArgs $) {
        this.backendSetName = $.backendSetName;
        this.path = $.path;
        this.pathMatchType = $.pathMatchType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PathRouteSetPathRouteArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PathRouteSetPathRouteArgs $;

        public Builder() {
            $ = new PathRouteSetPathRouteArgs();
        }

        public Builder(PathRouteSetPathRouteArgs defaults) {
            $ = new PathRouteSetPathRouteArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param backendSetName (Updatable) The name of the target backend set for requests where the incoming URI matches the specified path.  Example: `example_backend_set`
         * 
         * @return builder
         * 
         */
        public Builder backendSetName(Output<String> backendSetName) {
            $.backendSetName = backendSetName;
            return this;
        }

        /**
         * @param backendSetName (Updatable) The name of the target backend set for requests where the incoming URI matches the specified path.  Example: `example_backend_set`
         * 
         * @return builder
         * 
         */
        public Builder backendSetName(String backendSetName) {
            return backendSetName(Output.of(backendSetName));
        }

        /**
         * @param path (Updatable) The path string to match against the incoming URI path.
         * *  Path strings are case-insensitive.
         * *  Asterisk (*) wildcards are not supported.
         * *  Regular expressions are not supported.
         * 
         * @return builder
         * 
         */
        public Builder path(Output<String> path) {
            $.path = path;
            return this;
        }

        /**
         * @param path (Updatable) The path string to match against the incoming URI path.
         * *  Path strings are case-insensitive.
         * *  Asterisk (*) wildcards are not supported.
         * *  Regular expressions are not supported.
         * 
         * @return builder
         * 
         */
        public Builder path(String path) {
            return path(Output.of(path));
        }

        /**
         * @param pathMatchType (Updatable) The type of matching to apply to incoming URIs.
         * 
         * @return builder
         * 
         */
        public Builder pathMatchType(Output<PathRouteSetPathRoutePathMatchTypeArgs> pathMatchType) {
            $.pathMatchType = pathMatchType;
            return this;
        }

        /**
         * @param pathMatchType (Updatable) The type of matching to apply to incoming URIs.
         * 
         * @return builder
         * 
         */
        public Builder pathMatchType(PathRouteSetPathRoutePathMatchTypeArgs pathMatchType) {
            return pathMatchType(Output.of(pathMatchType));
        }

        public PathRouteSetPathRouteArgs build() {
            $.backendSetName = Objects.requireNonNull($.backendSetName, "expected parameter 'backendSetName' to be non-null");
            $.path = Objects.requireNonNull($.path, "expected parameter 'path' to be non-null");
            $.pathMatchType = Objects.requireNonNull($.pathMatchType, "expected parameter 'pathMatchType' to be non-null");
            return $;
        }
    }

}