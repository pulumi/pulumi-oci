// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.LoadBalancer.outputs.PathRouteSetPathRoutePathMatchType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class PathRouteSetPathRoute {
    /**
     * @return (Updatable) The name of the target backend set for requests where the incoming URI matches the specified path.  Example: `example_backend_set`
     * 
     */
    private final String backendSetName;
    /**
     * @return (Updatable) The path string to match against the incoming URI path.
     * *  Path strings are case-insensitive.
     * *  Asterisk (*) wildcards are not supported.
     * *  Regular expressions are not supported.
     * 
     */
    private final String path;
    /**
     * @return (Updatable) The type of matching to apply to incoming URIs.
     * 
     */
    private final PathRouteSetPathRoutePathMatchType pathMatchType;

    @CustomType.Constructor
    private PathRouteSetPathRoute(
        @CustomType.Parameter("backendSetName") String backendSetName,
        @CustomType.Parameter("path") String path,
        @CustomType.Parameter("pathMatchType") PathRouteSetPathRoutePathMatchType pathMatchType) {
        this.backendSetName = backendSetName;
        this.path = path;
        this.pathMatchType = pathMatchType;
    }

    /**
     * @return (Updatable) The name of the target backend set for requests where the incoming URI matches the specified path.  Example: `example_backend_set`
     * 
     */
    public String backendSetName() {
        return this.backendSetName;
    }
    /**
     * @return (Updatable) The path string to match against the incoming URI path.
     * *  Path strings are case-insensitive.
     * *  Asterisk (*) wildcards are not supported.
     * *  Regular expressions are not supported.
     * 
     */
    public String path() {
        return this.path;
    }
    /**
     * @return (Updatable) The type of matching to apply to incoming URIs.
     * 
     */
    public PathRouteSetPathRoutePathMatchType pathMatchType() {
        return this.pathMatchType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PathRouteSetPathRoute defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String backendSetName;
        private String path;
        private PathRouteSetPathRoutePathMatchType pathMatchType;

        public Builder() {
    	      // Empty
        }

        public Builder(PathRouteSetPathRoute defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backendSetName = defaults.backendSetName;
    	      this.path = defaults.path;
    	      this.pathMatchType = defaults.pathMatchType;
        }

        public Builder backendSetName(String backendSetName) {
            this.backendSetName = Objects.requireNonNull(backendSetName);
            return this;
        }
        public Builder path(String path) {
            this.path = Objects.requireNonNull(path);
            return this;
        }
        public Builder pathMatchType(PathRouteSetPathRoutePathMatchType pathMatchType) {
            this.pathMatchType = Objects.requireNonNull(pathMatchType);
            return this;
        }        public PathRouteSetPathRoute build() {
            return new PathRouteSetPathRoute(backendSetName, path, pathMatchType);
        }
    }
}
