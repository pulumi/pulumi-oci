// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetClusterPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetClusterPlainArgs Empty = new GetClusterPlainArgs();

    /**
     * The OCID of the cluster.
     * 
     */
    @Import(name="clusterId", required=true)
    private String clusterId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public String clusterId() {
        return this.clusterId;
    }

    /**
     * Boolean value to determine if the OpenIdConnectAuth configuration file should be displayed for the provided cluster.
     * 
     */
    @Import(name="shouldIncludeOidcConfigFile")
    private @Nullable Boolean shouldIncludeOidcConfigFile;

    /**
     * @return Boolean value to determine if the OpenIdConnectAuth configuration file should be displayed for the provided cluster.
     * 
     */
    public Optional<Boolean> shouldIncludeOidcConfigFile() {
        return Optional.ofNullable(this.shouldIncludeOidcConfigFile);
    }

    private GetClusterPlainArgs() {}

    private GetClusterPlainArgs(GetClusterPlainArgs $) {
        this.clusterId = $.clusterId;
        this.shouldIncludeOidcConfigFile = $.shouldIncludeOidcConfigFile;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetClusterPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetClusterPlainArgs $;

        public Builder() {
            $ = new GetClusterPlainArgs();
        }

        public Builder(GetClusterPlainArgs defaults) {
            $ = new GetClusterPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param clusterId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder clusterId(String clusterId) {
            $.clusterId = clusterId;
            return this;
        }

        /**
         * @param shouldIncludeOidcConfigFile Boolean value to determine if the OpenIdConnectAuth configuration file should be displayed for the provided cluster.
         * 
         * @return builder
         * 
         */
        public Builder shouldIncludeOidcConfigFile(@Nullable Boolean shouldIncludeOidcConfigFile) {
            $.shouldIncludeOidcConfigFile = shouldIncludeOidcConfigFile;
            return this;
        }

        public GetClusterPlainArgs build() {
            if ($.clusterId == null) {
                throw new MissingRequiredPropertyException("GetClusterPlainArgs", "clusterId");
            }
            return $;
        }
    }

}
