// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ClusterEndpointArgs extends com.pulumi.resources.ResourceArgs {

    public static final ClusterEndpointArgs Empty = new ClusterEndpointArgs();

    /**
     * The non-native networking Kubernetes API server endpoint.
     * 
     */
    @Import(name="kubernetes")
    private @Nullable Output<String> kubernetes;

    /**
     * @return The non-native networking Kubernetes API server endpoint.
     * 
     */
    public Optional<Output<String>> kubernetes() {
        return Optional.ofNullable(this.kubernetes);
    }

    /**
     * The private native networking Kubernetes API server endpoint.
     * 
     */
    @Import(name="privateEndpoint")
    private @Nullable Output<String> privateEndpoint;

    /**
     * @return The private native networking Kubernetes API server endpoint.
     * 
     */
    public Optional<Output<String>> privateEndpoint() {
        return Optional.ofNullable(this.privateEndpoint);
    }

    /**
     * The public native networking Kubernetes API server endpoint, if one was requested.
     * 
     */
    @Import(name="publicEndpoint")
    private @Nullable Output<String> publicEndpoint;

    /**
     * @return The public native networking Kubernetes API server endpoint, if one was requested.
     * 
     */
    public Optional<Output<String>> publicEndpoint() {
        return Optional.ofNullable(this.publicEndpoint);
    }

    /**
     * The FQDN assigned to the Kubernetes API private endpoint. Example: &#39;https://yourVcnHostnameEndpoint&#39;
     * 
     */
    @Import(name="vcnHostnameEndpoint")
    private @Nullable Output<String> vcnHostnameEndpoint;

    /**
     * @return The FQDN assigned to the Kubernetes API private endpoint. Example: &#39;https://yourVcnHostnameEndpoint&#39;
     * 
     */
    public Optional<Output<String>> vcnHostnameEndpoint() {
        return Optional.ofNullable(this.vcnHostnameEndpoint);
    }

    private ClusterEndpointArgs() {}

    private ClusterEndpointArgs(ClusterEndpointArgs $) {
        this.kubernetes = $.kubernetes;
        this.privateEndpoint = $.privateEndpoint;
        this.publicEndpoint = $.publicEndpoint;
        this.vcnHostnameEndpoint = $.vcnHostnameEndpoint;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ClusterEndpointArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ClusterEndpointArgs $;

        public Builder() {
            $ = new ClusterEndpointArgs();
        }

        public Builder(ClusterEndpointArgs defaults) {
            $ = new ClusterEndpointArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param kubernetes The non-native networking Kubernetes API server endpoint.
         * 
         * @return builder
         * 
         */
        public Builder kubernetes(@Nullable Output<String> kubernetes) {
            $.kubernetes = kubernetes;
            return this;
        }

        /**
         * @param kubernetes The non-native networking Kubernetes API server endpoint.
         * 
         * @return builder
         * 
         */
        public Builder kubernetes(String kubernetes) {
            return kubernetes(Output.of(kubernetes));
        }

        /**
         * @param privateEndpoint The private native networking Kubernetes API server endpoint.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpoint(@Nullable Output<String> privateEndpoint) {
            $.privateEndpoint = privateEndpoint;
            return this;
        }

        /**
         * @param privateEndpoint The private native networking Kubernetes API server endpoint.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpoint(String privateEndpoint) {
            return privateEndpoint(Output.of(privateEndpoint));
        }

        /**
         * @param publicEndpoint The public native networking Kubernetes API server endpoint, if one was requested.
         * 
         * @return builder
         * 
         */
        public Builder publicEndpoint(@Nullable Output<String> publicEndpoint) {
            $.publicEndpoint = publicEndpoint;
            return this;
        }

        /**
         * @param publicEndpoint The public native networking Kubernetes API server endpoint, if one was requested.
         * 
         * @return builder
         * 
         */
        public Builder publicEndpoint(String publicEndpoint) {
            return publicEndpoint(Output.of(publicEndpoint));
        }

        /**
         * @param vcnHostnameEndpoint The FQDN assigned to the Kubernetes API private endpoint. Example: &#39;https://yourVcnHostnameEndpoint&#39;
         * 
         * @return builder
         * 
         */
        public Builder vcnHostnameEndpoint(@Nullable Output<String> vcnHostnameEndpoint) {
            $.vcnHostnameEndpoint = vcnHostnameEndpoint;
            return this;
        }

        /**
         * @param vcnHostnameEndpoint The FQDN assigned to the Kubernetes API private endpoint. Example: &#39;https://yourVcnHostnameEndpoint&#39;
         * 
         * @return builder
         * 
         */
        public Builder vcnHostnameEndpoint(String vcnHostnameEndpoint) {
            return vcnHostnameEndpoint(Output.of(vcnHostnameEndpoint));
        }

        public ClusterEndpointArgs build() {
            return $;
        }
    }

}