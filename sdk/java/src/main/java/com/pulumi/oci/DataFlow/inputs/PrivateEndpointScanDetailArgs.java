// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PrivateEndpointScanDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final PrivateEndpointScanDetailArgs Empty = new PrivateEndpointScanDetailArgs();

    /**
     * (Updatable) A fully-qualified domain name (FQDN).
     * 
     */
    @Import(name="fqdn")
    private @Nullable Output<String> fqdn;

    /**
     * @return (Updatable) A fully-qualified domain name (FQDN).
     * 
     */
    public Optional<Output<String>> fqdn() {
        return Optional.ofNullable(this.fqdn);
    }

    /**
     * (Updatable) The port number of the FQDN
     * 
     */
    @Import(name="port")
    private @Nullable Output<String> port;

    /**
     * @return (Updatable) The port number of the FQDN
     * 
     */
    public Optional<Output<String>> port() {
        return Optional.ofNullable(this.port);
    }

    private PrivateEndpointScanDetailArgs() {}

    private PrivateEndpointScanDetailArgs(PrivateEndpointScanDetailArgs $) {
        this.fqdn = $.fqdn;
        this.port = $.port;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PrivateEndpointScanDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PrivateEndpointScanDetailArgs $;

        public Builder() {
            $ = new PrivateEndpointScanDetailArgs();
        }

        public Builder(PrivateEndpointScanDetailArgs defaults) {
            $ = new PrivateEndpointScanDetailArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param fqdn (Updatable) A fully-qualified domain name (FQDN).
         * 
         * @return builder
         * 
         */
        public Builder fqdn(@Nullable Output<String> fqdn) {
            $.fqdn = fqdn;
            return this;
        }

        /**
         * @param fqdn (Updatable) A fully-qualified domain name (FQDN).
         * 
         * @return builder
         * 
         */
        public Builder fqdn(String fqdn) {
            return fqdn(Output.of(fqdn));
        }

        /**
         * @param port (Updatable) The port number of the FQDN
         * 
         * @return builder
         * 
         */
        public Builder port(@Nullable Output<String> port) {
            $.port = port;
            return this;
        }

        /**
         * @param port (Updatable) The port number of the FQDN
         * 
         * @return builder
         * 
         */
        public Builder port(String port) {
            return port(Output.of(port));
        }

        public PrivateEndpointScanDetailArgs build() {
            return $;
        }
    }

}
