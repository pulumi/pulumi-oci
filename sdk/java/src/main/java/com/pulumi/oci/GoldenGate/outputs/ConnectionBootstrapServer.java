// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ConnectionBootstrapServer {
    /**
     * @return (Updatable) The name or address of a host.
     * 
     */
    private @Nullable String host;
    /**
     * @return (Updatable) The port of an endpoint usually specified for a connection.
     * 
     */
    private @Nullable Integer port;
    /**
     * @return (Updatable) Deprecated: this field will be removed in future versions. Either specify the private IP in the connectionString or host  field, or make sure the host name is resolvable in the target VCN.
     * 
     * The private IP address of the connection&#39;s endpoint in the customer&#39;s VCN, typically a database endpoint or a big data endpoint (e.g. Kafka bootstrap server). In case the privateIp is provided, the subnetId must also be provided. In case the privateIp (and the subnetId) is not provided it is assumed the datasource is publicly accessible. In case the connection is accessible only privately, the lack of privateIp will result in not being able to access the connection.
     * 
     */
    private @Nullable String privateIp;

    private ConnectionBootstrapServer() {}
    /**
     * @return (Updatable) The name or address of a host.
     * 
     */
    public Optional<String> host() {
        return Optional.ofNullable(this.host);
    }
    /**
     * @return (Updatable) The port of an endpoint usually specified for a connection.
     * 
     */
    public Optional<Integer> port() {
        return Optional.ofNullable(this.port);
    }
    /**
     * @return (Updatable) Deprecated: this field will be removed in future versions. Either specify the private IP in the connectionString or host  field, or make sure the host name is resolvable in the target VCN.
     * 
     * The private IP address of the connection&#39;s endpoint in the customer&#39;s VCN, typically a database endpoint or a big data endpoint (e.g. Kafka bootstrap server). In case the privateIp is provided, the subnetId must also be provided. In case the privateIp (and the subnetId) is not provided it is assumed the datasource is publicly accessible. In case the connection is accessible only privately, the lack of privateIp will result in not being able to access the connection.
     * 
     */
    public Optional<String> privateIp() {
        return Optional.ofNullable(this.privateIp);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ConnectionBootstrapServer defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String host;
        private @Nullable Integer port;
        private @Nullable String privateIp;
        public Builder() {}
        public Builder(ConnectionBootstrapServer defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.host = defaults.host;
    	      this.port = defaults.port;
    	      this.privateIp = defaults.privateIp;
        }

        @CustomType.Setter
        public Builder host(@Nullable String host) {

            this.host = host;
            return this;
        }
        @CustomType.Setter
        public Builder port(@Nullable Integer port) {

            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder privateIp(@Nullable String privateIp) {

            this.privateIp = privateIp;
            return this;
        }
        public ConnectionBootstrapServer build() {
            final var _resultValue = new ConnectionBootstrapServer();
            _resultValue.host = host;
            _resultValue.port = port;
            _resultValue.privateIp = privateIp;
            return _resultValue;
        }
    }
}
