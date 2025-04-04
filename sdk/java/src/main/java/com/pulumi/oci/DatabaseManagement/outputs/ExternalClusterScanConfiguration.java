// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ExternalClusterScanConfiguration {
    /**
     * @return The network number from which VIPs are obtained.
     * 
     */
    private @Nullable Integer networkNumber;
    /**
     * @return The name of the SCAN listener.
     * 
     */
    private @Nullable String scanName;
    /**
     * @return The port number of the SCAN listener.
     * 
     */
    private @Nullable Integer scanPort;
    /**
     * @return The protocol of the SCAN listener.
     * 
     */
    private @Nullable String scanProtocol;

    private ExternalClusterScanConfiguration() {}
    /**
     * @return The network number from which VIPs are obtained.
     * 
     */
    public Optional<Integer> networkNumber() {
        return Optional.ofNullable(this.networkNumber);
    }
    /**
     * @return The name of the SCAN listener.
     * 
     */
    public Optional<String> scanName() {
        return Optional.ofNullable(this.scanName);
    }
    /**
     * @return The port number of the SCAN listener.
     * 
     */
    public Optional<Integer> scanPort() {
        return Optional.ofNullable(this.scanPort);
    }
    /**
     * @return The protocol of the SCAN listener.
     * 
     */
    public Optional<String> scanProtocol() {
        return Optional.ofNullable(this.scanProtocol);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ExternalClusterScanConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Integer networkNumber;
        private @Nullable String scanName;
        private @Nullable Integer scanPort;
        private @Nullable String scanProtocol;
        public Builder() {}
        public Builder(ExternalClusterScanConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.networkNumber = defaults.networkNumber;
    	      this.scanName = defaults.scanName;
    	      this.scanPort = defaults.scanPort;
    	      this.scanProtocol = defaults.scanProtocol;
        }

        @CustomType.Setter
        public Builder networkNumber(@Nullable Integer networkNumber) {

            this.networkNumber = networkNumber;
            return this;
        }
        @CustomType.Setter
        public Builder scanName(@Nullable String scanName) {

            this.scanName = scanName;
            return this;
        }
        @CustomType.Setter
        public Builder scanPort(@Nullable Integer scanPort) {

            this.scanPort = scanPort;
            return this;
        }
        @CustomType.Setter
        public Builder scanProtocol(@Nullable String scanProtocol) {

            this.scanProtocol = scanProtocol;
            return this;
        }
        public ExternalClusterScanConfiguration build() {
            final var _resultValue = new ExternalClusterScanConfiguration();
            _resultValue.networkNumber = networkNumber;
            _resultValue.scanName = scanName;
            _resultValue.scanPort = scanPort;
            _resultValue.scanProtocol = scanProtocol;
            return _resultValue;
        }
    }
}
