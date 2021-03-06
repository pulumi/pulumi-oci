// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class InstanceConfigurationInstanceDetailsLaunchDetailsPlatformConfig {
    /**
     * @return Whether the Measured Boot feature is enabled on the instance.
     * 
     */
    private final @Nullable Boolean isMeasuredBootEnabled;
    /**
     * @return Whether Secure Boot is enabled on the instance.
     * 
     */
    private final @Nullable Boolean isSecureBootEnabled;
    /**
     * @return Whether the Trusted Platform Module (TPM) is enabled on the instance.
     * 
     */
    private final @Nullable Boolean isTrustedPlatformModuleEnabled;
    /**
     * @return The number of NUMA nodes per socket (NPS).
     * 
     */
    private final @Nullable String numaNodesPerSocket;
    /**
     * @return The type of action to run when the instance is interrupted for eviction.
     * 
     */
    private final String type;

    @CustomType.Constructor
    private InstanceConfigurationInstanceDetailsLaunchDetailsPlatformConfig(
        @CustomType.Parameter("isMeasuredBootEnabled") @Nullable Boolean isMeasuredBootEnabled,
        @CustomType.Parameter("isSecureBootEnabled") @Nullable Boolean isSecureBootEnabled,
        @CustomType.Parameter("isTrustedPlatformModuleEnabled") @Nullable Boolean isTrustedPlatformModuleEnabled,
        @CustomType.Parameter("numaNodesPerSocket") @Nullable String numaNodesPerSocket,
        @CustomType.Parameter("type") String type) {
        this.isMeasuredBootEnabled = isMeasuredBootEnabled;
        this.isSecureBootEnabled = isSecureBootEnabled;
        this.isTrustedPlatformModuleEnabled = isTrustedPlatformModuleEnabled;
        this.numaNodesPerSocket = numaNodesPerSocket;
        this.type = type;
    }

    /**
     * @return Whether the Measured Boot feature is enabled on the instance.
     * 
     */
    public Optional<Boolean> isMeasuredBootEnabled() {
        return Optional.ofNullable(this.isMeasuredBootEnabled);
    }
    /**
     * @return Whether Secure Boot is enabled on the instance.
     * 
     */
    public Optional<Boolean> isSecureBootEnabled() {
        return Optional.ofNullable(this.isSecureBootEnabled);
    }
    /**
     * @return Whether the Trusted Platform Module (TPM) is enabled on the instance.
     * 
     */
    public Optional<Boolean> isTrustedPlatformModuleEnabled() {
        return Optional.ofNullable(this.isTrustedPlatformModuleEnabled);
    }
    /**
     * @return The number of NUMA nodes per socket (NPS).
     * 
     */
    public Optional<String> numaNodesPerSocket() {
        return Optional.ofNullable(this.numaNodesPerSocket);
    }
    /**
     * @return The type of action to run when the instance is interrupted for eviction.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(InstanceConfigurationInstanceDetailsLaunchDetailsPlatformConfig defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable Boolean isMeasuredBootEnabled;
        private @Nullable Boolean isSecureBootEnabled;
        private @Nullable Boolean isTrustedPlatformModuleEnabled;
        private @Nullable String numaNodesPerSocket;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(InstanceConfigurationInstanceDetailsLaunchDetailsPlatformConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isMeasuredBootEnabled = defaults.isMeasuredBootEnabled;
    	      this.isSecureBootEnabled = defaults.isSecureBootEnabled;
    	      this.isTrustedPlatformModuleEnabled = defaults.isTrustedPlatformModuleEnabled;
    	      this.numaNodesPerSocket = defaults.numaNodesPerSocket;
    	      this.type = defaults.type;
        }

        public Builder isMeasuredBootEnabled(@Nullable Boolean isMeasuredBootEnabled) {
            this.isMeasuredBootEnabled = isMeasuredBootEnabled;
            return this;
        }
        public Builder isSecureBootEnabled(@Nullable Boolean isSecureBootEnabled) {
            this.isSecureBootEnabled = isSecureBootEnabled;
            return this;
        }
        public Builder isTrustedPlatformModuleEnabled(@Nullable Boolean isTrustedPlatformModuleEnabled) {
            this.isTrustedPlatformModuleEnabled = isTrustedPlatformModuleEnabled;
            return this;
        }
        public Builder numaNodesPerSocket(@Nullable String numaNodesPerSocket) {
            this.numaNodesPerSocket = numaNodesPerSocket;
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public InstanceConfigurationInstanceDetailsLaunchDetailsPlatformConfig build() {
            return new InstanceConfigurationInstanceDetailsLaunchDetailsPlatformConfig(isMeasuredBootEnabled, isSecureBootEnabled, isTrustedPlatformModuleEnabled, numaNodesPerSocket, type);
        }
    }
}
