// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Ocvp.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ClusterUpgradeLicenseArgs extends com.pulumi.resources.ResourceArgs {

    public static final ClusterUpgradeLicenseArgs Empty = new ClusterUpgradeLicenseArgs();

    /**
     * vSphere license key value.
     * 
     */
    @Import(name="licenseKey")
    private @Nullable Output<String> licenseKey;

    /**
     * @return vSphere license key value.
     * 
     */
    public Optional<Output<String>> licenseKey() {
        return Optional.ofNullable(this.licenseKey);
    }

    /**
     * vSphere license type.
     * 
     */
    @Import(name="licenseType")
    private @Nullable Output<String> licenseType;

    /**
     * @return vSphere license type.
     * 
     */
    public Optional<Output<String>> licenseType() {
        return Optional.ofNullable(this.licenseType);
    }

    private ClusterUpgradeLicenseArgs() {}

    private ClusterUpgradeLicenseArgs(ClusterUpgradeLicenseArgs $) {
        this.licenseKey = $.licenseKey;
        this.licenseType = $.licenseType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ClusterUpgradeLicenseArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ClusterUpgradeLicenseArgs $;

        public Builder() {
            $ = new ClusterUpgradeLicenseArgs();
        }

        public Builder(ClusterUpgradeLicenseArgs defaults) {
            $ = new ClusterUpgradeLicenseArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param licenseKey vSphere license key value.
         * 
         * @return builder
         * 
         */
        public Builder licenseKey(@Nullable Output<String> licenseKey) {
            $.licenseKey = licenseKey;
            return this;
        }

        /**
         * @param licenseKey vSphere license key value.
         * 
         * @return builder
         * 
         */
        public Builder licenseKey(String licenseKey) {
            return licenseKey(Output.of(licenseKey));
        }

        /**
         * @param licenseType vSphere license type.
         * 
         * @return builder
         * 
         */
        public Builder licenseType(@Nullable Output<String> licenseType) {
            $.licenseType = licenseType;
            return this;
        }

        /**
         * @param licenseType vSphere license type.
         * 
         * @return builder
         * 
         */
        public Builder licenseType(String licenseType) {
            return licenseType(Output.of(licenseType));
        }

        public ClusterUpgradeLicenseArgs build() {
            return $;
        }
    }

}
