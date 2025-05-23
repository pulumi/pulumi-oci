// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlArgs extends com.pulumi.resources.ResourceArgs {

    public static final FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlArgs Empty = new FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlArgs();

    /**
     * (Updatable) Key size for the encryption algorithm. Allowed values: 256 for EC, 2048 for DH/DSA/RSA
     * 
     */
    @Import(name="keySize")
    private @Nullable Output<Integer> keySize;

    /**
     * @return (Updatable) Key size for the encryption algorithm. Allowed values: 256 for EC, 2048 for DH/DSA/RSA
     * 
     */
    public Optional<Output<Integer>> keySize() {
        return Optional.ofNullable(this.keySize);
    }

    /**
     * (Updatable) The algorithm name.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) The algorithm name.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    private FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlArgs() {}

    private FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlArgs(FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlArgs $) {
        this.keySize = $.keySize;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlArgs $;

        public Builder() {
            $ = new FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlArgs();
        }

        public Builder(FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlArgs defaults) {
            $ = new FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param keySize (Updatable) Key size for the encryption algorithm. Allowed values: 256 for EC, 2048 for DH/DSA/RSA
         * 
         * @return builder
         * 
         */
        public Builder keySize(@Nullable Output<Integer> keySize) {
            $.keySize = keySize;
            return this;
        }

        /**
         * @param keySize (Updatable) Key size for the encryption algorithm. Allowed values: 256 for EC, 2048 for DH/DSA/RSA
         * 
         * @return builder
         * 
         */
        public Builder keySize(Integer keySize) {
            return keySize(Output.of(keySize));
        }

        /**
         * @param name (Updatable) The algorithm name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) The algorithm name.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlArgs build() {
            return $;
        }
    }

}
