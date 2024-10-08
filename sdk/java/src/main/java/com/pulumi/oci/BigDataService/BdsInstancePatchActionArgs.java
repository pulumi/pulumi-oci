// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.BigDataService.inputs.BdsInstancePatchActionPatchingConfigArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BdsInstancePatchActionArgs extends com.pulumi.resources.ResourceArgs {

    public static final BdsInstancePatchActionArgs Empty = new BdsInstancePatchActionArgs();

    /**
     * The OCID of the cluster.
     * 
     */
    @Import(name="bdsInstanceId", required=true)
    private Output<String> bdsInstanceId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public Output<String> bdsInstanceId() {
        return this.bdsInstanceId;
    }

    /**
     * Base-64 encoded password for the cluster admin user.
     * 
     */
    @Import(name="clusterAdminPassword", required=true)
    private Output<String> clusterAdminPassword;

    /**
     * @return Base-64 encoded password for the cluster admin user.
     * 
     */
    public Output<String> clusterAdminPassword() {
        return this.clusterAdminPassword;
    }

    /**
     * Detailed configurations for defining the behavior when installing ODH patches. If not provided, nodes will be patched with down time.
     * 
     */
    @Import(name="patchingConfig")
    private @Nullable Output<BdsInstancePatchActionPatchingConfigArgs> patchingConfig;

    /**
     * @return Detailed configurations for defining the behavior when installing ODH patches. If not provided, nodes will be patched with down time.
     * 
     */
    public Optional<Output<BdsInstancePatchActionPatchingConfigArgs>> patchingConfig() {
        return Optional.ofNullable(this.patchingConfig);
    }

    /**
     * The version of the patch to be installed.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="version", required=true)
    private Output<String> version;

    /**
     * @return The version of the patch to be installed.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> version() {
        return this.version;
    }

    private BdsInstancePatchActionArgs() {}

    private BdsInstancePatchActionArgs(BdsInstancePatchActionArgs $) {
        this.bdsInstanceId = $.bdsInstanceId;
        this.clusterAdminPassword = $.clusterAdminPassword;
        this.patchingConfig = $.patchingConfig;
        this.version = $.version;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BdsInstancePatchActionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BdsInstancePatchActionArgs $;

        public Builder() {
            $ = new BdsInstancePatchActionArgs();
        }

        public Builder(BdsInstancePatchActionArgs defaults) {
            $ = new BdsInstancePatchActionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(Output<String> bdsInstanceId) {
            $.bdsInstanceId = bdsInstanceId;
            return this;
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(String bdsInstanceId) {
            return bdsInstanceId(Output.of(bdsInstanceId));
        }

        /**
         * @param clusterAdminPassword Base-64 encoded password for the cluster admin user.
         * 
         * @return builder
         * 
         */
        public Builder clusterAdminPassword(Output<String> clusterAdminPassword) {
            $.clusterAdminPassword = clusterAdminPassword;
            return this;
        }

        /**
         * @param clusterAdminPassword Base-64 encoded password for the cluster admin user.
         * 
         * @return builder
         * 
         */
        public Builder clusterAdminPassword(String clusterAdminPassword) {
            return clusterAdminPassword(Output.of(clusterAdminPassword));
        }

        /**
         * @param patchingConfig Detailed configurations for defining the behavior when installing ODH patches. If not provided, nodes will be patched with down time.
         * 
         * @return builder
         * 
         */
        public Builder patchingConfig(@Nullable Output<BdsInstancePatchActionPatchingConfigArgs> patchingConfig) {
            $.patchingConfig = patchingConfig;
            return this;
        }

        /**
         * @param patchingConfig Detailed configurations for defining the behavior when installing ODH patches. If not provided, nodes will be patched with down time.
         * 
         * @return builder
         * 
         */
        public Builder patchingConfig(BdsInstancePatchActionPatchingConfigArgs patchingConfig) {
            return patchingConfig(Output.of(patchingConfig));
        }

        /**
         * @param version The version of the patch to be installed.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder version(Output<String> version) {
            $.version = version;
            return this;
        }

        /**
         * @param version The version of the patch to be installed.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder version(String version) {
            return version(Output.of(version));
        }

        public BdsInstancePatchActionArgs build() {
            if ($.bdsInstanceId == null) {
                throw new MissingRequiredPropertyException("BdsInstancePatchActionArgs", "bdsInstanceId");
            }
            if ($.clusterAdminPassword == null) {
                throw new MissingRequiredPropertyException("BdsInstancePatchActionArgs", "clusterAdminPassword");
            }
            if ($.version == null) {
                throw new MissingRequiredPropertyException("BdsInstancePatchActionArgs", "version");
            }
            return $;
        }
    }

}
