// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MigrationGgsDetailsGgsDeploymentArgs extends com.pulumi.resources.ResourceArgs {

    public static final MigrationGgsDetailsGgsDeploymentArgs Empty = new MigrationGgsDetailsGgsDeploymentArgs();

    /**
     * The OCID of the resource being referenced.
     * 
     */
    @Import(name="deploymentId")
    private @Nullable Output<String> deploymentId;

    /**
     * @return The OCID of the resource being referenced.
     * 
     */
    public Optional<Output<String>> deploymentId() {
        return Optional.ofNullable(this.deploymentId);
    }

    /**
     * The OCID of the resource being referenced.
     * 
     */
    @Import(name="ggsAdminCredentialsSecretId")
    private @Nullable Output<String> ggsAdminCredentialsSecretId;

    /**
     * @return The OCID of the resource being referenced.
     * 
     */
    public Optional<Output<String>> ggsAdminCredentialsSecretId() {
        return Optional.ofNullable(this.ggsAdminCredentialsSecretId);
    }

    private MigrationGgsDetailsGgsDeploymentArgs() {}

    private MigrationGgsDetailsGgsDeploymentArgs(MigrationGgsDetailsGgsDeploymentArgs $) {
        this.deploymentId = $.deploymentId;
        this.ggsAdminCredentialsSecretId = $.ggsAdminCredentialsSecretId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MigrationGgsDetailsGgsDeploymentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MigrationGgsDetailsGgsDeploymentArgs $;

        public Builder() {
            $ = new MigrationGgsDetailsGgsDeploymentArgs();
        }

        public Builder(MigrationGgsDetailsGgsDeploymentArgs defaults) {
            $ = new MigrationGgsDetailsGgsDeploymentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param deploymentId The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder deploymentId(@Nullable Output<String> deploymentId) {
            $.deploymentId = deploymentId;
            return this;
        }

        /**
         * @param deploymentId The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder deploymentId(String deploymentId) {
            return deploymentId(Output.of(deploymentId));
        }

        /**
         * @param ggsAdminCredentialsSecretId The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder ggsAdminCredentialsSecretId(@Nullable Output<String> ggsAdminCredentialsSecretId) {
            $.ggsAdminCredentialsSecretId = ggsAdminCredentialsSecretId;
            return this;
        }

        /**
         * @param ggsAdminCredentialsSecretId The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder ggsAdminCredentialsSecretId(String ggsAdminCredentialsSecretId) {
            return ggsAdminCredentialsSecretId(Output.of(ggsAdminCredentialsSecretId));
        }

        public MigrationGgsDetailsGgsDeploymentArgs build() {
            return $;
        }
    }

}
