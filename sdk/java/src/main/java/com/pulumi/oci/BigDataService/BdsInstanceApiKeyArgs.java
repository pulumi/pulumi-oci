// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BdsInstanceApiKeyArgs extends com.pulumi.resources.ResourceArgs {

    public static final BdsInstanceApiKeyArgs Empty = new BdsInstanceApiKeyArgs();

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
     * The name of the region to establish the Object Storage endpoint. See https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/Region/ for additional information.
     * 
     */
    @Import(name="defaultRegion")
    private @Nullable Output<String> defaultRegion;

    /**
     * @return The name of the region to establish the Object Storage endpoint. See https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/Region/ for additional information.
     * 
     */
    public Optional<Output<String>> defaultRegion() {
        return Optional.ofNullable(this.defaultRegion);
    }

    /**
     * User friendly identifier used to uniquely differentiate between different API keys associated with this Big Data Service cluster. Only ASCII alphanumeric characters with no spaces allowed.
     * 
     */
    @Import(name="keyAlias", required=true)
    private Output<String> keyAlias;

    /**
     * @return User friendly identifier used to uniquely differentiate between different API keys associated with this Big Data Service cluster. Only ASCII alphanumeric characters with no spaces allowed.
     * 
     */
    public Output<String> keyAlias() {
        return this.keyAlias;
    }

    /**
     * Base64 passphrase used to secure the private key which will be created on user behalf.
     * 
     */
    @Import(name="passphrase", required=true)
    private Output<String> passphrase;

    /**
     * @return Base64 passphrase used to secure the private key which will be created on user behalf.
     * 
     */
    public Output<String> passphrase() {
        return this.passphrase;
    }

    /**
     * The OCID of the user for whom this new generated API key pair will be created.
     * 
     */
    @Import(name="userId", required=true)
    private Output<String> userId;

    /**
     * @return The OCID of the user for whom this new generated API key pair will be created.
     * 
     */
    public Output<String> userId() {
        return this.userId;
    }

    private BdsInstanceApiKeyArgs() {}

    private BdsInstanceApiKeyArgs(BdsInstanceApiKeyArgs $) {
        this.bdsInstanceId = $.bdsInstanceId;
        this.defaultRegion = $.defaultRegion;
        this.keyAlias = $.keyAlias;
        this.passphrase = $.passphrase;
        this.userId = $.userId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BdsInstanceApiKeyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BdsInstanceApiKeyArgs $;

        public Builder() {
            $ = new BdsInstanceApiKeyArgs();
        }

        public Builder(BdsInstanceApiKeyArgs defaults) {
            $ = new BdsInstanceApiKeyArgs(Objects.requireNonNull(defaults));
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
         * @param defaultRegion The name of the region to establish the Object Storage endpoint. See https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/Region/ for additional information.
         * 
         * @return builder
         * 
         */
        public Builder defaultRegion(@Nullable Output<String> defaultRegion) {
            $.defaultRegion = defaultRegion;
            return this;
        }

        /**
         * @param defaultRegion The name of the region to establish the Object Storage endpoint. See https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/Region/ for additional information.
         * 
         * @return builder
         * 
         */
        public Builder defaultRegion(String defaultRegion) {
            return defaultRegion(Output.of(defaultRegion));
        }

        /**
         * @param keyAlias User friendly identifier used to uniquely differentiate between different API keys associated with this Big Data Service cluster. Only ASCII alphanumeric characters with no spaces allowed.
         * 
         * @return builder
         * 
         */
        public Builder keyAlias(Output<String> keyAlias) {
            $.keyAlias = keyAlias;
            return this;
        }

        /**
         * @param keyAlias User friendly identifier used to uniquely differentiate between different API keys associated with this Big Data Service cluster. Only ASCII alphanumeric characters with no spaces allowed.
         * 
         * @return builder
         * 
         */
        public Builder keyAlias(String keyAlias) {
            return keyAlias(Output.of(keyAlias));
        }

        /**
         * @param passphrase Base64 passphrase used to secure the private key which will be created on user behalf.
         * 
         * @return builder
         * 
         */
        public Builder passphrase(Output<String> passphrase) {
            $.passphrase = passphrase;
            return this;
        }

        /**
         * @param passphrase Base64 passphrase used to secure the private key which will be created on user behalf.
         * 
         * @return builder
         * 
         */
        public Builder passphrase(String passphrase) {
            return passphrase(Output.of(passphrase));
        }

        /**
         * @param userId The OCID of the user for whom this new generated API key pair will be created.
         * 
         * @return builder
         * 
         */
        public Builder userId(Output<String> userId) {
            $.userId = userId;
            return this;
        }

        /**
         * @param userId The OCID of the user for whom this new generated API key pair will be created.
         * 
         * @return builder
         * 
         */
        public Builder userId(String userId) {
            return userId(Output.of(userId));
        }

        public BdsInstanceApiKeyArgs build() {
            $.bdsInstanceId = Objects.requireNonNull($.bdsInstanceId, "expected parameter 'bdsInstanceId' to be non-null");
            $.keyAlias = Objects.requireNonNull($.keyAlias, "expected parameter 'keyAlias' to be non-null");
            $.passphrase = Objects.requireNonNull($.passphrase, "expected parameter 'passphrase' to be non-null");
            $.userId = Objects.requireNonNull($.userId, "expected parameter 'userId' to be non-null");
            return $;
        }
    }

}