// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAutonomousDatabaseWalletPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAutonomousDatabaseWalletPlainArgs Empty = new GetAutonomousDatabaseWalletPlainArgs();

    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     * @deprecated
     * The &#39;data.oci_database_autonomous_database_wallet&#39; resource has been deprecated. Please use &#39;oci_database_autonomous_database_wallet&#39; instead.
     * 
     */
    @Deprecated /* The 'data.oci_database_autonomous_database_wallet' resource has been deprecated. Please use 'oci_database_autonomous_database_wallet' instead. */
    @Import(name="autonomousDatabaseId", required=true)
    private String autonomousDatabaseId;

    /**
     * @return The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     * @deprecated
     * The &#39;data.oci_database_autonomous_database_wallet&#39; resource has been deprecated. Please use &#39;oci_database_autonomous_database_wallet&#39; instead.
     * 
     */
    @Deprecated /* The 'data.oci_database_autonomous_database_wallet' resource has been deprecated. Please use 'oci_database_autonomous_database_wallet' instead. */
    public String autonomousDatabaseId() {
        return this.autonomousDatabaseId;
    }

    @Import(name="base64EncodeContent")
    private @Nullable Boolean base64EncodeContent;

    public Optional<Boolean> base64EncodeContent() {
        return Optional.ofNullable(this.base64EncodeContent);
    }

    /**
     * The type of wallet to generate.
     * 
     */
    @Import(name="generateType")
    private @Nullable String generateType;

    /**
     * @return The type of wallet to generate.
     * 
     */
    public Optional<String> generateType() {
        return Optional.ofNullable(this.generateType);
    }

    /**
     * The password to encrypt the keys inside the wallet. The password must be at least 8 characters long and must include at least 1 letter and either 1 numeric character or 1 special character.
     * 
     */
    @Import(name="password", required=true)
    private String password;

    /**
     * @return The password to encrypt the keys inside the wallet. The password must be at least 8 characters long and must include at least 1 letter and either 1 numeric character or 1 special character.
     * 
     */
    public String password() {
        return this.password;
    }

    private GetAutonomousDatabaseWalletPlainArgs() {}

    private GetAutonomousDatabaseWalletPlainArgs(GetAutonomousDatabaseWalletPlainArgs $) {
        this.autonomousDatabaseId = $.autonomousDatabaseId;
        this.base64EncodeContent = $.base64EncodeContent;
        this.generateType = $.generateType;
        this.password = $.password;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAutonomousDatabaseWalletPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAutonomousDatabaseWalletPlainArgs $;

        public Builder() {
            $ = new GetAutonomousDatabaseWalletPlainArgs();
        }

        public Builder(GetAutonomousDatabaseWalletPlainArgs defaults) {
            $ = new GetAutonomousDatabaseWalletPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autonomousDatabaseId The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;data.oci_database_autonomous_database_wallet&#39; resource has been deprecated. Please use &#39;oci_database_autonomous_database_wallet&#39; instead.
         * 
         */
        @Deprecated /* The 'data.oci_database_autonomous_database_wallet' resource has been deprecated. Please use 'oci_database_autonomous_database_wallet' instead. */
        public Builder autonomousDatabaseId(String autonomousDatabaseId) {
            $.autonomousDatabaseId = autonomousDatabaseId;
            return this;
        }

        public Builder base64EncodeContent(@Nullable Boolean base64EncodeContent) {
            $.base64EncodeContent = base64EncodeContent;
            return this;
        }

        /**
         * @param generateType The type of wallet to generate.
         * 
         * @return builder
         * 
         */
        public Builder generateType(@Nullable String generateType) {
            $.generateType = generateType;
            return this;
        }

        /**
         * @param password The password to encrypt the keys inside the wallet. The password must be at least 8 characters long and must include at least 1 letter and either 1 numeric character or 1 special character.
         * 
         * @return builder
         * 
         */
        public Builder password(String password) {
            $.password = password;
            return this;
        }

        public GetAutonomousDatabaseWalletPlainArgs build() {
            $.autonomousDatabaseId = Objects.requireNonNull($.autonomousDatabaseId, "expected parameter 'autonomousDatabaseId' to be non-null");
            $.password = Objects.requireNonNull($.password, "expected parameter 'password' to be non-null");
            return $;
        }
    }

}