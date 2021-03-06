// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.CrossConnectGroupMacsecPropertiesPrimaryKeyArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CrossConnectGroupMacsecPropertiesArgs extends com.pulumi.resources.ResourceArgs {

    public static final CrossConnectGroupMacsecPropertiesArgs Empty = new CrossConnectGroupMacsecPropertiesArgs();

    /**
     * Type of encryption cipher suite to use for the MACsec connection.
     * 
     */
    @Import(name="encryptionCipher")
    private @Nullable Output<String> encryptionCipher;

    /**
     * @return Type of encryption cipher suite to use for the MACsec connection.
     * 
     */
    public Optional<Output<String>> encryptionCipher() {
        return Optional.ofNullable(this.encryptionCipher);
    }

    /**
     * An object defining the Secrets-in-Vault OCIDs representing the MACsec key.
     * 
     */
    @Import(name="primaryKey")
    private @Nullable Output<CrossConnectGroupMacsecPropertiesPrimaryKeyArgs> primaryKey;

    /**
     * @return An object defining the Secrets-in-Vault OCIDs representing the MACsec key.
     * 
     */
    public Optional<Output<CrossConnectGroupMacsecPropertiesPrimaryKeyArgs>> primaryKey() {
        return Optional.ofNullable(this.primaryKey);
    }

    /**
     * The cross-connect group&#39;s current state.
     * 
     */
    @Import(name="state", required=true)
    private Output<String> state;

    /**
     * @return The cross-connect group&#39;s current state.
     * 
     */
    public Output<String> state() {
        return this.state;
    }

    private CrossConnectGroupMacsecPropertiesArgs() {}

    private CrossConnectGroupMacsecPropertiesArgs(CrossConnectGroupMacsecPropertiesArgs $) {
        this.encryptionCipher = $.encryptionCipher;
        this.primaryKey = $.primaryKey;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CrossConnectGroupMacsecPropertiesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CrossConnectGroupMacsecPropertiesArgs $;

        public Builder() {
            $ = new CrossConnectGroupMacsecPropertiesArgs();
        }

        public Builder(CrossConnectGroupMacsecPropertiesArgs defaults) {
            $ = new CrossConnectGroupMacsecPropertiesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param encryptionCipher Type of encryption cipher suite to use for the MACsec connection.
         * 
         * @return builder
         * 
         */
        public Builder encryptionCipher(@Nullable Output<String> encryptionCipher) {
            $.encryptionCipher = encryptionCipher;
            return this;
        }

        /**
         * @param encryptionCipher Type of encryption cipher suite to use for the MACsec connection.
         * 
         * @return builder
         * 
         */
        public Builder encryptionCipher(String encryptionCipher) {
            return encryptionCipher(Output.of(encryptionCipher));
        }

        /**
         * @param primaryKey An object defining the Secrets-in-Vault OCIDs representing the MACsec key.
         * 
         * @return builder
         * 
         */
        public Builder primaryKey(@Nullable Output<CrossConnectGroupMacsecPropertiesPrimaryKeyArgs> primaryKey) {
            $.primaryKey = primaryKey;
            return this;
        }

        /**
         * @param primaryKey An object defining the Secrets-in-Vault OCIDs representing the MACsec key.
         * 
         * @return builder
         * 
         */
        public Builder primaryKey(CrossConnectGroupMacsecPropertiesPrimaryKeyArgs primaryKey) {
            return primaryKey(Output.of(primaryKey));
        }

        /**
         * @param state The cross-connect group&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The cross-connect group&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public CrossConnectGroupMacsecPropertiesArgs build() {
            $.state = Objects.requireNonNull($.state, "expected parameter 'state' to be non-null");
            return $;
        }
    }

}
