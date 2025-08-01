// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MysqlDbSystemEncryptDataArgs extends com.pulumi.resources.ResourceArgs {

    public static final MysqlDbSystemEncryptDataArgs Empty = new MysqlDbSystemEncryptDataArgs();

    /**
     * (Updatable) Select whether to use Oracle-managed key (SYSTEM) or your own key (BYOK).
     * 
     */
    @Import(name="keyGenerationType", required=true)
    private Output<String> keyGenerationType;

    /**
     * @return (Updatable) Select whether to use Oracle-managed key (SYSTEM) or your own key (BYOK).
     * 
     */
    public Output<String> keyGenerationType() {
        return this.keyGenerationType;
    }

    /**
     * (Updatable) The OCID of the key to use.
     * 
     */
    @Import(name="keyId")
    private @Nullable Output<String> keyId;

    /**
     * @return (Updatable) The OCID of the key to use.
     * 
     */
    public Optional<Output<String>> keyId() {
        return Optional.ofNullable(this.keyId);
    }

    private MysqlDbSystemEncryptDataArgs() {}

    private MysqlDbSystemEncryptDataArgs(MysqlDbSystemEncryptDataArgs $) {
        this.keyGenerationType = $.keyGenerationType;
        this.keyId = $.keyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MysqlDbSystemEncryptDataArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MysqlDbSystemEncryptDataArgs $;

        public Builder() {
            $ = new MysqlDbSystemEncryptDataArgs();
        }

        public Builder(MysqlDbSystemEncryptDataArgs defaults) {
            $ = new MysqlDbSystemEncryptDataArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param keyGenerationType (Updatable) Select whether to use Oracle-managed key (SYSTEM) or your own key (BYOK).
         * 
         * @return builder
         * 
         */
        public Builder keyGenerationType(Output<String> keyGenerationType) {
            $.keyGenerationType = keyGenerationType;
            return this;
        }

        /**
         * @param keyGenerationType (Updatable) Select whether to use Oracle-managed key (SYSTEM) or your own key (BYOK).
         * 
         * @return builder
         * 
         */
        public Builder keyGenerationType(String keyGenerationType) {
            return keyGenerationType(Output.of(keyGenerationType));
        }

        /**
         * @param keyId (Updatable) The OCID of the key to use.
         * 
         * @return builder
         * 
         */
        public Builder keyId(@Nullable Output<String> keyId) {
            $.keyId = keyId;
            return this;
        }

        /**
         * @param keyId (Updatable) The OCID of the key to use.
         * 
         * @return builder
         * 
         */
        public Builder keyId(String keyId) {
            return keyId(Output.of(keyId));
        }

        public MysqlDbSystemEncryptDataArgs build() {
            if ($.keyGenerationType == null) {
                throw new MissingRequiredPropertyException("MysqlDbSystemEncryptDataArgs", "keyGenerationType");
            }
            return $;
        }
    }

}
