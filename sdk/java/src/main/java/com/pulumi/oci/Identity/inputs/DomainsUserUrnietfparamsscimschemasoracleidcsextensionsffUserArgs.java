// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserArgs Empty = new DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserArgs();

    /**
     * (Updatable) SFF auth keys clob
     * 
     */
    @Import(name="sffAuthKeys")
    private @Nullable Output<String> sffAuthKeys;

    /**
     * @return (Updatable) SFF auth keys clob
     * 
     */
    public Optional<Output<String>> sffAuthKeys() {
        return Optional.ofNullable(this.sffAuthKeys);
    }

    private DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserArgs() {}

    private DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserArgs(DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserArgs $) {
        this.sffAuthKeys = $.sffAuthKeys;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserArgs $;

        public Builder() {
            $ = new DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserArgs();
        }

        public Builder(DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserArgs defaults) {
            $ = new DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param sffAuthKeys (Updatable) SFF auth keys clob
         * 
         * @return builder
         * 
         */
        public Builder sffAuthKeys(@Nullable Output<String> sffAuthKeys) {
            $.sffAuthKeys = sffAuthKeys;
            return this;
        }

        /**
         * @param sffAuthKeys (Updatable) SFF auth keys clob
         * 
         * @return builder
         * 
         */
        public Builder sffAuthKeys(String sffAuthKeys) {
            return sffAuthKeys(Output.of(sffAuthKeys));
        }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserArgs build() {
            return $;
        }
    }

}