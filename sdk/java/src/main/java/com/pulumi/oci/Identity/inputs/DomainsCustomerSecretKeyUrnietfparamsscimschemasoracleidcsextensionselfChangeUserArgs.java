// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs Empty = new DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs();

    /**
     * If true, allows requesting user to update themselves. If false, requesting user can&#39;t update themself (default).
     * 
     */
    @Import(name="allowSelfChange")
    private @Nullable Output<Boolean> allowSelfChange;

    /**
     * @return If true, allows requesting user to update themselves. If false, requesting user can&#39;t update themself (default).
     * 
     */
    public Optional<Output<Boolean>> allowSelfChange() {
        return Optional.ofNullable(this.allowSelfChange);
    }

    private DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs() {}

    private DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs(DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs $) {
        this.allowSelfChange = $.allowSelfChange;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs $;

        public Builder() {
            $ = new DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs();
        }

        public Builder(DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs defaults) {
            $ = new DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param allowSelfChange If true, allows requesting user to update themselves. If false, requesting user can&#39;t update themself (default).
         * 
         * @return builder
         * 
         */
        public Builder allowSelfChange(@Nullable Output<Boolean> allowSelfChange) {
            $.allowSelfChange = allowSelfChange;
            return this;
        }

        /**
         * @param allowSelfChange If true, allows requesting user to update themselves. If false, requesting user can&#39;t update themself (default).
         * 
         * @return builder
         * 
         */
        public Builder allowSelfChange(Boolean allowSelfChange) {
            return allowSelfChange(Output.of(allowSelfChange));
        }

        public DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs build() {
            return $;
        }
    }

}