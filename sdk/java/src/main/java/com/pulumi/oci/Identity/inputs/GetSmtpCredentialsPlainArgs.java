// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Identity.inputs.GetSmtpCredentialsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSmtpCredentialsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSmtpCredentialsPlainArgs Empty = new GetSmtpCredentialsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetSmtpCredentialsFilter> filters;

    public Optional<List<GetSmtpCredentialsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the user.
     * 
     */
    @Import(name="userId", required=true)
    private String userId;

    /**
     * @return The OCID of the user.
     * 
     */
    public String userId() {
        return this.userId;
    }

    private GetSmtpCredentialsPlainArgs() {}

    private GetSmtpCredentialsPlainArgs(GetSmtpCredentialsPlainArgs $) {
        this.filters = $.filters;
        this.userId = $.userId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSmtpCredentialsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSmtpCredentialsPlainArgs $;

        public Builder() {
            $ = new GetSmtpCredentialsPlainArgs();
        }

        public Builder(GetSmtpCredentialsPlainArgs defaults) {
            $ = new GetSmtpCredentialsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetSmtpCredentialsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetSmtpCredentialsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param userId The OCID of the user.
         * 
         * @return builder
         * 
         */
        public Builder userId(String userId) {
            $.userId = userId;
            return this;
        }

        public GetSmtpCredentialsPlainArgs build() {
            $.userId = Objects.requireNonNull($.userId, "expected parameter 'userId' to be non-null");
            return $;
        }
    }

}