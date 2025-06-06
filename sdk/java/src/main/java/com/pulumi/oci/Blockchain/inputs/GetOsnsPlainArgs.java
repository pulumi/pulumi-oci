// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Blockchain.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Blockchain.inputs.GetOsnsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetOsnsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOsnsPlainArgs Empty = new GetOsnsPlainArgs();

    /**
     * Unique service identifier.
     * 
     */
    @Import(name="blockchainPlatformId", required=true)
    private String blockchainPlatformId;

    /**
     * @return Unique service identifier.
     * 
     */
    public String blockchainPlatformId() {
        return this.blockchainPlatformId;
    }

    /**
     * A user-friendly name. Does not have to be unique, and it&#39;s changeable. Example: `My new resource`
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Example: `My new resource`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetOsnsFilter> filters;

    public Optional<List<GetOsnsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetOsnsPlainArgs() {}

    private GetOsnsPlainArgs(GetOsnsPlainArgs $) {
        this.blockchainPlatformId = $.blockchainPlatformId;
        this.displayName = $.displayName;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOsnsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOsnsPlainArgs $;

        public Builder() {
            $ = new GetOsnsPlainArgs();
        }

        public Builder(GetOsnsPlainArgs defaults) {
            $ = new GetOsnsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param blockchainPlatformId Unique service identifier.
         * 
         * @return builder
         * 
         */
        public Builder blockchainPlatformId(String blockchainPlatformId) {
            $.blockchainPlatformId = blockchainPlatformId;
            return this;
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable. Example: `My new resource`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetOsnsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetOsnsFilter... filters) {
            return filters(List.of(filters));
        }

        public GetOsnsPlainArgs build() {
            if ($.blockchainPlatformId == null) {
                throw new MissingRequiredPropertyException("GetOsnsPlainArgs", "blockchainPlatformId");
            }
            return $;
        }
    }

}
