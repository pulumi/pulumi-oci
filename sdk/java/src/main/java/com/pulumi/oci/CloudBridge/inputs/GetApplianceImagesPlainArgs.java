// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudBridge.inputs.GetApplianceImagesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetApplianceImagesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetApplianceImagesPlainArgs Empty = new GetApplianceImagesPlainArgs();

    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetApplianceImagesFilter> filters;

    public Optional<List<GetApplianceImagesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetApplianceImagesPlainArgs() {}

    private GetApplianceImagesPlainArgs(GetApplianceImagesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetApplianceImagesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetApplianceImagesPlainArgs $;

        public Builder() {
            $ = new GetApplianceImagesPlainArgs();
        }

        public Builder(GetApplianceImagesPlainArgs defaults) {
            $ = new GetApplianceImagesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetApplianceImagesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetApplianceImagesFilter... filters) {
            return filters(List.of(filters));
        }

        public GetApplianceImagesPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}