// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.inputs.GetAnnouncementsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAnnouncementsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAnnouncementsPlainArgs Empty = new GetAnnouncementsPlainArgs();

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
    private @Nullable List<GetAnnouncementsFilter> filters;

    public Optional<List<GetAnnouncementsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Filter the list of announcements that contains the given summary value.
     * 
     */
    @Import(name="summaryContains")
    private @Nullable String summaryContains;

    /**
     * @return Filter the list of announcements that contains the given summary value.
     * 
     */
    public Optional<String> summaryContains() {
        return Optional.ofNullable(this.summaryContains);
    }

    private GetAnnouncementsPlainArgs() {}

    private GetAnnouncementsPlainArgs(GetAnnouncementsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.summaryContains = $.summaryContains;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAnnouncementsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAnnouncementsPlainArgs $;

        public Builder() {
            $ = new GetAnnouncementsPlainArgs();
        }

        public Builder(GetAnnouncementsPlainArgs defaults) {
            $ = new GetAnnouncementsPlainArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable List<GetAnnouncementsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetAnnouncementsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param summaryContains Filter the list of announcements that contains the given summary value.
         * 
         * @return builder
         * 
         */
        public Builder summaryContains(@Nullable String summaryContains) {
            $.summaryContains = summaryContains;
            return this;
        }

        public GetAnnouncementsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetAnnouncementsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
