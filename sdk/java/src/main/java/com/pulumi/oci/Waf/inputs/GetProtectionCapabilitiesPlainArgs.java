// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Waf.inputs.GetProtectionCapabilitiesFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetProtectionCapabilitiesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetProtectionCapabilitiesPlainArgs Empty = new GetProtectionCapabilitiesPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
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
    private @Nullable List<GetProtectionCapabilitiesFilter> filters;

    public Optional<List<GetProtectionCapabilitiesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that are accociated given group tag.
     * 
     */
    @Import(name="groupTags")
    private @Nullable List<String> groupTags;

    /**
     * @return A filter to return only resources that are accociated given group tag.
     * 
     */
    public Optional<List<String>> groupTags() {
        return Optional.ofNullable(this.groupTags);
    }

    /**
     * A filter to return only resources that matches given isLatestVersion.
     * 
     */
    @Import(name="isLatestVersions")
    private @Nullable List<Boolean> isLatestVersions;

    /**
     * @return A filter to return only resources that matches given isLatestVersion.
     * 
     */
    public Optional<List<Boolean>> isLatestVersions() {
        return Optional.ofNullable(this.isLatestVersions);
    }

    /**
     * The unique key of protection capability to filter by.
     * 
     */
    @Import(name="key")
    private @Nullable String key;

    /**
     * @return The unique key of protection capability to filter by.
     * 
     */
    public Optional<String> key() {
        return Optional.ofNullable(this.key);
    }

    /**
     * A filter to return only resources that matches given type.
     * 
     */
    @Import(name="type")
    private @Nullable String type;

    /**
     * @return A filter to return only resources that matches given type.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    private GetProtectionCapabilitiesPlainArgs() {}

    private GetProtectionCapabilitiesPlainArgs(GetProtectionCapabilitiesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.groupTags = $.groupTags;
        this.isLatestVersions = $.isLatestVersions;
        this.key = $.key;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetProtectionCapabilitiesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetProtectionCapabilitiesPlainArgs $;

        public Builder() {
            $ = new GetProtectionCapabilitiesPlainArgs();
        }

        public Builder(GetProtectionCapabilitiesPlainArgs defaults) {
            $ = new GetProtectionCapabilitiesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
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

        public Builder filters(@Nullable List<GetProtectionCapabilitiesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetProtectionCapabilitiesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param groupTags A filter to return only resources that are accociated given group tag.
         * 
         * @return builder
         * 
         */
        public Builder groupTags(@Nullable List<String> groupTags) {
            $.groupTags = groupTags;
            return this;
        }

        /**
         * @param groupTags A filter to return only resources that are accociated given group tag.
         * 
         * @return builder
         * 
         */
        public Builder groupTags(String... groupTags) {
            return groupTags(List.of(groupTags));
        }

        /**
         * @param isLatestVersions A filter to return only resources that matches given isLatestVersion.
         * 
         * @return builder
         * 
         */
        public Builder isLatestVersions(@Nullable List<Boolean> isLatestVersions) {
            $.isLatestVersions = isLatestVersions;
            return this;
        }

        /**
         * @param isLatestVersions A filter to return only resources that matches given isLatestVersion.
         * 
         * @return builder
         * 
         */
        public Builder isLatestVersions(Boolean... isLatestVersions) {
            return isLatestVersions(List.of(isLatestVersions));
        }

        /**
         * @param key The unique key of protection capability to filter by.
         * 
         * @return builder
         * 
         */
        public Builder key(@Nullable String key) {
            $.key = key;
            return this;
        }

        /**
         * @param type A filter to return only resources that matches given type.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable String type) {
            $.type = type;
            return this;
        }

        public GetProtectionCapabilitiesPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetProtectionCapabilitiesPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
