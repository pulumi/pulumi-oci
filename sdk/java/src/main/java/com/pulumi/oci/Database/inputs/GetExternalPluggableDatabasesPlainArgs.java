// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Database.inputs.GetExternalPluggableDatabasesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetExternalPluggableDatabasesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetExternalPluggableDatabasesPlainArgs Empty = new GetExternalPluggableDatabasesPlainArgs();

    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The ExternalContainerDatabase [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="externalContainerDatabaseId")
    private @Nullable String externalContainerDatabaseId;

    /**
     * @return The ExternalContainerDatabase [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<String> externalContainerDatabaseId() {
        return Optional.ofNullable(this.externalContainerDatabaseId);
    }

    @Import(name="filters")
    private @Nullable List<GetExternalPluggableDatabasesFilter> filters;

    public Optional<List<GetExternalPluggableDatabasesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the specified lifecycle state.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources that match the specified lifecycle state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetExternalPluggableDatabasesPlainArgs() {}

    private GetExternalPluggableDatabasesPlainArgs(GetExternalPluggableDatabasesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.externalContainerDatabaseId = $.externalContainerDatabaseId;
        this.filters = $.filters;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetExternalPluggableDatabasesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetExternalPluggableDatabasesPlainArgs $;

        public Builder() {
            $ = new GetExternalPluggableDatabasesPlainArgs();
        }

        public Builder(GetExternalPluggableDatabasesPlainArgs defaults) {
            $ = new GetExternalPluggableDatabasesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given. The match is not case sensitive.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param externalContainerDatabaseId The ExternalContainerDatabase [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder externalContainerDatabaseId(@Nullable String externalContainerDatabaseId) {
            $.externalContainerDatabaseId = externalContainerDatabaseId;
            return this;
        }

        public Builder filters(@Nullable List<GetExternalPluggableDatabasesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetExternalPluggableDatabasesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to return only resources that match the specified lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetExternalPluggableDatabasesPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}