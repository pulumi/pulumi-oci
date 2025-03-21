// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.inputs.GetProfileAvailableSoftwareSourcesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetProfileAvailableSoftwareSourcesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetProfileAvailableSoftwareSourcesArgs Empty = new GetProfileAvailableSoftwareSourcesArgs();

    /**
     * The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * A filter to return resources that may partially match the given display name.
     * 
     */
    @Import(name="displayNameContains")
    private @Nullable Output<String> displayNameContains;

    /**
     * @return A filter to return resources that may partially match the given display name.
     * 
     */
    public Optional<Output<String>> displayNameContains() {
        return Optional.ofNullable(this.displayNameContains);
    }

    /**
     * A filter to return resources that match the given display names.
     * 
     */
    @Import(name="displayNames")
    private @Nullable Output<List<String>> displayNames;

    /**
     * @return A filter to return resources that match the given display names.
     * 
     */
    public Optional<Output<List<String>>> displayNames() {
        return Optional.ofNullable(this.displayNames);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetProfileAvailableSoftwareSourcesFilterArgs>> filters;

    public Optional<Output<List<GetProfileAvailableSoftwareSourcesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
     * 
     */
    @Import(name="profileId", required=true)
    private Output<String> profileId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
     * 
     */
    public Output<String> profileId() {
        return this.profileId;
    }

    private GetProfileAvailableSoftwareSourcesArgs() {}

    private GetProfileAvailableSoftwareSourcesArgs(GetProfileAvailableSoftwareSourcesArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayNameContains = $.displayNameContains;
        this.displayNames = $.displayNames;
        this.filters = $.filters;
        this.profileId = $.profileId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetProfileAvailableSoftwareSourcesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetProfileAvailableSoftwareSourcesArgs $;

        public Builder() {
            $ = new GetProfileAvailableSoftwareSourcesArgs();
        }

        public Builder(GetProfileAvailableSoftwareSourcesArgs defaults) {
            $ = new GetProfileAvailableSoftwareSourcesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayNameContains A filter to return resources that may partially match the given display name.
         * 
         * @return builder
         * 
         */
        public Builder displayNameContains(@Nullable Output<String> displayNameContains) {
            $.displayNameContains = displayNameContains;
            return this;
        }

        /**
         * @param displayNameContains A filter to return resources that may partially match the given display name.
         * 
         * @return builder
         * 
         */
        public Builder displayNameContains(String displayNameContains) {
            return displayNameContains(Output.of(displayNameContains));
        }

        /**
         * @param displayNames A filter to return resources that match the given display names.
         * 
         * @return builder
         * 
         */
        public Builder displayNames(@Nullable Output<List<String>> displayNames) {
            $.displayNames = displayNames;
            return this;
        }

        /**
         * @param displayNames A filter to return resources that match the given display names.
         * 
         * @return builder
         * 
         */
        public Builder displayNames(List<String> displayNames) {
            return displayNames(Output.of(displayNames));
        }

        /**
         * @param displayNames A filter to return resources that match the given display names.
         * 
         * @return builder
         * 
         */
        public Builder displayNames(String... displayNames) {
            return displayNames(List.of(displayNames));
        }

        public Builder filters(@Nullable Output<List<GetProfileAvailableSoftwareSourcesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetProfileAvailableSoftwareSourcesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetProfileAvailableSoftwareSourcesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param profileId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
         * 
         * @return builder
         * 
         */
        public Builder profileId(Output<String> profileId) {
            $.profileId = profileId;
            return this;
        }

        /**
         * @param profileId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
         * 
         * @return builder
         * 
         */
        public Builder profileId(String profileId) {
            return profileId(Output.of(profileId));
        }

        public GetProfileAvailableSoftwareSourcesArgs build() {
            if ($.profileId == null) {
                throw new MissingRequiredPropertyException("GetProfileAvailableSoftwareSourcesArgs", "profileId");
            }
            return $;
        }
    }

}
