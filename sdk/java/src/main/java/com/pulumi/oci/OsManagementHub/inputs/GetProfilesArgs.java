// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OsManagementHub.inputs.GetProfilesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetProfilesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetProfilesArgs Empty = new GetProfilesArgs();

    /**
     * A filter to return only profiles that match the given archType.
     * 
     */
    @Import(name="archType")
    private @Nullable Output<String> archType;

    /**
     * @return A filter to return only profiles that match the given archType.
     * 
     */
    public Optional<Output<String>> archType() {
        return Optional.ofNullable(this.archType);
    }

    /**
     * The OCID of the compartment that contains the resources to list.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment that contains the resources to list.
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
    private @Nullable Output<List<GetProfilesFilterArgs>> filters;

    public Optional<Output<List<GetProfilesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only profiles that match the given osFamily.
     * 
     */
    @Import(name="osFamily")
    private @Nullable Output<String> osFamily;

    /**
     * @return A filter to return only profiles that match the given osFamily.
     * 
     */
    public Optional<Output<String>> osFamily() {
        return Optional.ofNullable(this.osFamily);
    }

    /**
     * The OCID of the registration profile.
     * 
     */
    @Import(name="profileId")
    private @Nullable Output<String> profileId;

    /**
     * @return The OCID of the registration profile.
     * 
     */
    public Optional<Output<String>> profileId() {
        return Optional.ofNullable(this.profileId);
    }

    /**
     * A filter to return registration profiles that match the given profileType.
     * 
     */
    @Import(name="profileTypes")
    private @Nullable Output<List<String>> profileTypes;

    /**
     * @return A filter to return registration profiles that match the given profileType.
     * 
     */
    public Optional<Output<List<String>>> profileTypes() {
        return Optional.ofNullable(this.profileTypes);
    }

    /**
     * A filter to return only registration profile whose lifecycleState matches the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only registration profile whose lifecycleState matches the given lifecycleState.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter to return only profiles that match the given vendorName.
     * 
     */
    @Import(name="vendorName")
    private @Nullable Output<String> vendorName;

    /**
     * @return A filter to return only profiles that match the given vendorName.
     * 
     */
    public Optional<Output<String>> vendorName() {
        return Optional.ofNullable(this.vendorName);
    }

    private GetProfilesArgs() {}

    private GetProfilesArgs(GetProfilesArgs $) {
        this.archType = $.archType;
        this.compartmentId = $.compartmentId;
        this.displayNameContains = $.displayNameContains;
        this.displayNames = $.displayNames;
        this.filters = $.filters;
        this.osFamily = $.osFamily;
        this.profileId = $.profileId;
        this.profileTypes = $.profileTypes;
        this.state = $.state;
        this.vendorName = $.vendorName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetProfilesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetProfilesArgs $;

        public Builder() {
            $ = new GetProfilesArgs();
        }

        public Builder(GetProfilesArgs defaults) {
            $ = new GetProfilesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param archType A filter to return only profiles that match the given archType.
         * 
         * @return builder
         * 
         */
        public Builder archType(@Nullable Output<String> archType) {
            $.archType = archType;
            return this;
        }

        /**
         * @param archType A filter to return only profiles that match the given archType.
         * 
         * @return builder
         * 
         */
        public Builder archType(String archType) {
            return archType(Output.of(archType));
        }

        /**
         * @param compartmentId The OCID of the compartment that contains the resources to list.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment that contains the resources to list.
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

        public Builder filters(@Nullable Output<List<GetProfilesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetProfilesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetProfilesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param osFamily A filter to return only profiles that match the given osFamily.
         * 
         * @return builder
         * 
         */
        public Builder osFamily(@Nullable Output<String> osFamily) {
            $.osFamily = osFamily;
            return this;
        }

        /**
         * @param osFamily A filter to return only profiles that match the given osFamily.
         * 
         * @return builder
         * 
         */
        public Builder osFamily(String osFamily) {
            return osFamily(Output.of(osFamily));
        }

        /**
         * @param profileId The OCID of the registration profile.
         * 
         * @return builder
         * 
         */
        public Builder profileId(@Nullable Output<String> profileId) {
            $.profileId = profileId;
            return this;
        }

        /**
         * @param profileId The OCID of the registration profile.
         * 
         * @return builder
         * 
         */
        public Builder profileId(String profileId) {
            return profileId(Output.of(profileId));
        }

        /**
         * @param profileTypes A filter to return registration profiles that match the given profileType.
         * 
         * @return builder
         * 
         */
        public Builder profileTypes(@Nullable Output<List<String>> profileTypes) {
            $.profileTypes = profileTypes;
            return this;
        }

        /**
         * @param profileTypes A filter to return registration profiles that match the given profileType.
         * 
         * @return builder
         * 
         */
        public Builder profileTypes(List<String> profileTypes) {
            return profileTypes(Output.of(profileTypes));
        }

        /**
         * @param profileTypes A filter to return registration profiles that match the given profileType.
         * 
         * @return builder
         * 
         */
        public Builder profileTypes(String... profileTypes) {
            return profileTypes(List.of(profileTypes));
        }

        /**
         * @param state A filter to return only registration profile whose lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only registration profile whose lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param vendorName A filter to return only profiles that match the given vendorName.
         * 
         * @return builder
         * 
         */
        public Builder vendorName(@Nullable Output<String> vendorName) {
            $.vendorName = vendorName;
            return this;
        }

        /**
         * @param vendorName A filter to return only profiles that match the given vendorName.
         * 
         * @return builder
         * 
         */
        public Builder vendorName(String vendorName) {
            return vendorName(Output.of(vendorName));
        }

        public GetProfilesArgs build() {
            return $;
        }
    }

}