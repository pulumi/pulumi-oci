// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OsManagementHub.inputs.GetLifecycleEnvironmentsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetLifecycleEnvironmentsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetLifecycleEnvironmentsArgs Empty = new GetLifecycleEnvironmentsArgs();

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
     * (Updatable) The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
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
    private @Nullable Output<List<GetLifecycleEnvironmentsFilterArgs>> filters;

    public Optional<Output<List<GetLifecycleEnvironmentsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle environment.
     * 
     */
    @Import(name="lifecycleEnvironmentId")
    private @Nullable Output<String> lifecycleEnvironmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle environment.
     * 
     */
    public Optional<Output<String>> lifecycleEnvironmentId() {
        return Optional.ofNullable(this.lifecycleEnvironmentId);
    }

    /**
     * A filter to return only resources whose location does not match the given value.
     * 
     */
    @Import(name="locationNotEqualTos")
    private @Nullable Output<List<String>> locationNotEqualTos;

    /**
     * @return A filter to return only resources whose location does not match the given value.
     * 
     */
    public Optional<Output<List<String>>> locationNotEqualTos() {
        return Optional.ofNullable(this.locationNotEqualTos);
    }

    /**
     * A filter to return only resources whose location matches the given value.
     * 
     */
    @Import(name="locations")
    private @Nullable Output<List<String>> locations;

    /**
     * @return A filter to return only resources whose location matches the given value.
     * 
     */
    public Optional<Output<List<String>>> locations() {
        return Optional.ofNullable(this.locations);
    }

    /**
     * A filter to return only resources that match the given operating system family.
     * 
     */
    @Import(name="osFamily")
    private @Nullable Output<String> osFamily;

    /**
     * @return A filter to return only resources that match the given operating system family.
     * 
     */
    public Optional<Output<String>> osFamily() {
        return Optional.ofNullable(this.osFamily);
    }

    /**
     * A filter to return only the lifecycle environments that match the display name given.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only the lifecycle environments that match the display name given.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetLifecycleEnvironmentsArgs() {}

    private GetLifecycleEnvironmentsArgs(GetLifecycleEnvironmentsArgs $) {
        this.archType = $.archType;
        this.compartmentId = $.compartmentId;
        this.displayNameContains = $.displayNameContains;
        this.displayNames = $.displayNames;
        this.filters = $.filters;
        this.lifecycleEnvironmentId = $.lifecycleEnvironmentId;
        this.locationNotEqualTos = $.locationNotEqualTos;
        this.locations = $.locations;
        this.osFamily = $.osFamily;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetLifecycleEnvironmentsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetLifecycleEnvironmentsArgs $;

        public Builder() {
            $ = new GetLifecycleEnvironmentsArgs();
        }

        public Builder(GetLifecycleEnvironmentsArgs defaults) {
            $ = new GetLifecycleEnvironmentsArgs(Objects.requireNonNull(defaults));
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
         * @param compartmentId (Updatable) The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
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

        public Builder filters(@Nullable Output<List<GetLifecycleEnvironmentsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetLifecycleEnvironmentsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetLifecycleEnvironmentsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param lifecycleEnvironmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle environment.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleEnvironmentId(@Nullable Output<String> lifecycleEnvironmentId) {
            $.lifecycleEnvironmentId = lifecycleEnvironmentId;
            return this;
        }

        /**
         * @param lifecycleEnvironmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle environment.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleEnvironmentId(String lifecycleEnvironmentId) {
            return lifecycleEnvironmentId(Output.of(lifecycleEnvironmentId));
        }

        /**
         * @param locationNotEqualTos A filter to return only resources whose location does not match the given value.
         * 
         * @return builder
         * 
         */
        public Builder locationNotEqualTos(@Nullable Output<List<String>> locationNotEqualTos) {
            $.locationNotEqualTos = locationNotEqualTos;
            return this;
        }

        /**
         * @param locationNotEqualTos A filter to return only resources whose location does not match the given value.
         * 
         * @return builder
         * 
         */
        public Builder locationNotEqualTos(List<String> locationNotEqualTos) {
            return locationNotEqualTos(Output.of(locationNotEqualTos));
        }

        /**
         * @param locationNotEqualTos A filter to return only resources whose location does not match the given value.
         * 
         * @return builder
         * 
         */
        public Builder locationNotEqualTos(String... locationNotEqualTos) {
            return locationNotEqualTos(List.of(locationNotEqualTos));
        }

        /**
         * @param locations A filter to return only resources whose location matches the given value.
         * 
         * @return builder
         * 
         */
        public Builder locations(@Nullable Output<List<String>> locations) {
            $.locations = locations;
            return this;
        }

        /**
         * @param locations A filter to return only resources whose location matches the given value.
         * 
         * @return builder
         * 
         */
        public Builder locations(List<String> locations) {
            return locations(Output.of(locations));
        }

        /**
         * @param locations A filter to return only resources whose location matches the given value.
         * 
         * @return builder
         * 
         */
        public Builder locations(String... locations) {
            return locations(List.of(locations));
        }

        /**
         * @param osFamily A filter to return only resources that match the given operating system family.
         * 
         * @return builder
         * 
         */
        public Builder osFamily(@Nullable Output<String> osFamily) {
            $.osFamily = osFamily;
            return this;
        }

        /**
         * @param osFamily A filter to return only resources that match the given operating system family.
         * 
         * @return builder
         * 
         */
        public Builder osFamily(String osFamily) {
            return osFamily(Output.of(osFamily));
        }

        /**
         * @param state A filter to return only the lifecycle environments that match the display name given.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only the lifecycle environments that match the display name given.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetLifecycleEnvironmentsArgs build() {
            return $;
        }
    }

}
