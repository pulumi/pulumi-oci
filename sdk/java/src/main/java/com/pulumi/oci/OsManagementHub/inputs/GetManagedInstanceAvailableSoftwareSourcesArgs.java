// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.inputs.GetManagedInstanceAvailableSoftwareSourcesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagedInstanceAvailableSoftwareSourcesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedInstanceAvailableSoftwareSourcesArgs Empty = new GetManagedInstanceAvailableSoftwareSourcesArgs();

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
    private @Nullable Output<List<GetManagedInstanceAvailableSoftwareSourcesFilterArgs>> filters;

    public Optional<Output<List<GetManagedInstanceAvailableSoftwareSourcesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
     * 
     */
    @Import(name="managedInstanceId", required=true)
    private Output<String> managedInstanceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
     * 
     */
    public Output<String> managedInstanceId() {
        return this.managedInstanceId;
    }

    private GetManagedInstanceAvailableSoftwareSourcesArgs() {}

    private GetManagedInstanceAvailableSoftwareSourcesArgs(GetManagedInstanceAvailableSoftwareSourcesArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayNameContains = $.displayNameContains;
        this.displayNames = $.displayNames;
        this.filters = $.filters;
        this.managedInstanceId = $.managedInstanceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedInstanceAvailableSoftwareSourcesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedInstanceAvailableSoftwareSourcesArgs $;

        public Builder() {
            $ = new GetManagedInstanceAvailableSoftwareSourcesArgs();
        }

        public Builder(GetManagedInstanceAvailableSoftwareSourcesArgs defaults) {
            $ = new GetManagedInstanceAvailableSoftwareSourcesArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable Output<List<GetManagedInstanceAvailableSoftwareSourcesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetManagedInstanceAvailableSoftwareSourcesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetManagedInstanceAvailableSoftwareSourcesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param managedInstanceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceId(Output<String> managedInstanceId) {
            $.managedInstanceId = managedInstanceId;
            return this;
        }

        /**
         * @param managedInstanceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceId(String managedInstanceId) {
            return managedInstanceId(Output.of(managedInstanceId));
        }

        public GetManagedInstanceAvailableSoftwareSourcesArgs build() {
            if ($.managedInstanceId == null) {
                throw new MissingRequiredPropertyException("GetManagedInstanceAvailableSoftwareSourcesArgs", "managedInstanceId");
            }
            return $;
        }
    }

}
