// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.inputs.GetManagedInstanceInstalledWindowsUpdatesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagedInstanceInstalledWindowsUpdatesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedInstanceInstalledWindowsUpdatesArgs Empty = new GetManagedInstanceInstalledWindowsUpdatesArgs();

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
     * A filter to return resources that match the given user-friendly name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return resources that match the given user-friendly name.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
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

    @Import(name="filters")
    private @Nullable Output<List<GetManagedInstanceInstalledWindowsUpdatesFilterArgs>> filters;

    public Optional<Output<List<GetManagedInstanceInstalledWindowsUpdatesFilterArgs>>> filters() {
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

    /**
     * A filter based on the unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.  Example: &#39;6981d463-cd91-4a26-b7c4-ea4ded9183ed&#39;
     * 
     */
    @Import(name="names")
    private @Nullable Output<List<String>> names;

    /**
     * @return A filter based on the unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.  Example: &#39;6981d463-cd91-4a26-b7c4-ea4ded9183ed&#39;
     * 
     */
    public Optional<Output<List<String>>> names() {
        return Optional.ofNullable(this.names);
    }

    private GetManagedInstanceInstalledWindowsUpdatesArgs() {}

    private GetManagedInstanceInstalledWindowsUpdatesArgs(GetManagedInstanceInstalledWindowsUpdatesArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.displayNameContains = $.displayNameContains;
        this.filters = $.filters;
        this.managedInstanceId = $.managedInstanceId;
        this.names = $.names;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedInstanceInstalledWindowsUpdatesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedInstanceInstalledWindowsUpdatesArgs $;

        public Builder() {
            $ = new GetManagedInstanceInstalledWindowsUpdatesArgs();
        }

        public Builder(GetManagedInstanceInstalledWindowsUpdatesArgs defaults) {
            $ = new GetManagedInstanceInstalledWindowsUpdatesArgs(Objects.requireNonNull(defaults));
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
         * @param displayName A filter to return resources that match the given user-friendly name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return resources that match the given user-friendly name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
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

        public Builder filters(@Nullable Output<List<GetManagedInstanceInstalledWindowsUpdatesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetManagedInstanceInstalledWindowsUpdatesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetManagedInstanceInstalledWindowsUpdatesFilterArgs... filters) {
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

        /**
         * @param names A filter based on the unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.  Example: &#39;6981d463-cd91-4a26-b7c4-ea4ded9183ed&#39;
         * 
         * @return builder
         * 
         */
        public Builder names(@Nullable Output<List<String>> names) {
            $.names = names;
            return this;
        }

        /**
         * @param names A filter based on the unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.  Example: &#39;6981d463-cd91-4a26-b7c4-ea4ded9183ed&#39;
         * 
         * @return builder
         * 
         */
        public Builder names(List<String> names) {
            return names(Output.of(names));
        }

        /**
         * @param names A filter based on the unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.  Example: &#39;6981d463-cd91-4a26-b7c4-ea4ded9183ed&#39;
         * 
         * @return builder
         * 
         */
        public Builder names(String... names) {
            return names(List.of(names));
        }

        public GetManagedInstanceInstalledWindowsUpdatesArgs build() {
            if ($.managedInstanceId == null) {
                throw new MissingRequiredPropertyException("GetManagedInstanceInstalledWindowsUpdatesArgs", "managedInstanceId");
            }
            return $;
        }
    }

}
