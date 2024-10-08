// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OsManagementHub.inputs.SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilterArgs;
import com.pulumi.oci.OsManagementHub.inputs.SoftwareSourceCustomSoftwareSourceFilterPackageFilterArgs;
import com.pulumi.oci.OsManagementHub.inputs.SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SoftwareSourceCustomSoftwareSourceFilterArgs extends com.pulumi.resources.ResourceArgs {

    public static final SoftwareSourceCustomSoftwareSourceFilterArgs Empty = new SoftwareSourceCustomSoftwareSourceFilterArgs();

    /**
     * (Updatable) The list of module stream/profile filters.
     * 
     */
    @Import(name="moduleStreamProfileFilters")
    private @Nullable Output<List<SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilterArgs>> moduleStreamProfileFilters;

    /**
     * @return (Updatable) The list of module stream/profile filters.
     * 
     */
    public Optional<Output<List<SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilterArgs>>> moduleStreamProfileFilters() {
        return Optional.ofNullable(this.moduleStreamProfileFilters);
    }

    /**
     * (Updatable) The list of package filters.
     * 
     */
    @Import(name="packageFilters")
    private @Nullable Output<List<SoftwareSourceCustomSoftwareSourceFilterPackageFilterArgs>> packageFilters;

    /**
     * @return (Updatable) The list of package filters.
     * 
     */
    public Optional<Output<List<SoftwareSourceCustomSoftwareSourceFilterPackageFilterArgs>>> packageFilters() {
        return Optional.ofNullable(this.packageFilters);
    }

    /**
     * (Updatable) The list of group filters.
     * 
     */
    @Import(name="packageGroupFilters")
    private @Nullable Output<List<SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs>> packageGroupFilters;

    /**
     * @return (Updatable) The list of group filters.
     * 
     */
    public Optional<Output<List<SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs>>> packageGroupFilters() {
        return Optional.ofNullable(this.packageGroupFilters);
    }

    private SoftwareSourceCustomSoftwareSourceFilterArgs() {}

    private SoftwareSourceCustomSoftwareSourceFilterArgs(SoftwareSourceCustomSoftwareSourceFilterArgs $) {
        this.moduleStreamProfileFilters = $.moduleStreamProfileFilters;
        this.packageFilters = $.packageFilters;
        this.packageGroupFilters = $.packageGroupFilters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SoftwareSourceCustomSoftwareSourceFilterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SoftwareSourceCustomSoftwareSourceFilterArgs $;

        public Builder() {
            $ = new SoftwareSourceCustomSoftwareSourceFilterArgs();
        }

        public Builder(SoftwareSourceCustomSoftwareSourceFilterArgs defaults) {
            $ = new SoftwareSourceCustomSoftwareSourceFilterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param moduleStreamProfileFilters (Updatable) The list of module stream/profile filters.
         * 
         * @return builder
         * 
         */
        public Builder moduleStreamProfileFilters(@Nullable Output<List<SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilterArgs>> moduleStreamProfileFilters) {
            $.moduleStreamProfileFilters = moduleStreamProfileFilters;
            return this;
        }

        /**
         * @param moduleStreamProfileFilters (Updatable) The list of module stream/profile filters.
         * 
         * @return builder
         * 
         */
        public Builder moduleStreamProfileFilters(List<SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilterArgs> moduleStreamProfileFilters) {
            return moduleStreamProfileFilters(Output.of(moduleStreamProfileFilters));
        }

        /**
         * @param moduleStreamProfileFilters (Updatable) The list of module stream/profile filters.
         * 
         * @return builder
         * 
         */
        public Builder moduleStreamProfileFilters(SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilterArgs... moduleStreamProfileFilters) {
            return moduleStreamProfileFilters(List.of(moduleStreamProfileFilters));
        }

        /**
         * @param packageFilters (Updatable) The list of package filters.
         * 
         * @return builder
         * 
         */
        public Builder packageFilters(@Nullable Output<List<SoftwareSourceCustomSoftwareSourceFilterPackageFilterArgs>> packageFilters) {
            $.packageFilters = packageFilters;
            return this;
        }

        /**
         * @param packageFilters (Updatable) The list of package filters.
         * 
         * @return builder
         * 
         */
        public Builder packageFilters(List<SoftwareSourceCustomSoftwareSourceFilterPackageFilterArgs> packageFilters) {
            return packageFilters(Output.of(packageFilters));
        }

        /**
         * @param packageFilters (Updatable) The list of package filters.
         * 
         * @return builder
         * 
         */
        public Builder packageFilters(SoftwareSourceCustomSoftwareSourceFilterPackageFilterArgs... packageFilters) {
            return packageFilters(List.of(packageFilters));
        }

        /**
         * @param packageGroupFilters (Updatable) The list of group filters.
         * 
         * @return builder
         * 
         */
        public Builder packageGroupFilters(@Nullable Output<List<SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs>> packageGroupFilters) {
            $.packageGroupFilters = packageGroupFilters;
            return this;
        }

        /**
         * @param packageGroupFilters (Updatable) The list of group filters.
         * 
         * @return builder
         * 
         */
        public Builder packageGroupFilters(List<SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs> packageGroupFilters) {
            return packageGroupFilters(Output.of(packageGroupFilters));
        }

        /**
         * @param packageGroupFilters (Updatable) The list of group filters.
         * 
         * @return builder
         * 
         */
        public Builder packageGroupFilters(SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs... packageGroupFilters) {
            return packageGroupFilters(List.of(packageGroupFilters));
        }

        public SoftwareSourceCustomSoftwareSourceFilterArgs build() {
            return $;
        }
    }

}
