// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs extends com.pulumi.resources.ResourceArgs {

    public static final SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs Empty = new SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs();

    /**
     * (Updatable) The type of the filter, which can be of two types - INCLUDE or EXCLUDE.
     * 
     */
    @Import(name="filterType", required=true)
    private Output<String> filterType;

    /**
     * @return (Updatable) The type of the filter, which can be of two types - INCLUDE or EXCLUDE.
     * 
     */
    public Output<String> filterType() {
        return this.filterType;
    }

    /**
     * (Updatable) List of package group names.
     * 
     */
    @Import(name="packageGroups")
    private @Nullable Output<List<String>> packageGroups;

    /**
     * @return (Updatable) List of package group names.
     * 
     */
    public Optional<Output<List<String>>> packageGroups() {
        return Optional.ofNullable(this.packageGroups);
    }

    private SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs() {}

    private SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs(SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs $) {
        this.filterType = $.filterType;
        this.packageGroups = $.packageGroups;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs $;

        public Builder() {
            $ = new SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs();
        }

        public Builder(SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs defaults) {
            $ = new SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param filterType (Updatable) The type of the filter, which can be of two types - INCLUDE or EXCLUDE.
         * 
         * @return builder
         * 
         */
        public Builder filterType(Output<String> filterType) {
            $.filterType = filterType;
            return this;
        }

        /**
         * @param filterType (Updatable) The type of the filter, which can be of two types - INCLUDE or EXCLUDE.
         * 
         * @return builder
         * 
         */
        public Builder filterType(String filterType) {
            return filterType(Output.of(filterType));
        }

        /**
         * @param packageGroups (Updatable) List of package group names.
         * 
         * @return builder
         * 
         */
        public Builder packageGroups(@Nullable Output<List<String>> packageGroups) {
            $.packageGroups = packageGroups;
            return this;
        }

        /**
         * @param packageGroups (Updatable) List of package group names.
         * 
         * @return builder
         * 
         */
        public Builder packageGroups(List<String> packageGroups) {
            return packageGroups(Output.of(packageGroups));
        }

        /**
         * @param packageGroups (Updatable) List of package group names.
         * 
         * @return builder
         * 
         */
        public Builder packageGroups(String... packageGroups) {
            return packageGroups(List.of(packageGroups));
        }

        public SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterArgs build() {
            $.filterType = Objects.requireNonNull($.filterType, "expected parameter 'filterType' to be non-null");
            return $;
        }
    }

}