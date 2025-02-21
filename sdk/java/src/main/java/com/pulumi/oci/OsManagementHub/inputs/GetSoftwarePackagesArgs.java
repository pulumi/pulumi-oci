// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OsManagementHub.inputs.GetSoftwarePackagesFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSoftwarePackagesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSoftwarePackagesArgs Empty = new GetSoftwarePackagesArgs();

    /**
     * A filter to return software packages that match the given architecture.
     * 
     */
    @Import(name="architecture")
    private @Nullable Output<String> architecture;

    /**
     * @return A filter to return software packages that match the given architecture.
     * 
     */
    public Optional<Output<String>> architecture() {
        return Optional.ofNullable(this.architecture);
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
    private @Nullable Output<List<GetSoftwarePackagesFilterArgs>> filters;

    public Optional<Output<List<GetSoftwarePackagesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Indicates whether to list only the latest versions of packages, module streams, and stream profiles.
     * 
     */
    @Import(name="isLatest")
    private @Nullable Output<Boolean> isLatest;

    /**
     * @return Indicates whether to list only the latest versions of packages, module streams, and stream profiles.
     * 
     */
    public Optional<Output<Boolean>> isLatest() {
        return Optional.ofNullable(this.isLatest);
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
     * A filter to return software packages that match the given version.
     * 
     */
    @Import(name="version")
    private @Nullable Output<String> version;

    /**
     * @return A filter to return software packages that match the given version.
     * 
     */
    public Optional<Output<String>> version() {
        return Optional.ofNullable(this.version);
    }

    private GetSoftwarePackagesArgs() {}

    private GetSoftwarePackagesArgs(GetSoftwarePackagesArgs $) {
        this.architecture = $.architecture;
        this.displayName = $.displayName;
        this.displayNameContains = $.displayNameContains;
        this.filters = $.filters;
        this.isLatest = $.isLatest;
        this.osFamily = $.osFamily;
        this.version = $.version;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSoftwarePackagesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSoftwarePackagesArgs $;

        public Builder() {
            $ = new GetSoftwarePackagesArgs();
        }

        public Builder(GetSoftwarePackagesArgs defaults) {
            $ = new GetSoftwarePackagesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param architecture A filter to return software packages that match the given architecture.
         * 
         * @return builder
         * 
         */
        public Builder architecture(@Nullable Output<String> architecture) {
            $.architecture = architecture;
            return this;
        }

        /**
         * @param architecture A filter to return software packages that match the given architecture.
         * 
         * @return builder
         * 
         */
        public Builder architecture(String architecture) {
            return architecture(Output.of(architecture));
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

        public Builder filters(@Nullable Output<List<GetSoftwarePackagesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetSoftwarePackagesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetSoftwarePackagesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isLatest Indicates whether to list only the latest versions of packages, module streams, and stream profiles.
         * 
         * @return builder
         * 
         */
        public Builder isLatest(@Nullable Output<Boolean> isLatest) {
            $.isLatest = isLatest;
            return this;
        }

        /**
         * @param isLatest Indicates whether to list only the latest versions of packages, module streams, and stream profiles.
         * 
         * @return builder
         * 
         */
        public Builder isLatest(Boolean isLatest) {
            return isLatest(Output.of(isLatest));
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
         * @param version A filter to return software packages that match the given version.
         * 
         * @return builder
         * 
         */
        public Builder version(@Nullable Output<String> version) {
            $.version = version;
            return this;
        }

        /**
         * @param version A filter to return software packages that match the given version.
         * 
         * @return builder
         * 
         */
        public Builder version(String version) {
            return version(Output.of(version));
        }

        public GetSoftwarePackagesArgs build() {
            return $;
        }
    }

}
