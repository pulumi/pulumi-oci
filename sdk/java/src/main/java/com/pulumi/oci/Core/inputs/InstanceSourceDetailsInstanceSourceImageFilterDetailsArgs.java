// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class InstanceSourceDetailsInstanceSourceImageFilterDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final InstanceSourceDetailsInstanceSourceImageFilterDetailsArgs Empty = new InstanceSourceDetailsInstanceSourceImageFilterDetailsArgs();

    /**
     * (Updatable) The OCID of the compartment containing images to search
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment containing images to search
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * Filter based on these defined tags. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Import(name="definedTagsFilter")
    private @Nullable Output<Map<String,Object>> definedTagsFilter;

    /**
     * @return Filter based on these defined tags. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTagsFilter() {
        return Optional.ofNullable(this.definedTagsFilter);
    }

    /**
     * The image&#39;s operating system.  Example: `Oracle Linux`
     * 
     */
    @Import(name="operatingSystem")
    private @Nullable Output<String> operatingSystem;

    /**
     * @return The image&#39;s operating system.  Example: `Oracle Linux`
     * 
     */
    public Optional<Output<String>> operatingSystem() {
        return Optional.ofNullable(this.operatingSystem);
    }

    /**
     * The image&#39;s operating system version.  Example: `7.2`
     * 
     */
    @Import(name="operatingSystemVersion")
    private @Nullable Output<String> operatingSystemVersion;

    /**
     * @return The image&#39;s operating system version.  Example: `7.2`
     * 
     */
    public Optional<Output<String>> operatingSystemVersion() {
        return Optional.ofNullable(this.operatingSystemVersion);
    }

    private InstanceSourceDetailsInstanceSourceImageFilterDetailsArgs() {}

    private InstanceSourceDetailsInstanceSourceImageFilterDetailsArgs(InstanceSourceDetailsInstanceSourceImageFilterDetailsArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTagsFilter = $.definedTagsFilter;
        this.operatingSystem = $.operatingSystem;
        this.operatingSystemVersion = $.operatingSystemVersion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(InstanceSourceDetailsInstanceSourceImageFilterDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private InstanceSourceDetailsInstanceSourceImageFilterDetailsArgs $;

        public Builder() {
            $ = new InstanceSourceDetailsInstanceSourceImageFilterDetailsArgs();
        }

        public Builder(InstanceSourceDetailsInstanceSourceImageFilterDetailsArgs defaults) {
            $ = new InstanceSourceDetailsInstanceSourceImageFilterDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment containing images to search
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment containing images to search
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTagsFilter Filter based on these defined tags. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTagsFilter(@Nullable Output<Map<String,Object>> definedTagsFilter) {
            $.definedTagsFilter = definedTagsFilter;
            return this;
        }

        /**
         * @param definedTagsFilter Filter based on these defined tags. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTagsFilter(Map<String,Object> definedTagsFilter) {
            return definedTagsFilter(Output.of(definedTagsFilter));
        }

        /**
         * @param operatingSystem The image&#39;s operating system.  Example: `Oracle Linux`
         * 
         * @return builder
         * 
         */
        public Builder operatingSystem(@Nullable Output<String> operatingSystem) {
            $.operatingSystem = operatingSystem;
            return this;
        }

        /**
         * @param operatingSystem The image&#39;s operating system.  Example: `Oracle Linux`
         * 
         * @return builder
         * 
         */
        public Builder operatingSystem(String operatingSystem) {
            return operatingSystem(Output.of(operatingSystem));
        }

        /**
         * @param operatingSystemVersion The image&#39;s operating system version.  Example: `7.2`
         * 
         * @return builder
         * 
         */
        public Builder operatingSystemVersion(@Nullable Output<String> operatingSystemVersion) {
            $.operatingSystemVersion = operatingSystemVersion;
            return this;
        }

        /**
         * @param operatingSystemVersion The image&#39;s operating system version.  Example: `7.2`
         * 
         * @return builder
         * 
         */
        public Builder operatingSystemVersion(String operatingSystemVersion) {
            return operatingSystemVersion(Output.of(operatingSystemVersion));
        }

        public InstanceSourceDetailsInstanceSourceImageFilterDetailsArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}