// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeployEnvironmentComputeInstanceGroupSelectorsItemArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeployEnvironmentComputeInstanceGroupSelectorsItemArgs Empty = new DeployEnvironmentComputeInstanceGroupSelectorsItemArgs();

    /**
     * (Updatable) Compute instance OCID identifiers that are members of this group.
     * 
     */
    @Import(name="computeInstanceIds")
    private @Nullable Output<List<String>> computeInstanceIds;

    /**
     * @return (Updatable) Compute instance OCID identifiers that are members of this group.
     * 
     */
    public Optional<Output<List<String>>> computeInstanceIds() {
        return Optional.ofNullable(this.computeInstanceIds);
    }

    /**
     * (Updatable) Query expression confirming to the Oracle Cloud Infrastructure Search Language syntax to select compute instances for the group. The language is documented at https://docs.oracle.com/en-us/iaas/Content/Search/Concepts/querysyntax.htm
     * 
     */
    @Import(name="query")
    private @Nullable Output<String> query;

    /**
     * @return (Updatable) Query expression confirming to the Oracle Cloud Infrastructure Search Language syntax to select compute instances for the group. The language is documented at https://docs.oracle.com/en-us/iaas/Content/Search/Concepts/querysyntax.htm
     * 
     */
    public Optional<Output<String>> query() {
        return Optional.ofNullable(this.query);
    }

    /**
     * (Updatable) Region identifier referred by the deployment environment. Region identifiers are listed at https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm
     * 
     */
    @Import(name="region")
    private @Nullable Output<String> region;

    /**
     * @return (Updatable) Region identifier referred by the deployment environment. Region identifiers are listed at https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm
     * 
     */
    public Optional<Output<String>> region() {
        return Optional.ofNullable(this.region);
    }

    /**
     * (Updatable) Defines the type of the instance selector for the group.
     * 
     */
    @Import(name="selectorType", required=true)
    private Output<String> selectorType;

    /**
     * @return (Updatable) Defines the type of the instance selector for the group.
     * 
     */
    public Output<String> selectorType() {
        return this.selectorType;
    }

    private DeployEnvironmentComputeInstanceGroupSelectorsItemArgs() {}

    private DeployEnvironmentComputeInstanceGroupSelectorsItemArgs(DeployEnvironmentComputeInstanceGroupSelectorsItemArgs $) {
        this.computeInstanceIds = $.computeInstanceIds;
        this.query = $.query;
        this.region = $.region;
        this.selectorType = $.selectorType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeployEnvironmentComputeInstanceGroupSelectorsItemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeployEnvironmentComputeInstanceGroupSelectorsItemArgs $;

        public Builder() {
            $ = new DeployEnvironmentComputeInstanceGroupSelectorsItemArgs();
        }

        public Builder(DeployEnvironmentComputeInstanceGroupSelectorsItemArgs defaults) {
            $ = new DeployEnvironmentComputeInstanceGroupSelectorsItemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param computeInstanceIds (Updatable) Compute instance OCID identifiers that are members of this group.
         * 
         * @return builder
         * 
         */
        public Builder computeInstanceIds(@Nullable Output<List<String>> computeInstanceIds) {
            $.computeInstanceIds = computeInstanceIds;
            return this;
        }

        /**
         * @param computeInstanceIds (Updatable) Compute instance OCID identifiers that are members of this group.
         * 
         * @return builder
         * 
         */
        public Builder computeInstanceIds(List<String> computeInstanceIds) {
            return computeInstanceIds(Output.of(computeInstanceIds));
        }

        /**
         * @param computeInstanceIds (Updatable) Compute instance OCID identifiers that are members of this group.
         * 
         * @return builder
         * 
         */
        public Builder computeInstanceIds(String... computeInstanceIds) {
            return computeInstanceIds(List.of(computeInstanceIds));
        }

        /**
         * @param query (Updatable) Query expression confirming to the Oracle Cloud Infrastructure Search Language syntax to select compute instances for the group. The language is documented at https://docs.oracle.com/en-us/iaas/Content/Search/Concepts/querysyntax.htm
         * 
         * @return builder
         * 
         */
        public Builder query(@Nullable Output<String> query) {
            $.query = query;
            return this;
        }

        /**
         * @param query (Updatable) Query expression confirming to the Oracle Cloud Infrastructure Search Language syntax to select compute instances for the group. The language is documented at https://docs.oracle.com/en-us/iaas/Content/Search/Concepts/querysyntax.htm
         * 
         * @return builder
         * 
         */
        public Builder query(String query) {
            return query(Output.of(query));
        }

        /**
         * @param region (Updatable) Region identifier referred by the deployment environment. Region identifiers are listed at https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm
         * 
         * @return builder
         * 
         */
        public Builder region(@Nullable Output<String> region) {
            $.region = region;
            return this;
        }

        /**
         * @param region (Updatable) Region identifier referred by the deployment environment. Region identifiers are listed at https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm
         * 
         * @return builder
         * 
         */
        public Builder region(String region) {
            return region(Output.of(region));
        }

        /**
         * @param selectorType (Updatable) Defines the type of the instance selector for the group.
         * 
         * @return builder
         * 
         */
        public Builder selectorType(Output<String> selectorType) {
            $.selectorType = selectorType;
            return this;
        }

        /**
         * @param selectorType (Updatable) Defines the type of the instance selector for the group.
         * 
         * @return builder
         * 
         */
        public Builder selectorType(String selectorType) {
            return selectorType(Output.of(selectorType));
        }

        public DeployEnvironmentComputeInstanceGroupSelectorsItemArgs build() {
            if ($.selectorType == null) {
                throw new MissingRequiredPropertyException("DeployEnvironmentComputeInstanceGroupSelectorsItemArgs", "selectorType");
            }
            return $;
        }
    }

}
