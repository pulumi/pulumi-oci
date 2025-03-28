// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OsManagementHub.inputs.LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class LifecycleStageDetachManagedInstancesManagementState extends com.pulumi.resources.ResourceArgs {

    public static final LifecycleStageDetachManagedInstancesManagementState Empty = new LifecycleStageDetachManagedInstancesManagementState();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
     * 
     */
    @Import(name="lifecycleStageId")
    private @Nullable Output<String> lifecycleStageId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
     * 
     */
    public Optional<Output<String>> lifecycleStageId() {
        return Optional.ofNullable(this.lifecycleStageId);
    }

    /**
     * The details about the managed instances.
     * 
     */
    @Import(name="managedInstanceDetails")
    private @Nullable Output<LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs> managedInstanceDetails;

    /**
     * @return The details about the managed instances.
     * 
     */
    public Optional<Output<LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs>> managedInstanceDetails() {
        return Optional.ofNullable(this.managedInstanceDetails);
    }

    private LifecycleStageDetachManagedInstancesManagementState() {}

    private LifecycleStageDetachManagedInstancesManagementState(LifecycleStageDetachManagedInstancesManagementState $) {
        this.lifecycleStageId = $.lifecycleStageId;
        this.managedInstanceDetails = $.managedInstanceDetails;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(LifecycleStageDetachManagedInstancesManagementState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private LifecycleStageDetachManagedInstancesManagementState $;

        public Builder() {
            $ = new LifecycleStageDetachManagedInstancesManagementState();
        }

        public Builder(LifecycleStageDetachManagedInstancesManagementState defaults) {
            $ = new LifecycleStageDetachManagedInstancesManagementState(Objects.requireNonNull(defaults));
        }

        /**
         * @param lifecycleStageId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleStageId(@Nullable Output<String> lifecycleStageId) {
            $.lifecycleStageId = lifecycleStageId;
            return this;
        }

        /**
         * @param lifecycleStageId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleStageId(String lifecycleStageId) {
            return lifecycleStageId(Output.of(lifecycleStageId));
        }

        /**
         * @param managedInstanceDetails The details about the managed instances.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceDetails(@Nullable Output<LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs> managedInstanceDetails) {
            $.managedInstanceDetails = managedInstanceDetails;
            return this;
        }

        /**
         * @param managedInstanceDetails The details about the managed instances.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceDetails(LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs managedInstanceDetails) {
            return managedInstanceDetails(Output.of(managedInstanceDetails));
        }

        public LifecycleStageDetachManagedInstancesManagementState build() {
            return $;
        }
    }

}
