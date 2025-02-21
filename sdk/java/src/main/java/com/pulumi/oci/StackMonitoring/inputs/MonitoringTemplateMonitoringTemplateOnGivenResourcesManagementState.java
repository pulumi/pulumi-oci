// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MonitoringTemplateMonitoringTemplateOnGivenResourcesManagementState extends com.pulumi.resources.ResourceArgs {

    public static final MonitoringTemplateMonitoringTemplateOnGivenResourcesManagementState Empty = new MonitoringTemplateMonitoringTemplateOnGivenResourcesManagementState();

    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="enableMonitoringTemplateOnGivenResources")
    private @Nullable Output<Boolean> enableMonitoringTemplateOnGivenResources;

    /**
     * @return (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Boolean>> enableMonitoringTemplateOnGivenResources() {
        return Optional.ofNullable(this.enableMonitoringTemplateOnGivenResources);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
     * 
     */
    @Import(name="monitoringTemplateId")
    private @Nullable Output<String> monitoringTemplateId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
     * 
     */
    public Optional<Output<String>> monitoringTemplateId() {
        return Optional.ofNullable(this.monitoringTemplateId);
    }

    private MonitoringTemplateMonitoringTemplateOnGivenResourcesManagementState() {}

    private MonitoringTemplateMonitoringTemplateOnGivenResourcesManagementState(MonitoringTemplateMonitoringTemplateOnGivenResourcesManagementState $) {
        this.enableMonitoringTemplateOnGivenResources = $.enableMonitoringTemplateOnGivenResources;
        this.monitoringTemplateId = $.monitoringTemplateId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MonitoringTemplateMonitoringTemplateOnGivenResourcesManagementState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MonitoringTemplateMonitoringTemplateOnGivenResourcesManagementState $;

        public Builder() {
            $ = new MonitoringTemplateMonitoringTemplateOnGivenResourcesManagementState();
        }

        public Builder(MonitoringTemplateMonitoringTemplateOnGivenResourcesManagementState defaults) {
            $ = new MonitoringTemplateMonitoringTemplateOnGivenResourcesManagementState(Objects.requireNonNull(defaults));
        }

        /**
         * @param enableMonitoringTemplateOnGivenResources (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder enableMonitoringTemplateOnGivenResources(@Nullable Output<Boolean> enableMonitoringTemplateOnGivenResources) {
            $.enableMonitoringTemplateOnGivenResources = enableMonitoringTemplateOnGivenResources;
            return this;
        }

        /**
         * @param enableMonitoringTemplateOnGivenResources (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder enableMonitoringTemplateOnGivenResources(Boolean enableMonitoringTemplateOnGivenResources) {
            return enableMonitoringTemplateOnGivenResources(Output.of(enableMonitoringTemplateOnGivenResources));
        }

        /**
         * @param monitoringTemplateId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
         * 
         * @return builder
         * 
         */
        public Builder monitoringTemplateId(@Nullable Output<String> monitoringTemplateId) {
            $.monitoringTemplateId = monitoringTemplateId;
            return this;
        }

        /**
         * @param monitoringTemplateId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
         * 
         * @return builder
         * 
         */
        public Builder monitoringTemplateId(String monitoringTemplateId) {
            return monitoringTemplateId(Output.of(monitoringTemplateId));
        }

        public MonitoringTemplateMonitoringTemplateOnGivenResourcesManagementState build() {
            return $;
        }
    }

}
