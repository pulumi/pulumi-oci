// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudMigrations.inputs.TargetAssetUserSpecAgentConfigPluginsConfigArgs;
import java.lang.Boolean;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TargetAssetUserSpecAgentConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final TargetAssetUserSpecAgentConfigArgs Empty = new TargetAssetUserSpecAgentConfigArgs();

    /**
     * (Updatable) Whether Oracle Cloud Agent can run all the available plugins. This includes the management and monitoring plugins.
     * 
     */
    @Import(name="areAllPluginsDisabled")
    private @Nullable Output<Boolean> areAllPluginsDisabled;

    /**
     * @return (Updatable) Whether Oracle Cloud Agent can run all the available plugins. This includes the management and monitoring plugins.
     * 
     */
    public Optional<Output<Boolean>> areAllPluginsDisabled() {
        return Optional.ofNullable(this.areAllPluginsDisabled);
    }

    /**
     * (Updatable) Whether Oracle Cloud Agent can run all the available management plugins. By default, the value is false (management plugins are enabled).
     * 
     */
    @Import(name="isManagementDisabled")
    private @Nullable Output<Boolean> isManagementDisabled;

    /**
     * @return (Updatable) Whether Oracle Cloud Agent can run all the available management plugins. By default, the value is false (management plugins are enabled).
     * 
     */
    public Optional<Output<Boolean>> isManagementDisabled() {
        return Optional.ofNullable(this.isManagementDisabled);
    }

    /**
     * (Updatable) Whether Oracle Cloud Agent can gather performance metrics and monitor the instance using the monitoring plugins. By default, the value is false (monitoring plugins are enabled).
     * 
     */
    @Import(name="isMonitoringDisabled")
    private @Nullable Output<Boolean> isMonitoringDisabled;

    /**
     * @return (Updatable) Whether Oracle Cloud Agent can gather performance metrics and monitor the instance using the monitoring plugins. By default, the value is false (monitoring plugins are enabled).
     * 
     */
    public Optional<Output<Boolean>> isMonitoringDisabled() {
        return Optional.ofNullable(this.isMonitoringDisabled);
    }

    /**
     * (Updatable) The configuration of plugins associated with this instance.
     * 
     */
    @Import(name="pluginsConfigs")
    private @Nullable Output<List<TargetAssetUserSpecAgentConfigPluginsConfigArgs>> pluginsConfigs;

    /**
     * @return (Updatable) The configuration of plugins associated with this instance.
     * 
     */
    public Optional<Output<List<TargetAssetUserSpecAgentConfigPluginsConfigArgs>>> pluginsConfigs() {
        return Optional.ofNullable(this.pluginsConfigs);
    }

    private TargetAssetUserSpecAgentConfigArgs() {}

    private TargetAssetUserSpecAgentConfigArgs(TargetAssetUserSpecAgentConfigArgs $) {
        this.areAllPluginsDisabled = $.areAllPluginsDisabled;
        this.isManagementDisabled = $.isManagementDisabled;
        this.isMonitoringDisabled = $.isMonitoringDisabled;
        this.pluginsConfigs = $.pluginsConfigs;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TargetAssetUserSpecAgentConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TargetAssetUserSpecAgentConfigArgs $;

        public Builder() {
            $ = new TargetAssetUserSpecAgentConfigArgs();
        }

        public Builder(TargetAssetUserSpecAgentConfigArgs defaults) {
            $ = new TargetAssetUserSpecAgentConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param areAllPluginsDisabled (Updatable) Whether Oracle Cloud Agent can run all the available plugins. This includes the management and monitoring plugins.
         * 
         * @return builder
         * 
         */
        public Builder areAllPluginsDisabled(@Nullable Output<Boolean> areAllPluginsDisabled) {
            $.areAllPluginsDisabled = areAllPluginsDisabled;
            return this;
        }

        /**
         * @param areAllPluginsDisabled (Updatable) Whether Oracle Cloud Agent can run all the available plugins. This includes the management and monitoring plugins.
         * 
         * @return builder
         * 
         */
        public Builder areAllPluginsDisabled(Boolean areAllPluginsDisabled) {
            return areAllPluginsDisabled(Output.of(areAllPluginsDisabled));
        }

        /**
         * @param isManagementDisabled (Updatable) Whether Oracle Cloud Agent can run all the available management plugins. By default, the value is false (management plugins are enabled).
         * 
         * @return builder
         * 
         */
        public Builder isManagementDisabled(@Nullable Output<Boolean> isManagementDisabled) {
            $.isManagementDisabled = isManagementDisabled;
            return this;
        }

        /**
         * @param isManagementDisabled (Updatable) Whether Oracle Cloud Agent can run all the available management plugins. By default, the value is false (management plugins are enabled).
         * 
         * @return builder
         * 
         */
        public Builder isManagementDisabled(Boolean isManagementDisabled) {
            return isManagementDisabled(Output.of(isManagementDisabled));
        }

        /**
         * @param isMonitoringDisabled (Updatable) Whether Oracle Cloud Agent can gather performance metrics and monitor the instance using the monitoring plugins. By default, the value is false (monitoring plugins are enabled).
         * 
         * @return builder
         * 
         */
        public Builder isMonitoringDisabled(@Nullable Output<Boolean> isMonitoringDisabled) {
            $.isMonitoringDisabled = isMonitoringDisabled;
            return this;
        }

        /**
         * @param isMonitoringDisabled (Updatable) Whether Oracle Cloud Agent can gather performance metrics and monitor the instance using the monitoring plugins. By default, the value is false (monitoring plugins are enabled).
         * 
         * @return builder
         * 
         */
        public Builder isMonitoringDisabled(Boolean isMonitoringDisabled) {
            return isMonitoringDisabled(Output.of(isMonitoringDisabled));
        }

        /**
         * @param pluginsConfigs (Updatable) The configuration of plugins associated with this instance.
         * 
         * @return builder
         * 
         */
        public Builder pluginsConfigs(@Nullable Output<List<TargetAssetUserSpecAgentConfigPluginsConfigArgs>> pluginsConfigs) {
            $.pluginsConfigs = pluginsConfigs;
            return this;
        }

        /**
         * @param pluginsConfigs (Updatable) The configuration of plugins associated with this instance.
         * 
         * @return builder
         * 
         */
        public Builder pluginsConfigs(List<TargetAssetUserSpecAgentConfigPluginsConfigArgs> pluginsConfigs) {
            return pluginsConfigs(Output.of(pluginsConfigs));
        }

        /**
         * @param pluginsConfigs (Updatable) The configuration of plugins associated with this instance.
         * 
         * @return builder
         * 
         */
        public Builder pluginsConfigs(TargetAssetUserSpecAgentConfigPluginsConfigArgs... pluginsConfigs) {
            return pluginsConfigs(List.of(pluginsConfigs));
        }

        public TargetAssetUserSpecAgentConfigArgs build() {
            return $;
        }
    }

}