// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetAutoScalingConfigurationPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAutoScalingConfigurationPlainArgs Empty = new GetAutoScalingConfigurationPlainArgs();

    /**
     * Unique Oracle-assigned identifier of the autoscale configuration.
     * 
     */
    @Import(name="autoScalingConfigurationId", required=true)
    private String autoScalingConfigurationId;

    /**
     * @return Unique Oracle-assigned identifier of the autoscale configuration.
     * 
     */
    public String autoScalingConfigurationId() {
        return this.autoScalingConfigurationId;
    }

    /**
     * The OCID of the cluster.
     * 
     */
    @Import(name="bdsInstanceId", required=true)
    private String bdsInstanceId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public String bdsInstanceId() {
        return this.bdsInstanceId;
    }

    private GetAutoScalingConfigurationPlainArgs() {}

    private GetAutoScalingConfigurationPlainArgs(GetAutoScalingConfigurationPlainArgs $) {
        this.autoScalingConfigurationId = $.autoScalingConfigurationId;
        this.bdsInstanceId = $.bdsInstanceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAutoScalingConfigurationPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAutoScalingConfigurationPlainArgs $;

        public Builder() {
            $ = new GetAutoScalingConfigurationPlainArgs();
        }

        public Builder(GetAutoScalingConfigurationPlainArgs defaults) {
            $ = new GetAutoScalingConfigurationPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autoScalingConfigurationId Unique Oracle-assigned identifier of the autoscale configuration.
         * 
         * @return builder
         * 
         */
        public Builder autoScalingConfigurationId(String autoScalingConfigurationId) {
            $.autoScalingConfigurationId = autoScalingConfigurationId;
            return this;
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(String bdsInstanceId) {
            $.bdsInstanceId = bdsInstanceId;
            return this;
        }

        public GetAutoScalingConfigurationPlainArgs build() {
            $.autoScalingConfigurationId = Objects.requireNonNull($.autoScalingConfigurationId, "expected parameter 'autoScalingConfigurationId' to be non-null");
            $.bdsInstanceId = Objects.requireNonNull($.bdsInstanceId, "expected parameter 'bdsInstanceId' to be non-null");
            return $;
        }
    }

}