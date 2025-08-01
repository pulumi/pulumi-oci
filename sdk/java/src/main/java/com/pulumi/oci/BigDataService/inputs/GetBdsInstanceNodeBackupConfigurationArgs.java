// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetBdsInstanceNodeBackupConfigurationArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBdsInstanceNodeBackupConfigurationArgs Empty = new GetBdsInstanceNodeBackupConfigurationArgs();

    /**
     * The OCID of the cluster.
     * 
     */
    @Import(name="bdsInstanceId", required=true)
    private Output<String> bdsInstanceId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public Output<String> bdsInstanceId() {
        return this.bdsInstanceId;
    }

    /**
     * Unique Oracle-assigned identifier of the NodeBackupConfiguration.
     * 
     */
    @Import(name="nodeBackupConfigurationId", required=true)
    private Output<String> nodeBackupConfigurationId;

    /**
     * @return Unique Oracle-assigned identifier of the NodeBackupConfiguration.
     * 
     */
    public Output<String> nodeBackupConfigurationId() {
        return this.nodeBackupConfigurationId;
    }

    private GetBdsInstanceNodeBackupConfigurationArgs() {}

    private GetBdsInstanceNodeBackupConfigurationArgs(GetBdsInstanceNodeBackupConfigurationArgs $) {
        this.bdsInstanceId = $.bdsInstanceId;
        this.nodeBackupConfigurationId = $.nodeBackupConfigurationId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBdsInstanceNodeBackupConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBdsInstanceNodeBackupConfigurationArgs $;

        public Builder() {
            $ = new GetBdsInstanceNodeBackupConfigurationArgs();
        }

        public Builder(GetBdsInstanceNodeBackupConfigurationArgs defaults) {
            $ = new GetBdsInstanceNodeBackupConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(Output<String> bdsInstanceId) {
            $.bdsInstanceId = bdsInstanceId;
            return this;
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(String bdsInstanceId) {
            return bdsInstanceId(Output.of(bdsInstanceId));
        }

        /**
         * @param nodeBackupConfigurationId Unique Oracle-assigned identifier of the NodeBackupConfiguration.
         * 
         * @return builder
         * 
         */
        public Builder nodeBackupConfigurationId(Output<String> nodeBackupConfigurationId) {
            $.nodeBackupConfigurationId = nodeBackupConfigurationId;
            return this;
        }

        /**
         * @param nodeBackupConfigurationId Unique Oracle-assigned identifier of the NodeBackupConfiguration.
         * 
         * @return builder
         * 
         */
        public Builder nodeBackupConfigurationId(String nodeBackupConfigurationId) {
            return nodeBackupConfigurationId(Output.of(nodeBackupConfigurationId));
        }

        public GetBdsInstanceNodeBackupConfigurationArgs build() {
            if ($.bdsInstanceId == null) {
                throw new MissingRequiredPropertyException("GetBdsInstanceNodeBackupConfigurationArgs", "bdsInstanceId");
            }
            if ($.nodeBackupConfigurationId == null) {
                throw new MissingRequiredPropertyException("GetBdsInstanceNodeBackupConfigurationArgs", "nodeBackupConfigurationId");
            }
            return $;
        }
    }

}
