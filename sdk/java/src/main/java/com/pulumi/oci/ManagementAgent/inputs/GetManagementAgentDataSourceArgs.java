// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ManagementAgent.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetManagementAgentDataSourceArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagementAgentDataSourceArgs Empty = new GetManagementAgentDataSourceArgs();

    /**
     * Data source type and name identifier.
     * 
     */
    @Import(name="dataSourceKey", required=true)
    private Output<String> dataSourceKey;

    /**
     * @return Data source type and name identifier.
     * 
     */
    public Output<String> dataSourceKey() {
        return this.dataSourceKey;
    }

    /**
     * Unique Management Agent identifier
     * 
     */
    @Import(name="managementAgentId", required=true)
    private Output<String> managementAgentId;

    /**
     * @return Unique Management Agent identifier
     * 
     */
    public Output<String> managementAgentId() {
        return this.managementAgentId;
    }

    private GetManagementAgentDataSourceArgs() {}

    private GetManagementAgentDataSourceArgs(GetManagementAgentDataSourceArgs $) {
        this.dataSourceKey = $.dataSourceKey;
        this.managementAgentId = $.managementAgentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagementAgentDataSourceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagementAgentDataSourceArgs $;

        public Builder() {
            $ = new GetManagementAgentDataSourceArgs();
        }

        public Builder(GetManagementAgentDataSourceArgs defaults) {
            $ = new GetManagementAgentDataSourceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dataSourceKey Data source type and name identifier.
         * 
         * @return builder
         * 
         */
        public Builder dataSourceKey(Output<String> dataSourceKey) {
            $.dataSourceKey = dataSourceKey;
            return this;
        }

        /**
         * @param dataSourceKey Data source type and name identifier.
         * 
         * @return builder
         * 
         */
        public Builder dataSourceKey(String dataSourceKey) {
            return dataSourceKey(Output.of(dataSourceKey));
        }

        /**
         * @param managementAgentId Unique Management Agent identifier
         * 
         * @return builder
         * 
         */
        public Builder managementAgentId(Output<String> managementAgentId) {
            $.managementAgentId = managementAgentId;
            return this;
        }

        /**
         * @param managementAgentId Unique Management Agent identifier
         * 
         * @return builder
         * 
         */
        public Builder managementAgentId(String managementAgentId) {
            return managementAgentId(Output.of(managementAgentId));
        }

        public GetManagementAgentDataSourceArgs build() {
            if ($.dataSourceKey == null) {
                throw new MissingRequiredPropertyException("GetManagementAgentDataSourceArgs", "dataSourceKey");
            }
            if ($.managementAgentId == null) {
                throw new MissingRequiredPropertyException("GetManagementAgentDataSourceArgs", "managementAgentId");
            }
            return $;
        }
    }

}
