// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetAgentDataSourceArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAgentDataSourceArgs Empty = new GetAgentDataSourceArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data source.
     * 
     */
    @Import(name="dataSourceId", required=true)
    private Output<String> dataSourceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data source.
     * 
     */
    public Output<String> dataSourceId() {
        return this.dataSourceId;
    }

    private GetAgentDataSourceArgs() {}

    private GetAgentDataSourceArgs(GetAgentDataSourceArgs $) {
        this.dataSourceId = $.dataSourceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAgentDataSourceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAgentDataSourceArgs $;

        public Builder() {
            $ = new GetAgentDataSourceArgs();
        }

        public Builder(GetAgentDataSourceArgs defaults) {
            $ = new GetAgentDataSourceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dataSourceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data source.
         * 
         * @return builder
         * 
         */
        public Builder dataSourceId(Output<String> dataSourceId) {
            $.dataSourceId = dataSourceId;
            return this;
        }

        /**
         * @param dataSourceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data source.
         * 
         * @return builder
         * 
         */
        public Builder dataSourceId(String dataSourceId) {
            return dataSourceId(Output.of(dataSourceId));
        }

        public GetAgentDataSourceArgs build() {
            if ($.dataSourceId == null) {
                throw new MissingRequiredPropertyException("GetAgentDataSourceArgs", "dataSourceId");
            }
            return $;
        }
    }

}
