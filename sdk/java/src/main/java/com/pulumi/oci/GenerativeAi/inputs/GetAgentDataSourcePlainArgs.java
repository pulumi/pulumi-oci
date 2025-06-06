// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetAgentDataSourcePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAgentDataSourcePlainArgs Empty = new GetAgentDataSourcePlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data source.
     * 
     */
    @Import(name="dataSourceId", required=true)
    private String dataSourceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data source.
     * 
     */
    public String dataSourceId() {
        return this.dataSourceId;
    }

    private GetAgentDataSourcePlainArgs() {}

    private GetAgentDataSourcePlainArgs(GetAgentDataSourcePlainArgs $) {
        this.dataSourceId = $.dataSourceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAgentDataSourcePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAgentDataSourcePlainArgs $;

        public Builder() {
            $ = new GetAgentDataSourcePlainArgs();
        }

        public Builder(GetAgentDataSourcePlainArgs defaults) {
            $ = new GetAgentDataSourcePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dataSourceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data source.
         * 
         * @return builder
         * 
         */
        public Builder dataSourceId(String dataSourceId) {
            $.dataSourceId = dataSourceId;
            return this;
        }

        public GetAgentDataSourcePlainArgs build() {
            if ($.dataSourceId == null) {
                throw new MissingRequiredPropertyException("GetAgentDataSourcePlainArgs", "dataSourceId");
            }
            return $;
        }
    }

}
