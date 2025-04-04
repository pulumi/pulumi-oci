// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetAgentDataIngestionJobLogContentArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAgentDataIngestionJobLogContentArgs Empty = new GetAgentDataIngestionJobLogContentArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data ingestion job.
     * 
     */
    @Import(name="dataIngestionJobId", required=true)
    private Output<String> dataIngestionJobId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data ingestion job.
     * 
     */
    public Output<String> dataIngestionJobId() {
        return this.dataIngestionJobId;
    }

    private GetAgentDataIngestionJobLogContentArgs() {}

    private GetAgentDataIngestionJobLogContentArgs(GetAgentDataIngestionJobLogContentArgs $) {
        this.dataIngestionJobId = $.dataIngestionJobId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAgentDataIngestionJobLogContentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAgentDataIngestionJobLogContentArgs $;

        public Builder() {
            $ = new GetAgentDataIngestionJobLogContentArgs();
        }

        public Builder(GetAgentDataIngestionJobLogContentArgs defaults) {
            $ = new GetAgentDataIngestionJobLogContentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dataIngestionJobId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data ingestion job.
         * 
         * @return builder
         * 
         */
        public Builder dataIngestionJobId(Output<String> dataIngestionJobId) {
            $.dataIngestionJobId = dataIngestionJobId;
            return this;
        }

        /**
         * @param dataIngestionJobId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data ingestion job.
         * 
         * @return builder
         * 
         */
        public Builder dataIngestionJobId(String dataIngestionJobId) {
            return dataIngestionJobId(Output.of(dataIngestionJobId));
        }

        public GetAgentDataIngestionJobLogContentArgs build() {
            if ($.dataIngestionJobId == null) {
                throw new MissingRequiredPropertyException("GetAgentDataIngestionJobLogContentArgs", "dataIngestionJobId");
            }
            return $;
        }
    }

}
