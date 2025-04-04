// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetPipelineRunArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPipelineRunArgs Empty = new GetPipelineRunArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline run.
     * 
     */
    @Import(name="pipelineRunId", required=true)
    private Output<String> pipelineRunId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline run.
     * 
     */
    public Output<String> pipelineRunId() {
        return this.pipelineRunId;
    }

    private GetPipelineRunArgs() {}

    private GetPipelineRunArgs(GetPipelineRunArgs $) {
        this.pipelineRunId = $.pipelineRunId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPipelineRunArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPipelineRunArgs $;

        public Builder() {
            $ = new GetPipelineRunArgs();
        }

        public Builder(GetPipelineRunArgs defaults) {
            $ = new GetPipelineRunArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param pipelineRunId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline run.
         * 
         * @return builder
         * 
         */
        public Builder pipelineRunId(Output<String> pipelineRunId) {
            $.pipelineRunId = pipelineRunId;
            return this;
        }

        /**
         * @param pipelineRunId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline run.
         * 
         * @return builder
         * 
         */
        public Builder pipelineRunId(String pipelineRunId) {
            return pipelineRunId(Output.of(pipelineRunId));
        }

        public GetPipelineRunArgs build() {
            if ($.pipelineRunId == null) {
                throw new MissingRequiredPropertyException("GetPipelineRunArgs", "pipelineRunId");
            }
            return $;
        }
    }

}
